// Package scanplan defines the versioned planning and coverage contract shared
// by Argus Server, Agent, and offline CLI components. It deliberately contains
// no persistence or scanner implementation details.
package scanplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	SchemaVersion               = "argus.scanplan/v1"
	CheckpointSchemaVersion     = "argus.checkpoint/v1"
	ResumePlanSchemaVersion     = "argus.resume-plan/v1"
	StageObservationPayloadType = "coverage_event"
	MaxCheckpointItems          = 4096
)

const (
	PublicNetworkZone = "public"
	LocalTenantID     = "_local"
	LocalProjectID    = "_default"
	LocalNetworkZone  = "_local"
)

type Scenario string

const (
	ScenarioExternalMap          Scenario = "external-map"
	ScenarioInternalFast         Scenario = "internal-fast"
	ScenarioInternalServer       Scenario = "internal-server"
	ScenarioRiskValidation       Scenario = "risk-validation"
	ScenarioCredentialValidation Scenario = "credential-validation"
)

func (s Scenario) Valid() bool {
	switch s {
	case ScenarioExternalMap, ScenarioInternalFast, ScenarioInternalServer, ScenarioRiskValidation, ScenarioCredentialValidation:
		return true
	default:
		return false
	}
}

type Stage string

const (
	StageSearchEngine         Stage = "search_engine"
	StageSubdomainDiscovery   Stage = "subdomain_discovery"
	StageCDNClassification    Stage = "cdn_classification"
	StageICMPDiscovery        Stage = "icmp_discovery"
	StageTCPLiveness          Stage = "tcp_liveness"
	StagePortScan             Stage = "port_scan"
	StageProtocolIdentify     Stage = "protocol_identification"
	StageHTTPProbe            Stage = "http_probe"
	StageHostBinding          Stage = "host_binding"
	StageBehaviorProbe        Stage = "behavior_probe"
	StageDirectoryProbe       Stage = "directory_probe"
	StageFingerprint          Stage = "fingerprint"
	StageRiskValidation       Stage = "risk_validation"
	StageCredentialValidation Stage = "credential_validation"
	StageWebCrawl             Stage = "web_crawl"
	StageSensitiveInfo        Stage = "sensitive_info"
)

func (s Stage) Valid() bool {
	switch s {
	case StageSearchEngine, StageSubdomainDiscovery, StageCDNClassification,
		StageICMPDiscovery, StageTCPLiveness, StagePortScan,
		StageProtocolIdentify, StageHTTPProbe, StageHostBinding,
		StageBehaviorProbe, StageDirectoryProbe, StageFingerprint, StageRiskValidation, StageCredentialValidation,
		StageWebCrawl, StageSensitiveInfo:
		return true
	default:
		return false
	}
}

type StagePlan struct {
	Stage     Stage   `json:"stage"`
	DependsOn []Stage `json:"depends_on,omitempty"`
	Force     bool    `json:"force,omitempty"`
}

type Plan struct {
	SchemaVersion string      `json:"schema_version"`
	Scenario      Scenario    `json:"scenario"`
	TenantID      string      `json:"tenant_id"`
	ProjectID     string      `json:"project_id"`
	NetworkZone   string      `json:"network_zone"`
	Targets       []string    `json:"targets"`
	ScopeHash     string      `json:"scope_hash"`
	ConfigHash    string      `json:"config_hash"`
	RuleVersion   string      `json:"rule_version"`
	Stages        []StagePlan `json:"stages"`
}

func (p Plan) Validate() error {
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported scan plan schema %q", p.SchemaVersion)
	}
	if !p.Scenario.Valid() {
		return fmt.Errorf("unsupported scan scenario %q", p.Scenario)
	}
	for _, dimension := range []struct {
		name  string
		value string
	}{
		{name: "tenant_id", value: p.TenantID},
		{name: "project_id", value: p.ProjectID},
		{name: "network_zone", value: p.NetworkZone},
		{name: "scope_hash", value: p.ScopeHash},
		{name: "config_hash", value: p.ConfigHash},
		{name: "rule_version", value: p.RuleVersion},
	} {
		if err := validateDimension(dimension.name, dimension.value); err != nil {
			return err
		}
	}
	if len(p.Targets) == 0 {
		return errors.New("scan plan requires at least one normalized target")
	}
	targets := make(map[string]struct{}, len(p.Targets))
	for _, target := range p.Targets {
		if err := validateDimension("target", target); err != nil {
			return err
		}
		if _, duplicate := targets[target]; duplicate {
			return fmt.Errorf("scan plan contains duplicate target %q", target)
		}
		targets[target] = struct{}{}
	}
	if len(p.Stages) == 0 {
		return errors.New("scan plan requires at least one stage")
	}
	stages := make(map[Stage]StagePlan, len(p.Stages))
	for _, planned := range p.Stages {
		if !planned.Stage.Valid() {
			return fmt.Errorf("scan plan contains unsupported stage %q", planned.Stage)
		}
		if _, duplicate := stages[planned.Stage]; duplicate {
			return fmt.Errorf("scan plan contains duplicate stage %q", planned.Stage)
		}
		stages[planned.Stage] = planned
	}
	if p.Scenario == ScenarioRiskValidation || p.Scenario == ScenarioCredentialValidation {
		expected := StageRiskValidation
		if p.Scenario == ScenarioCredentialValidation {
			expected = StageCredentialValidation
		}
		if len(p.Stages) != 1 || p.Stages[0].Stage != expected {
			return fmt.Errorf("%s plans may contain only the %s stage", p.Scenario, expected)
		}
		if !p.Stages[0].Force {
			return fmt.Errorf("%s plans must force the authorized stage", p.Scenario)
		}
	} else if _, unsafe := stages[StageRiskValidation]; unsafe {
		return errors.New("asset discovery plans cannot include risk_validation")
	} else if _, unsafe := stages[StageCredentialValidation]; unsafe {
		return errors.New("asset discovery plans cannot include credential_validation")
	}
	for _, planned := range p.Stages {
		seenDependencies := make(map[Stage]struct{}, len(planned.DependsOn))
		for _, dependency := range planned.DependsOn {
			if dependency == planned.Stage {
				return fmt.Errorf("stage %q cannot depend on itself", planned.Stage)
			}
			if _, exists := stages[dependency]; !exists {
				return fmt.Errorf("stage %q depends on missing stage %q", planned.Stage, dependency)
			}
			if _, duplicate := seenDependencies[dependency]; duplicate {
				return fmt.Errorf("stage %q contains duplicate dependency %q", planned.Stage, dependency)
			}
			seenDependencies[dependency] = struct{}{}
		}
	}
	if hasStageCycle(stages) {
		return errors.New("scan plan stage dependencies contain a cycle")
	}
	return nil
}

func hasStageCycle(stages map[Stage]StagePlan) bool {
	const (
		unvisited = iota
		visiting
		visited
	)
	state := make(map[Stage]int, len(stages))
	var visit func(Stage) bool
	visit = func(stage Stage) bool {
		switch state[stage] {
		case visiting:
			return true
		case visited:
			return false
		}
		state[stage] = visiting
		for _, dependency := range stages[stage].DependsOn {
			if visit(dependency) {
				return true
			}
		}
		state[stage] = visited
		return false
	}
	for stage := range stages {
		if visit(stage) {
			return true
		}
	}
	return false
}

type WorkKey struct {
	TenantID               string `json:"tenant_id"`
	ProjectID              string `json:"project_id"`
	NetworkZone            string `json:"network_zone"`
	NormalizedTarget       string `json:"normalized_target"`
	Stage                  Stage  `json:"stage"`
	ScopeHash              string `json:"scope_hash"`
	ConfigHash             string `json:"config_hash"`
	RuleVersion            string `json:"rule_version"`
	POCSetHash             string `json:"poc_set_hash,omitempty"`
	EndpointContentHash    string `json:"endpoint_content_hash,omitempty"`
	CredentialSetHash      string `json:"credential_set_hash,omitempty"`
	ServiceObservationHash string `json:"service_observation_hash,omitempty"`
}

func (k WorkKey) Validate() error {
	for _, dimension := range []struct {
		name  string
		value string
	}{
		{name: "tenant_id", value: k.TenantID},
		{name: "project_id", value: k.ProjectID},
		{name: "network_zone", value: k.NetworkZone},
		{name: "normalized_target", value: k.NormalizedTarget},
		{name: "scope_hash", value: k.ScopeHash},
		{name: "config_hash", value: k.ConfigHash},
		{name: "rule_version", value: k.RuleVersion},
	} {
		if err := validateDimension(dimension.name, dimension.value); err != nil {
			return err
		}
	}
	if !k.Stage.Valid() {
		return fmt.Errorf("unsupported work stage %q", k.Stage)
	}
	if k.Stage == StageRiskValidation {
		if err := validateDimension("poc_set_hash", k.POCSetHash); err != nil {
			return err
		}
		if err := validateDimension("endpoint_content_hash", k.EndpointContentHash); err != nil {
			return err
		}
	} else if k.POCSetHash != "" || k.EndpointContentHash != "" {
		return errors.New("POC dimensions are valid only for risk_validation work")
	}
	if k.Stage == StageCredentialValidation {
		if err := validateDimension("credential_set_hash", k.CredentialSetHash); err != nil {
			return err
		}
		if err := validateDimension("service_observation_hash", k.ServiceObservationHash); err != nil {
			return err
		}
	} else if k.CredentialSetHash != "" || k.ServiceObservationHash != "" {
		return errors.New("credential dimensions are valid only for credential_validation work")
	}
	return nil
}

func (k WorkKey) CanonicalJSON() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(k)
}

func (k WorkKey) Digest() (string, error) {
	canonical, err := k.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

type ObservationOutcome string

const (
	ObservationSuccess  ObservationOutcome = "success"
	ObservationNegative ObservationOutcome = "negative"
	ObservationFailed   ObservationOutcome = "failed"
	ObservationSkipped  ObservationOutcome = "skipped"
)

func (o ObservationOutcome) Valid() bool {
	switch o {
	case ObservationSuccess, ObservationNegative, ObservationFailed, ObservationSkipped:
		return true
	default:
		return false
	}
}

type Observation struct {
	SchemaVersion  string             `json:"schema_version"`
	WorkKey        WorkKey            `json:"work_key"`
	Outcome        ObservationOutcome `json:"outcome"`
	ObservedAt     time.Time          `json:"observed_at"`
	ContentHash    string             `json:"content_hash,omitempty"`
	CheckpointHash string             `json:"checkpoint_hash,omitempty"`
	EvidenceHash   string             `json:"evidence_hash,omitempty"`
	ErrorCode      string             `json:"error_code,omitempty"`
	ErrorMessage   string             `json:"error_message,omitempty"`
}

type ServiceCheckpoint struct {
	Endpoint string `json:"endpoint"`
	Protocol string `json:"protocol"`
}

// StageCheckpoint contains only bounded, derived discovery facts required to
// resume a later stage. It deliberately excludes response bodies, headers,
// credentials, and arbitrary evidence text.
type StageCheckpoint struct {
	SchemaVersion string              `json:"schema_version"`
	Stage         Stage               `json:"stage"`
	AliveHosts    []string            `json:"alive_hosts,omitempty"`
	OpenPorts     []string            `json:"open_ports,omitempty"`
	Services      []ServiceCheckpoint `json:"services,omitempty"`
	URLs          []string            `json:"urls,omitempty"`
	Domains       []string            `json:"domains,omitempty"`
}

func (c StageCheckpoint) Validate() error {
	if c.SchemaVersion != CheckpointSchemaVersion {
		return fmt.Errorf("unsupported checkpoint schema %q", c.SchemaVersion)
	}
	if !c.Stage.Valid() {
		return fmt.Errorf("unsupported checkpoint stage %q", c.Stage)
	}
	total := len(c.AliveHosts) + len(c.OpenPorts) + len(c.Services) + len(c.URLs) + len(c.Domains)
	if total > MaxCheckpointItems {
		return fmt.Errorf("checkpoint contains %d items, limit is %d", total, MaxCheckpointItems)
	}
	if err := validateSortedCheckpointStrings("alive_hosts", c.AliveHosts, func(value string) bool { return net.ParseIP(value) != nil }); err != nil {
		return err
	}
	if err := validateSortedCheckpointStrings("open_ports", c.OpenPorts, validCheckpointEndpoint); err != nil {
		return err
	}
	if err := validateSortedCheckpointStrings("urls", c.URLs, validCheckpointURL); err != nil {
		return err
	}
	if err := validateSortedCheckpointStrings("domains", c.Domains, validCheckpointDomain); err != nil {
		return err
	}
	if err := validateSortedServiceCheckpoints(c.Services); err != nil {
		return err
	}

	switch c.Stage {
	case StageICMPDiscovery, StageTCPLiveness:
		if len(c.OpenPorts)+len(c.Services)+len(c.URLs)+len(c.Domains) != 0 {
			return errors.New("liveness checkpoint may contain only alive_hosts")
		}
	case StagePortScan:
		if len(c.AliveHosts)+len(c.Services)+len(c.URLs)+len(c.Domains) != 0 {
			return errors.New("port checkpoint may contain only open_ports")
		}
	case StageProtocolIdentify:
		if len(c.AliveHosts)+len(c.OpenPorts)+len(c.URLs)+len(c.Domains) != 0 {
			return errors.New("protocol checkpoint may contain only services")
		}
	case StageHTTPProbe, StageHostBinding:
		if len(c.AliveHosts)+len(c.OpenPorts)+len(c.Services)+len(c.Domains) != 0 {
			return errors.New("HTTP checkpoint may contain only urls")
		}
	case StageSubdomainDiscovery:
		if len(c.AliveHosts)+len(c.OpenPorts)+len(c.Services)+len(c.URLs) != 0 {
			return errors.New("subdomain checkpoint may contain only domains")
		}
	default:
		return fmt.Errorf("stage %q does not support a resumable checkpoint", c.Stage)
	}
	return nil
}

func validateSortedCheckpointStrings(name string, values []string, valid func(string) bool) error {
	previous := ""
	for index, value := range values {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") || !valid(value) {
			return fmt.Errorf("checkpoint %s contains invalid item %q", name, value)
		}
		if index > 0 && strings.Compare(previous, value) >= 0 {
			return fmt.Errorf("checkpoint %s must be sorted and unique", name)
		}
		previous = value
	}
	return nil
}

func validateSortedServiceCheckpoints(values []ServiceCheckpoint) error {
	previous := ""
	for index, value := range values {
		if !validCheckpointEndpoint(value.Endpoint) || value.Protocol == "" || value.Protocol != strings.ToLower(strings.TrimSpace(value.Protocol)) || len(value.Protocol) > 64 || strings.ContainsAny(value.Protocol, "\r\n\x00") {
			return fmt.Errorf("checkpoint services contains invalid item %+v", value)
		}
		key := value.Endpoint + "\x00" + value.Protocol
		if index > 0 && strings.Compare(previous, key) >= 0 {
			return errors.New("checkpoint services must be sorted and unique")
		}
		previous = key
	}
	return nil
}

func validCheckpointEndpoint(value string) bool {
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) == "" {
		return false
	}
	port, err := strconv.Atoi(rawPort)
	return err == nil && port > 0 && port < 65536
}

func validCheckpointURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.User == nil
}

func validCheckpointDomain(value string) bool {
	if len(value) > 253 || strings.ContainsAny(value, " /:?#") || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
				return false
			}
		}
	}
	return true
}

func (c StageCheckpoint) CanonicalJSON() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// ResumeCheckpoint binds replayable, target-scoped stage output to the exact
// immutable coverage and observation rows selected by the Server Planner.
// Agents treat these IDs and hashes as opaque provenance and must still
// validate the embedded checkpoint before use.
type ResumeCheckpoint struct {
	Stage               Stage           `json:"stage"`
	WorkKeyHash         string          `json:"work_key_hash"`
	CoverageID          uint64          `json:"coverage_id"`
	SourceObservationID uint64          `json:"source_observation_id"`
	ObservationHash     string          `json:"observation_hash"`
	CheckpointHash      string          `json:"checkpoint_hash"`
	Checkpoint          StageCheckpoint `json:"checkpoint"`
}

// ResumePlan is a single-target, dependency-closed execution decision. The
// complete required stage order is partitioned into a reusable prefix and an
// execution suffix. A plan with an empty reusable prefix is an explicit safe
// fallback to the normal full pipeline.
type ResumePlan struct {
	SchemaVersion   string             `json:"schema_version"`
	TenantID        string             `json:"tenant_id"`
	ProjectID       string             `json:"project_id"`
	NetworkZone     string             `json:"network_zone"`
	Target          string             `json:"target"`
	ScopeHash       string             `json:"scope_hash"`
	ConfigHash      string             `json:"config_hash"`
	RuleVersion     string             `json:"rule_version"`
	RequiredStages  []Stage            `json:"required_stages"`
	ReusedStages    []Stage            `json:"reused_stages,omitempty"`
	ExecutionStages []Stage            `json:"execution_stages"`
	StartStage      Stage              `json:"start_stage"`
	Checkpoints     []ResumeCheckpoint `json:"checkpoints,omitempty"`
	FallbackReason  string             `json:"fallback_reason,omitempty"`
}

func (p ResumePlan) Validate() error {
	if p.SchemaVersion != ResumePlanSchemaVersion {
		return fmt.Errorf("unsupported resume plan schema %q", p.SchemaVersion)
	}
	for _, dimension := range []struct {
		name  string
		value string
	}{
		{name: "tenant_id", value: p.TenantID},
		{name: "project_id", value: p.ProjectID},
		{name: "network_zone", value: p.NetworkZone},
		{name: "target", value: p.Target},
		{name: "scope_hash", value: p.ScopeHash},
		{name: "config_hash", value: p.ConfigHash},
		{name: "rule_version", value: p.RuleVersion},
	} {
		if err := validateDimension(dimension.name, dimension.value); err != nil {
			return err
		}
	}
	if p.FallbackReason != "" {
		if err := validateDimension("fallback_reason", p.FallbackReason); err != nil {
			return err
		}
	}
	if len(p.RequiredStages) == 0 || len(p.ExecutionStages) == 0 {
		return errors.New("resume plan requires stage order and executable work")
	}
	requiredIndex := make(map[Stage]int, len(p.RequiredStages))
	for index, stage := range p.RequiredStages {
		if !stage.Valid() || stage == StageRiskValidation {
			return fmt.Errorf("resume plan contains unsupported stage %q", stage)
		}
		if _, duplicate := requiredIndex[stage]; duplicate {
			return fmt.Errorf("resume plan contains duplicate required stage %q", stage)
		}
		requiredIndex[stage] = index
	}
	if p.StartStage != p.ExecutionStages[0] {
		return errors.New("resume plan start_stage must be the first execution stage")
	}
	partition := make(map[Stage]string, len(p.RequiredStages))
	validateOrderedPartition := func(name string, stages []Stage) error {
		previous := -1
		for _, stage := range stages {
			index, exists := requiredIndex[stage]
			if !exists {
				return fmt.Errorf("resume plan %s contains stage %q outside required stages", name, stage)
			}
			if index <= previous {
				return fmt.Errorf("resume plan %s must preserve required stage order", name)
			}
			if owner, duplicate := partition[stage]; duplicate {
				return fmt.Errorf("resume plan stage %q appears in both %s and %s", stage, owner, name)
			}
			partition[stage] = name
			previous = index
		}
		return nil
	}
	if err := validateOrderedPartition("reused_stages", p.ReusedStages); err != nil {
		return err
	}
	if err := validateOrderedPartition("execution_stages", p.ExecutionStages); err != nil {
		return err
	}
	if len(partition) != len(p.RequiredStages) {
		return errors.New("resume plan must partition every required stage")
	}
	for index, stage := range p.RequiredStages {
		want := "execution_stages"
		if index < len(p.ReusedStages) {
			want = "reused_stages"
		}
		if partition[stage] != want {
			return errors.New("resume plan reusable work must be a prefix and execution work must be a suffix")
		}
	}

	checkpointStages := make(map[Stage]struct{}, len(p.Checkpoints))
	previousCheckpointIndex := -1
	for _, evidence := range p.Checkpoints {
		index, reused := requiredIndex[evidence.Stage]
		if !reused || partition[evidence.Stage] != "reused_stages" {
			return fmt.Errorf("resume checkpoint stage %q is not reusable plan work", evidence.Stage)
		}
		if index <= previousCheckpointIndex {
			return errors.New("resume checkpoints must preserve required stage order")
		}
		if _, duplicate := checkpointStages[evidence.Stage]; duplicate {
			return fmt.Errorf("resume plan contains duplicate checkpoint stage %q", evidence.Stage)
		}
		checkpointStages[evidence.Stage] = struct{}{}
		previousCheckpointIndex = index
		if evidence.CoverageID == 0 || evidence.SourceObservationID == 0 {
			return errors.New("resume checkpoint requires coverage and observation provenance")
		}
		for _, hash := range []struct {
			name  string
			value string
		}{
			{name: "work_key_hash", value: evidence.WorkKeyHash},
			{name: "observation_hash", value: evidence.ObservationHash},
			{name: "checkpoint_hash", value: evidence.CheckpointHash},
		} {
			if !validSHA256Hex(hash.value) {
				return fmt.Errorf("resume checkpoint %s must be a SHA-256 digest", hash.name)
			}
		}
		if evidence.Checkpoint.Stage != evidence.Stage {
			return errors.New("resume checkpoint stage does not match its evidence")
		}
		if err := evidence.Checkpoint.ValidateForTarget(p.Target); err != nil {
			return fmt.Errorf("resume checkpoint is outside its target: %w", err)
		}
		encoded, err := evidence.Checkpoint.CanonicalJSON()
		if err != nil {
			return err
		}
		digest := sha256.Sum256(encoded)
		if hex.EncodeToString(digest[:]) != evidence.CheckpointHash {
			return errors.New("resume checkpoint hash does not match its canonical payload")
		}
	}
	return nil
}

func (p ResumePlan) CanonicalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func (p ResumePlan) Digest() (string, error) {
	canonical, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

// ValidateForTarget prevents an Agent from attaching derived endpoints to an
// unrelated assigned target. Domain discovery is intentionally conservative:
// resolved IP checkpoints are not accepted until a signed DNS mapping is part
// of the resume contract.
func (c StageCheckpoint) ValidateForTarget(target string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return errors.New("checkpoint target is empty")
	}
	if parsed, err := url.Parse(target); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		if c.Stage != StageHTTPProbe && c.Stage != StageHostBinding {
			return fmt.Errorf("URL target does not support %q checkpoint", c.Stage)
		}
		for _, item := range c.URLs {
			candidate, _ := url.Parse(item)
			if !sameCheckpointURLAuthority(parsed, candidate) {
				return fmt.Errorf("checkpoint URL %q is outside assigned URL target", item)
			}
		}
		return nil
	}
	if ip := net.ParseIP(target); ip != nil {
		if !checkpointStageSupportsNetworkTarget(c.Stage) {
			return fmt.Errorf("IP target does not support %q checkpoint", c.Stage)
		}
		return validateCheckpointHosts(c, func(host string) bool {
			candidate := net.ParseIP(host)
			return candidate != nil && candidate.Equal(ip)
		})
	}
	if _, network, err := net.ParseCIDR(target); err == nil {
		if !checkpointStageSupportsNetworkTarget(c.Stage) {
			return fmt.Errorf("CIDR target does not support %q checkpoint", c.Stage)
		}
		return validateCheckpointHosts(c, func(host string) bool {
			candidate := net.ParseIP(host)
			return candidate != nil && network.Contains(candidate)
		})
	}
	if parts := strings.SplitN(target, "-", 2); len(parts) == 2 {
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start != nil && end != nil {
			if !checkpointStageSupportsNetworkTarget(c.Stage) {
				return fmt.Errorf("IP range target does not support %q checkpoint", c.Stage)
			}
			return validateCheckpointHosts(c, func(host string) bool {
				candidate := net.ParseIP(host)
				return checkpointIPInRange(candidate, start, end)
			})
		}
	}
	if host, port, err := net.SplitHostPort(target); err == nil {
		if c.Stage != StageProtocolIdentify && c.Stage != StageHTTPProbe && c.Stage != StageHostBinding {
			return fmt.Errorf("host:port target does not support %q checkpoint", c.Stage)
		}
		return validateCheckpointHostPort(c, host, port)
	}
	if parts := strings.Split(target, ":"); len(parts) == 2 {
		if _, err := strconv.Atoi(parts[1]); err == nil {
			if c.Stage != StageProtocolIdentify && c.Stage != StageHTTPProbe && c.Stage != StageHostBinding {
				return fmt.Errorf("host:port target does not support %q checkpoint", c.Stage)
			}
			return validateCheckpointHostPort(c, parts[0], parts[1])
		}
	}
	if c.Stage != StageSubdomainDiscovery {
		return fmt.Errorf("domain target does not support %q checkpoint without a DNS mapping", c.Stage)
	}
	base := strings.ToLower(strings.TrimSuffix(target, "."))
	for _, domain := range c.Domains {
		if domain != base && !strings.HasSuffix(domain, "."+base) {
			return fmt.Errorf("checkpoint domain %q is outside assigned domain target", domain)
		}
	}
	return nil
}

func checkpointStageSupportsNetworkTarget(stage Stage) bool {
	switch stage {
	case StageICMPDiscovery, StageTCPLiveness, StagePortScan, StageProtocolIdentify, StageHTTPProbe, StageHostBinding:
		return true
	default:
		return false
	}
}

func validateCheckpointHosts(checkpoint StageCheckpoint, allowed func(string) bool) error {
	for _, host := range checkpoint.AliveHosts {
		if !allowed(host) {
			return fmt.Errorf("checkpoint host %q is outside assigned target", host)
		}
	}
	for _, endpoint := range checkpoint.OpenPorts {
		host, _, _ := net.SplitHostPort(endpoint)
		if !allowed(host) {
			return fmt.Errorf("checkpoint endpoint %q is outside assigned target", endpoint)
		}
	}
	for _, service := range checkpoint.Services {
		host, _, _ := net.SplitHostPort(service.Endpoint)
		if !allowed(host) {
			return fmt.Errorf("checkpoint service %q is outside assigned target", service.Endpoint)
		}
	}
	for _, rawURL := range checkpoint.URLs {
		parsed, _ := url.Parse(rawURL)
		if !allowed(parsed.Hostname()) {
			return fmt.Errorf("checkpoint URL %q is outside assigned target", rawURL)
		}
	}
	return nil
}

func validateCheckpointHostPort(checkpoint StageCheckpoint, expectedHost, expectedPort string) error {
	expectedHost = strings.ToLower(strings.Trim(strings.TrimSpace(expectedHost), "[]"))
	for _, service := range checkpoint.Services {
		host, port, _ := net.SplitHostPort(service.Endpoint)
		if !sameCheckpointHost(host, expectedHost) || port != expectedPort {
			return fmt.Errorf("checkpoint service %q is outside assigned endpoint", service.Endpoint)
		}
	}
	for _, rawURL := range checkpoint.URLs {
		parsed, _ := url.Parse(rawURL)
		port := parsed.Port()
		if port == "" {
			if parsed.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		if !sameCheckpointHost(parsed.Hostname(), expectedHost) || port != expectedPort {
			return fmt.Errorf("checkpoint URL %q is outside assigned endpoint", rawURL)
		}
	}
	return nil
}

func sameCheckpointURLAuthority(left, right *url.URL) bool {
	if left == nil || right == nil || !sameCheckpointHost(left.Hostname(), right.Hostname()) {
		return false
	}
	effectivePort := func(value *url.URL) string {
		if port := value.Port(); port != "" {
			return port
		}
		if value.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return effectivePort(left) == effectivePort(right)
}

func sameCheckpointHost(left, right string) bool {
	if leftIP, rightIP := net.ParseIP(left), net.ParseIP(right); leftIP != nil && rightIP != nil {
		return leftIP.Equal(rightIP)
	}
	return strings.EqualFold(strings.TrimSuffix(left, "."), strings.TrimSuffix(right, "."))
}

func checkpointIPInRange(candidate, start, end net.IP) bool {
	if candidate == nil || start == nil || end == nil {
		return false
	}
	if start4, end4, candidate4 := start.To4(), end.To4(), candidate.To4(); start4 != nil && end4 != nil && candidate4 != nil {
		return bytes.Compare(candidate4, start4) >= 0 && bytes.Compare(candidate4, end4) <= 0
	}
	start16, end16, candidate16 := start.To16(), end.To16(), candidate.To16()
	return start16 != nil && end16 != nil && candidate16 != nil && bytes.Compare(candidate16, start16) >= 0 && bytes.Compare(candidate16, end16) <= 0
}

// StageObservationEvent is the Agent-to-Server transport envelope for one
// terminal stage outcome. The Server enriches it with tenant, project, network
// zone, and canonical WorkKeys; Agents must never choose those trust-boundary
// dimensions themselves.
type StageObservationEvent struct {
	SchemaVersion string             `json:"schema_version"`
	EventID       string             `json:"event_id"`
	AttemptID     string             `json:"attempt_id"`
	AgentID       string             `json:"agent_id"`
	Stage         Stage              `json:"stage"`
	Outcome       ObservationOutcome `json:"outcome"`
	Targets       []string           `json:"targets"`
	ConfigHash    string             `json:"config_hash"`
	RuleVersion   string             `json:"rule_version"`
	StartedAt     time.Time          `json:"started_at"`
	FinishedAt    time.Time          `json:"finished_at"`
	ContentHash   string             `json:"content_hash"`
	Checkpoint    *StageCheckpoint   `json:"checkpoint,omitempty"`
	ErrorCode     string             `json:"error_code,omitempty"`
	ErrorMessage  string             `json:"error_message,omitempty"`
}

func (e StageObservationEvent) Validate() error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported stage observation schema %q", e.SchemaVersion)
	}
	for _, dimension := range []struct {
		name  string
		value string
	}{
		{name: "event_id", value: e.EventID},
		{name: "attempt_id", value: e.AttemptID},
		{name: "agent_id", value: e.AgentID},
		{name: "config_hash", value: e.ConfigHash},
		{name: "rule_version", value: e.RuleVersion},
		{name: "content_hash", value: e.ContentHash},
	} {
		if err := validateDimension(dimension.name, dimension.value); err != nil {
			return err
		}
	}
	if !e.Stage.Valid() {
		return fmt.Errorf("unsupported stage observation stage %q", e.Stage)
	}
	if !e.Outcome.Valid() {
		return fmt.Errorf("unsupported stage observation outcome %q", e.Outcome)
	}
	if len(e.Targets) == 0 {
		return errors.New("stage observation requires at least one normalized target")
	}
	seenTargets := make(map[string]struct{}, len(e.Targets))
	for _, target := range e.Targets {
		if err := validateDimension("target", target); err != nil {
			return err
		}
		if _, duplicate := seenTargets[target]; duplicate {
			return fmt.Errorf("stage observation contains duplicate target %q", target)
		}
		seenTargets[target] = struct{}{}
	}
	if e.StartedAt.IsZero() || e.FinishedAt.IsZero() || e.FinishedAt.Before(e.StartedAt) {
		return errors.New("stage observation requires a valid started_at/finished_at interval")
	}
	if (e.Outcome == ObservationFailed || e.Outcome == ObservationSkipped) && strings.TrimSpace(e.ErrorCode) == "" && strings.TrimSpace(e.ErrorMessage) == "" {
		return fmt.Errorf("%s stage observation requires an error code or message", e.Outcome)
	}
	if e.Checkpoint != nil {
		if len(e.Targets) != 1 {
			return errors.New("stage checkpoint requires exactly one assigned target")
		}
		if e.Outcome != ObservationSuccess && e.Outcome != ObservationNegative {
			return errors.New("failed or skipped observations cannot carry checkpoints")
		}
		if e.Checkpoint.Stage != e.Stage {
			return errors.New("stage checkpoint does not match observation stage")
		}
		if err := e.Checkpoint.Validate(); err != nil {
			return fmt.Errorf("invalid stage checkpoint: %w", err)
		}
	}
	return nil
}

func (o Observation) Validate() error {
	if o.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported observation schema %q", o.SchemaVersion)
	}
	if err := o.WorkKey.Validate(); err != nil {
		return fmt.Errorf("invalid observation work key: %w", err)
	}
	if !o.Outcome.Valid() {
		return fmt.Errorf("unsupported observation outcome %q", o.Outcome)
	}
	if o.ObservedAt.IsZero() {
		return errors.New("observation requires observed_at")
	}
	if (o.Outcome == ObservationFailed || o.Outcome == ObservationSkipped) && strings.TrimSpace(o.ErrorCode) == "" && strings.TrimSpace(o.ErrorMessage) == "" {
		return fmt.Errorf("%s observation requires an error code or message", o.Outcome)
	}
	return nil
}

func validateDimension(name, value string) error {
	if value == "" || value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must be non-empty and normalized", name)
	}
	if len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s contains an invalid value", name)
	}
	return nil
}
