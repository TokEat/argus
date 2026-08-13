package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

var assetObservationStages = []scanplan.Stage{
	scanplan.StageSearchEngine,
	scanplan.StageSubdomainDiscovery,
	scanplan.StageCDNClassification,
	scanplan.StageICMPDiscovery,
	scanplan.StageTCPLiveness,
	scanplan.StagePortScan,
	scanplan.StageProtocolIdentify,
	scanplan.StageHTTPProbe,
	scanplan.StageHostBinding,
	scanplan.StageDirectoryProbe,
	scanplan.StageFingerprint,
}

type stageObservationState struct {
	startedAt           time.Time
	active              bool
	terminal            bool
	items               []string
	checkpointItems     map[string]scanplan.ServiceCheckpoint
	checkpointTruncated bool
}

type stageObservationReporter struct {
	attemptID   string
	agentID     string
	targets     []string
	configHash  string
	ruleVersion string
	planned     []scanplan.Stage
	plannedSet  map[scanplan.Stage]struct{}
	states      map[scanplan.Stage]*stageObservationState
	now         func() time.Time
}

type stageObservationReporterPlan struct {
	ConfigHash string
	Stages     []scanplan.Stage
}

func newStageObservationReporter(taskID, agentID string, targets []string, config []byte, ruleVersion, executionMode string, resume ...stageObservationReporterPlan) *stageObservationReporter {
	targets = normalizedEventTargets(targets)
	configDigest := sha256.Sum256(config)
	ruleVersion = strings.TrimSpace(ruleVersion)
	if ruleVersion == "" {
		ruleVersion = "_unknown"
	}
	planned := append([]scanplan.Stage(nil), assetObservationStages...)
	if strings.EqualFold(strings.TrimSpace(executionMode), "risk_validation") {
		planned = []scanplan.Stage{scanplan.StageRiskValidation}
	} else if strings.EqualFold(strings.TrimSpace(executionMode), "credential_validation") {
		planned = []scanplan.Stage{scanplan.StageCredentialValidation}
	}
	configHash := hex.EncodeToString(configDigest[:])
	if len(resume) > 0 {
		configHash = strings.TrimSpace(resume[0].ConfigHash)
		planned = append([]scanplan.Stage(nil), resume[0].Stages...)
	}
	plannedSet := make(map[scanplan.Stage]struct{}, len(planned))
	for _, stage := range planned {
		plannedSet[stage] = struct{}{}
	}
	return &stageObservationReporter{
		attemptID: taskID, agentID: agentID, targets: targets,
		configHash: configHash, ruleVersion: ruleVersion,
		planned: planned, plannedSet: plannedSet, states: make(map[scanplan.Stage]*stageObservationState),
		now: func() time.Time { return time.Now().UTC() },
	}
}

func normalizedEventTargets(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	result := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, duplicate := seen[target]; duplicate {
			continue
		}
		seen[target] = struct{}{}
		result = append(result, target)
	}
	sort.Strings(result)
	return result
}

func (r *stageObservationReporter) recordOutput(payloadType string, payload []byte) {
	if r == nil {
		return
	}
	sum := sha256.Sum256(append(append([]byte(payloadType), 0), payload...))
	digest := hex.EncodeToString(sum[:])
	var message engine.OutputMessage
	_ = json.Unmarshal(payload, &message)
	for stage, state := range r.states {
		if state.active && !state.terminal {
			state.items = append(state.items, digest)
			if len(r.targets) == 1 {
				recordStageCheckpointItem(stage, state, message)
			}
		}
	}
}

func (r *stageObservationReporter) observePhase(phase engine.PhaseEvent) []*scanplan.StageObservationEvent {
	if r == nil {
		return nil
	}
	stage, ok := engine.CanonicalStageForPhase(phase.Phase)
	if !ok {
		return nil
	}
	if _, planned := r.plannedSet[stage]; !planned {
		return nil
	}
	state := r.state(stage)
	if state.terminal {
		return nil
	}
	now := r.now()
	switch strings.ToLower(strings.TrimSpace(phase.Status)) {
	case "start":
		if state.startedAt.IsZero() {
			state.startedAt = now
		}
		state.active = true
		return nil
	case "end", "success", "negative":
		outcome := scanplan.ObservationSuccess
		if strings.EqualFold(phase.Status, "negative") || len(state.items) == 0 {
			outcome = scanplan.ObservationNegative
		}
		return []*scanplan.StageObservationEvent{r.finish(stage, state, outcome, now, "", "")}
	case "failed":
		return []*scanplan.StageObservationEvent{r.finish(stage, state, scanplan.ObservationFailed, now, "phase_failed", phase.Message)}
	case "skipped":
		return []*scanplan.StageObservationEvent{r.finish(stage, state, scanplan.ObservationSkipped, now, "phase_skipped", phase.Message)}
	default:
		return nil
	}
}

func (r *stageObservationReporter) finalize(runErr error, cancelled bool) []*scanplan.StageObservationEvent {
	if r == nil || len(r.targets) == 0 {
		return nil
	}
	now := r.now()
	events := make([]*scanplan.StageObservationEvent, 0, len(r.planned))
	for _, stage := range r.planned {
		state := r.state(stage)
		if state.terminal {
			continue
		}
		if state.active {
			if cancelled {
				events = append(events, r.finish(stage, state, scanplan.ObservationSkipped, now, "pipeline_cancelled", "task cancelled before stage completion"))
			} else if runErr != nil {
				events = append(events, r.finish(stage, state, scanplan.ObservationFailed, now, "pipeline_failed", runErr.Error()))
			} else {
				events = append(events, r.finish(stage, state, scanplan.ObservationFailed, now, "phase_incomplete", "stage started without a terminal event"))
			}
			continue
		}
		events = append(events, r.finish(stage, state, scanplan.ObservationSkipped, now, "stage_not_executed", "stage was disabled or not applicable to this task"))
	}
	return events
}

func (r *stageObservationReporter) state(stage scanplan.Stage) *stageObservationState {
	state := r.states[stage]
	if state == nil {
		state = &stageObservationState{}
		r.states[stage] = state
	}
	return state
}

func (r *stageObservationReporter) finish(stage scanplan.Stage, state *stageObservationState, outcome scanplan.ObservationOutcome, finishedAt time.Time, errorCode, errorMessage string) *scanplan.StageObservationEvent {
	if state.startedAt.IsZero() {
		state.startedAt = finishedAt
	}
	state.active = false
	state.terminal = true
	contentHash := observationContentHash(state.items)
	event := &scanplan.StageObservationEvent{
		SchemaVersion: scanplan.SchemaVersion,
		AttemptID:     r.attemptID,
		AgentID:       r.agentID,
		Stage:         stage,
		Outcome:       outcome,
		Targets:       append([]string(nil), r.targets...),
		ConfigHash:    r.configHash,
		RuleVersion:   r.ruleVersion,
		StartedAt:     state.startedAt,
		FinishedAt:    finishedAt,
		ContentHash:   contentHash,
		ErrorCode:     errorCode,
		ErrorMessage:  strings.TrimSpace(errorMessage),
	}
	if outcome == scanplan.ObservationSuccess || outcome == scanplan.ObservationNegative {
		checkpointTarget := ""
		if len(r.targets) == 1 {
			checkpointTarget = r.targets[0]
		}
		event.Checkpoint = stageCheckpointFromState(stage, state, checkpointTarget)
	}
	event.EventID = stageObservationEventID(event)
	return event
}

func recordStageCheckpointItem(stage scanplan.Stage, state *stageObservationState, message engine.OutputMessage) {
	if state == nil || state.checkpointTruncated {
		return
	}
	if state.checkpointItems == nil {
		state.checkpointItems = make(map[string]scanplan.ServiceCheckpoint)
	}
	add := func(key string, item scanplan.ServiceCheckpoint) {
		if key == "" {
			return
		}
		if _, exists := state.checkpointItems[key]; exists {
			return
		}
		if len(state.checkpointItems) >= scanplan.MaxCheckpointItems {
			state.checkpointItems = nil
			state.checkpointTruncated = true
			return
		}
		state.checkpointItems[key] = item
	}
	switch stage {
	case scanplan.StageICMPDiscovery, scanplan.StageTCPLiveness:
		if ip := normalizedCheckpointIP(message.IP); ip != "" {
			add(ip, scanplan.ServiceCheckpoint{Endpoint: ip})
		}
	case scanplan.StagePortScan:
		if endpoint := normalizedCheckpointEndpoint(message.IP, message.Port); endpoint != "" {
			add(endpoint, scanplan.ServiceCheckpoint{Endpoint: endpoint})
		}
	case scanplan.StageProtocolIdentify:
		endpoint := normalizedCheckpointEndpoint(message.IP, message.Port)
		protocol := strings.ToLower(strings.TrimSpace(message.Protocol))
		if endpoint != "" && protocol != "" && len(protocol) <= 64 && !strings.ContainsAny(protocol, "\r\n\x00") {
			add(endpoint+"\x00"+protocol, scanplan.ServiceCheckpoint{Endpoint: endpoint, Protocol: protocol})
		}
	case scanplan.StageHTTPProbe, scanplan.StageHostBinding:
		if normalized := normalizedCheckpointURL(message.URI); normalized != "" {
			add(normalized, scanplan.ServiceCheckpoint{Endpoint: normalized})
		}
	case scanplan.StageSubdomainDiscovery:
		if domain := normalizedCheckpointDomain(message.Domain); domain != "" {
			add(domain, scanplan.ServiceCheckpoint{Endpoint: domain})
		}
	}
}

func stageCheckpointFromState(stage scanplan.Stage, state *stageObservationState, target string) *scanplan.StageCheckpoint {
	if target == "" || state == nil || state.checkpointTruncated {
		return nil
	}
	checkpoint := &scanplan.StageCheckpoint{SchemaVersion: scanplan.CheckpointSchemaVersion, Stage: stage}
	keys := make([]string, 0, len(state.checkpointItems))
	for key := range state.checkpointItems {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	switch stage {
	case scanplan.StageICMPDiscovery, scanplan.StageTCPLiveness:
		for _, key := range keys {
			checkpoint.AliveHosts = append(checkpoint.AliveHosts, state.checkpointItems[key].Endpoint)
		}
	case scanplan.StagePortScan:
		for _, key := range keys {
			checkpoint.OpenPorts = append(checkpoint.OpenPorts, state.checkpointItems[key].Endpoint)
		}
	case scanplan.StageProtocolIdentify:
		for _, key := range keys {
			checkpoint.Services = append(checkpoint.Services, state.checkpointItems[key])
		}
	case scanplan.StageHTTPProbe, scanplan.StageHostBinding:
		for _, key := range keys {
			checkpoint.URLs = append(checkpoint.URLs, state.checkpointItems[key].Endpoint)
		}
	case scanplan.StageSubdomainDiscovery:
		for _, key := range keys {
			checkpoint.Domains = append(checkpoint.Domains, state.checkpointItems[key].Endpoint)
		}
	default:
		return nil
	}
	if err := checkpoint.ValidateForTarget(target); err != nil {
		return nil
	}
	return checkpoint
}

func normalizedCheckpointIP(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func normalizedCheckpointEndpoint(rawHost, rawPort string) string {
	host := strings.TrimSpace(rawHost)
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" || strings.ContainsAny(host, " /:?#\r\n\x00") {
			return ""
		}
	}
	port, err := strconv.Atoi(strings.TrimSpace(rawPort))
	if err != nil || port < 1 || port > 65535 {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func normalizedCheckpointURL(raw string) string {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return ""
	}
	parsed.Fragment = ""
	return parsed.String()
}

func normalizedCheckpointDomain(raw string) string {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if !strings.Contains(domain, ".") || strings.ContainsAny(domain, " /:?#\r\n\x00") {
		return ""
	}
	return domain
}

func observationContentHash(items []string) string {
	items = append([]string(nil), items...)
	sort.Strings(items)
	hash := sha256.New()
	for _, item := range items {
		_, _ = hash.Write([]byte(item))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func stageObservationEventID(event *scanplan.StageObservationEvent) string {
	checkpointHash := ""
	if event.Checkpoint != nil {
		if encoded, err := event.Checkpoint.CanonicalJSON(); err == nil {
			sum := sha256.Sum256(encoded)
			checkpointHash = hex.EncodeToString(sum[:])
		}
	}
	value := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		event.SchemaVersion, event.AttemptID, event.AgentID, event.Stage, event.Outcome,
		event.FinishedAt.UTC().Format(time.RFC3339Nano), event.ContentHash, checkpointHash)
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
