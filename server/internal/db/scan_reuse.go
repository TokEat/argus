package db

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrScanReuseAttemptNotClaimable = errors.New("scan reuse attempt is no longer claimable")
	ErrReusableCoverageChanged      = errors.New("reusable coverage changed before Agent lease")
)

type ScanReuseAtClaimResult struct {
	RemainingTargets []string
	ReusedTargets    int
	ReusedStages     int
	FullyReused      bool
	Links            []TaskCoverageLink
	ResumePlan       *scanplan.ResumePlan
	ResumePlanHash   string
}

type reusableScanConfig struct {
	ExecutionMode     string
	Hunter            bool
	Fofa              bool
	Quake             bool
	OnlyIPPort        bool
	Subdomain         bool
	SkipHostDiscovery bool
	NoICMPPing        bool
	TCPPing           bool
	UDPPing           bool
	NoHostBind        bool
	// NoResolvedIPScan 改变域名目标的阶段集合（去掉端口扫描/协议识别），
	// 必须参与复用阶段判定；旧配置缺省该字段时按 false 处理。
	NoResolvedIPScan  bool
	NoDirSearch       bool
	NoPoc             bool
	GolangPoc         bool
	DisableGeneralPoc bool
	PocNameForSearch  string
}

type targetCoveragePlan struct {
	target            string
	networkZone       string
	required          []scanplan.Stage
	protocolAfterPort bool
	workHashes        map[scanplan.Stage]string
}

// ApplyReusableCoverageAtClaim plans reuse for fully covered targets. A fully
// reused Attempt is completed in this transaction; a partial plan is returned
// without writes so ClaimTask can commit it atomically with the Agent lease.
// TaskBatch.Targets remains the immutable requested scope. Manual retries and
// risk-validation Attempts deliberately bypass this path.
func ApplyReusableCoverageAtClaim(store *gorm.DB, attemptID, tenantID, agentID string) (ScanReuseAtClaimResult, error) {
	result := ScanReuseAtClaimResult{}
	if store == nil {
		return result, errors.New("scan reuse store is unavailable")
	}
	attemptID = strings.TrimSpace(attemptID)
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	if attemptID == "" || tenantID == "" || agentID == "" {
		return result, errors.New("scan reuse requires attempt, tenant, and agent identities")
	}

	err := store.Transaction(func(tx *gorm.DB) error {
		attempt, batch, _, eligible, err := lockReusableAttemptContext(tx, attemptID, tenantID)
		if err != nil {
			return fmt.Errorf("load scan reuse attempt: %w", err)
		}
		var targets []string
		if err := json.Unmarshal([]byte(attempt.ChunkTargets), &targets); err != nil || len(targets) == 0 {
			return nil
		}
		result.RemainingTargets = append([]string(nil), targets...)
		if !eligible {
			return nil
		}
		var node Node
		if err := tx.Select("agent_id", "tenant_id", "status", "tags").
			Where("agent_id = ? AND tenant_id = ? AND UPPER(status) = ?", agentID, attempt.TenantID, "ALIVE").
			First(&node).Error; err != nil {
			// Reuse must never bypass the tenant-bound Agent eligibility check
			// performed again by the final execution lease CAS.
			return nil
		}

		if strings.EqualFold(strings.TrimSpace(batch.Kind), "risk_validation") || normalizeAttemptTrigger(attempt.Trigger) == AttemptTriggerManualRetry {
			return nil
		}

		config, ok := decodeReusableScanConfig(attempt.Config)
		ruleVersion := strings.TrimSpace(attempt.RuleVersion)
		if !ok || strings.TrimSpace(attempt.ProjectID) == "" || strings.TrimSpace(attempt.RootTaskID) == "" ||
			ruleVersion == "" || strings.EqualFold(ruleVersion, "unknown") || strings.EqualFold(ruleVersion, "_unknown") {
			return nil
		}
		var project Project
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND tenant_id = ? AND status = ?", attempt.ProjectID, attempt.TenantID, "active").First(&project).Error; err != nil {
			return nil
		}
		scopeHash, scopeValid := canonicalJSONHash(project.Scope)
		if !scopeValid {
			return nil
		}
		configHash := observationConfigHash(tx, attempt)
		// Agent Pipeline skips host discovery for small tasks unless TCP ping
		// was explicitly requested. Mirror that runtime decision so the Planner
		// does not require an ICMP stage the Agent intentionally never ran.
		if !config.TCPPing && !config.UDPPing && !config.SkipHostDiscovery && reusableTargetIPCount(targets) <= 256 {
			config.SkipHostDiscovery = true
		}

		plans := make([]targetCoveragePlan, 0, len(targets))
		allHashes := make([]string, 0, len(targets)*6)
		expectedZoneByWork := make(map[string]string, len(targets)*6)
		for _, target := range targets {
			required, protocolAfterPort, valid := reusableStagesForTarget(target, config)
			if !valid {
				continue
			}
			networkZone := scanNetworkZoneForTarget(agentID, node.Tags, target)
			plan := targetCoveragePlan{target: target, networkZone: networkZone, required: required, protocolAfterPort: protocolAfterPort, workHashes: make(map[scanplan.Stage]string, len(required)+1)}
			stages := append([]scanplan.Stage(nil), required...)
			if protocolAfterPort {
				stages = append(stages, scanplan.StageProtocolIdentify)
			}
			for _, stage := range stages {
				workKey := scanplan.WorkKey{
					TenantID: attempt.TenantID, ProjectID: attempt.ProjectID, NetworkZone: networkZone,
					NormalizedTarget: target, Stage: stage, ScopeHash: scopeHash, ConfigHash: configHash,
					RuleVersion: attempt.RuleVersion,
				}
				digest, err := workKey.Digest()
				if err != nil {
					return fmt.Errorf("build reusable WorkKey: %w", err)
				}
				plan.workHashes[stage] = digest
				allHashes = append(allHashes, digest)
				expectedZoneByWork[digest] = networkZone
			}
			plans = append(plans, plan)
		}
		if len(plans) == 0 {
			return nil
		}

		var coverages []ScanCoverage
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
			"tenant_id = ? AND project_id = ? AND work_key_hash IN ?",
			attempt.TenantID, attempt.ProjectID, allHashes,
		).Find(&coverages).Error; err != nil {
			return fmt.Errorf("load reusable coverage: %w", err)
		}
		coverageByWork := make(map[string]ScanCoverage, len(coverages))
		completedSources, err := completedReusableSourceAttempts(tx, attempt.TenantID, attempt.ProjectID, coverages)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		for _, coverage := range coverages {
			if reusableCoverageValid(coverage, expectedZoneByWork[coverage.WorkKeyHash], now) && coverage.SourceAttemptID != attempt.ID && completedSources[coverage.SourceAttemptID] {
				coverageByWork[coverage.WorkKeyHash] = coverage
			}
		}

		reusedTargets := make(map[string]struct{})
		for _, plan := range plans {
			stages := materializedReusableStages(plan, coverageByWork)
			matched := make([]ScanCoverage, 0, len(stages))
			complete := true
			for _, stage := range stages {
				coverage, exists := coverageByWork[plan.workHashes[stage]]
				if !exists {
					complete = false
					break
				}
				matched = append(matched, coverage)
			}
			if !complete {
				continue
			}
			for _, coverage := range matched {
				result.Links = append(result.Links, TaskCoverageLink{
					SchemaVersion: scanplan.SchemaVersion,
					TenantID:      attempt.TenantID, ProjectID: attempt.ProjectID, RootTaskID: attempt.RootTaskID,
					BatchID: attempt.BatchID, AttemptID: attempt.ID, WorkKeyHash: coverage.WorkKeyHash,
					LinkType: "reused", Status: "active", CoverageID: coverage.ID,
					SourceTaskID: coverage.SourceTaskID, SourceBatchID: coverage.SourceBatchID,
					SourceAttemptID: coverage.SourceAttemptID, Reason: "valid_project_coverage",
				})
			}
			reusedTargets[plan.target] = struct{}{}
			result.ReusedTargets++
			result.ReusedStages += len(matched)
		}
		if len(targets) == 1 && len(plans) == 1 && len(reusedTargets) == 0 {
			resumePlan, resumePlanHash, err := buildCheckpointAwareResumePlan(tx, attempt, plans[0], coverageByWork, scopeHash, configHash)
			if err != nil {
				return err
			}
			result.ResumePlan = resumePlan
			result.ResumePlanHash = resumePlanHash
		}
		if len(reusedTargets) == 0 {
			return nil
		}

		remaining := make([]string, 0, len(targets)-len(reusedTargets))
		for _, target := range targets {
			if _, reused := reusedTargets[target]; !reused {
				remaining = append(remaining, target)
			}
		}
		result.RemainingTargets = remaining
		result.FullyReused = len(remaining) == 0
		if !result.FullyReused {
			// Partial plans are committed together with the Agent assignment in
			// ClaimTask. Persisting them here could incorrectly carry an
			// agent-scoped decision to a different Agent after a lease race.
			return nil
		}
		for index := range result.Links {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&result.Links[index]).Error; err != nil {
				return fmt.Errorf("link reusable coverage: %w", err)
			}
		}
		encoded, err := json.Marshal(remaining)
		if err != nil {
			return err
		}
		updates := map[string]interface{}{
			"chunk_targets": string(encoded), "status": "Done", "finished_at": now,
			"failure_reason": "", "agent_id": "", "stream_msg_id": "",
		}
		updated := tx.Model(&SubTask{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND agent_id = ?", attempt.ID, attempt.TenantID, attempt.Status, "").
			Updates(updates)
		if updated.Error != nil {
			return fmt.Errorf("complete reusable targets: %w", updated.Error)
		}
		if updated.RowsAffected != 1 {
			return ErrScanReuseAttemptNotClaimable
		}
		if err := tx.Model(&TaskBatch{}).
			Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", batch.ID, batch.TenantID, attempt.ID).
			Update("status", "Done").Error; err != nil {
			return fmt.Errorf("complete reused batch: %w", err)
		}
		return nil
	})
	return result, err
}

func materializedReusableStages(plan targetCoveragePlan, coverageByWork map[string]ScanCoverage) []scanplan.Stage {
	stages := make([]scanplan.Stage, 0, len(plan.required)+1)
	for _, stage := range plan.required {
		stages = append(stages, stage)
		if stage != scanplan.StagePortScan || !plan.protocolAfterPort {
			continue
		}
		portCoverage, exists := coverageByWork[plan.workHashes[scanplan.StagePortScan]]
		// Missing port evidence means the execution path may discover open
		// ports, so protocol identification remains required. A completed
		// negative port observation is the only safe reason to omit it.
		if !exists || scanplan.ObservationOutcome(portCoverage.Outcome) != scanplan.ObservationNegative {
			stages = append(stages, scanplan.StageProtocolIdentify)
		}
	}
	return stages
}

// ValidateReusableCoverageLinksAtLease locks and revalidates a partial plan
// immediately before ClaimTask writes the Agent lease. This closes the window
// in which a coverage update, Scope change, or lifecycle action could make the
// earlier read decision stale.
func ValidateReusableCoverageLinksAtLease(store *gorm.DB, attemptID, tenantID, agentID string, links []TaskCoverageLink) error {
	if store == nil || len(links) == 0 {
		return nil
	}
	attempt, batch, _, eligible, err := lockReusableAttemptContext(store, attemptID, tenantID)
	if err != nil {
		return fmt.Errorf("reload partial reuse attempt: %w", err)
	}
	if !eligible {
		return ErrScanReuseAttemptNotClaimable
	}
	if strings.EqualFold(strings.TrimSpace(batch.Kind), "risk_validation") || normalizeAttemptTrigger(attempt.Trigger) == AttemptTriggerManualRetry {
		return ErrReusableCoverageChanged
	}
	if _, ok := decodeReusableScanConfig(attempt.Config); !ok {
		return ErrReusableCoverageChanged
	}
	var project Project
	if err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ? AND tenant_id = ? AND status = ?", attempt.ProjectID, attempt.TenantID, "active").First(&project).Error; err != nil {
		return ErrReusableCoverageChanged
	}
	scopeHash, scopeValid := canonicalJSONHash(project.Scope)
	if !scopeValid {
		return ErrReusableCoverageChanged
	}
	configHash := observationConfigHash(store, attempt)
	var node Node
	if err := store.Select("agent_id", "tenant_id", "status", "tags").Where(
		"agent_id = ? AND tenant_id = ? AND UPPER(status) = ?", agentID, attempt.TenantID, "ALIVE",
	).First(&node).Error; err != nil {
		return ErrReusableCoverageChanged
	}

	ids := make([]uint64, 0, len(links))
	linkByID := make(map[uint64]TaskCoverageLink, len(links))
	for _, link := range links {
		if link.TenantID != attempt.TenantID || link.ProjectID != attempt.ProjectID || link.RootTaskID != attempt.RootTaskID ||
			link.BatchID != attempt.BatchID || link.AttemptID != attempt.ID || link.LinkType != "reused" || link.CoverageID == 0 {
			return ErrReusableCoverageChanged
		}
		ids = append(ids, link.CoverageID)
		linkByID[link.CoverageID] = link
	}
	var coverages []ScanCoverage
	if err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
		"tenant_id = ? AND project_id = ? AND id IN ?", attempt.TenantID, attempt.ProjectID, ids,
	).Find(&coverages).Error; err != nil {
		return fmt.Errorf("reload partial reusable coverage: %w", err)
	}
	if len(coverages) != len(linkByID) {
		return ErrReusableCoverageChanged
	}
	completedSources, err := completedReusableSourceAttempts(store, attempt.TenantID, attempt.ProjectID, coverages)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, coverage := range coverages {
		link, exists := linkByID[coverage.ID]
		expectedNetworkZone := scanNetworkZoneForTarget(agentID, node.Tags, coverage.NormalizedTarget)
		if !exists || !reusableCoverageValid(coverage, expectedNetworkZone, now) || coverage.SourceAttemptID == attempt.ID || !completedSources[coverage.SourceAttemptID] ||
			coverage.WorkKeyHash != link.WorkKeyHash || coverage.ScopeHash != scopeHash || coverage.ConfigHash != configHash ||
			coverage.RuleVersion != attempt.RuleVersion || coverage.SourceTaskID != link.SourceTaskID ||
			coverage.SourceBatchID != link.SourceBatchID || coverage.SourceAttemptID != link.SourceAttemptID {
			return ErrReusableCoverageChanged
		}
	}
	return nil
}

func completedReusableSourceAttempts(store *gorm.DB, tenantID, projectID string, coverages []ScanCoverage) (map[string]bool, error) {
	ids := make([]string, 0, len(coverages))
	seen := make(map[string]struct{}, len(coverages))
	for _, coverage := range coverages {
		id := strings.TrimSpace(coverage.SourceAttemptID)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	completed := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		return completed, nil
	}
	var sources []SubTask
	if err := store.Select("id", "status").Where(
		"tenant_id = ? AND project_id = ? AND id IN ?", tenantID, projectID, ids,
	).Find(&sources).Error; err != nil {
		return nil, fmt.Errorf("load reusable source attempts: %w", err)
	}
	for _, source := range sources {
		completed[source.ID] = CanonicalAttemptState(source.Status) == AttemptStateCompleted
	}
	return completed, nil
}

func lockReusableAttemptContext(store *gorm.DB, attemptID, tenantID string) (SubTask, TaskBatch, RootTask, bool, error) {
	var hint SubTask
	if err := store.Where("id = ? AND tenant_id = ?", attemptID, tenantID).First(&hint).Error; err != nil {
		return hint, TaskBatch{}, RootTask{}, false, err
	}
	if hint.RootTaskID == "" || hint.BatchID == "" || hint.ProjectID == "" {
		return hint, TaskBatch{}, RootTask{}, false, nil
	}
	var root RootTask
	if err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
		"id = ? AND tenant_id = ? AND project_id = ?", hint.RootTaskID, hint.TenantID, hint.ProjectID,
	).First(&root).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return hint, TaskBatch{}, root, false, nil
		}
		return hint, TaskBatch{}, root, false, err
	}
	var batch TaskBatch
	if err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
		"id = ? AND tenant_id = ? AND project_id = ? AND root_task_id = ? AND latest_attempt_id = ? AND archived_at IS NULL",
		hint.BatchID, hint.TenantID, hint.ProjectID, hint.RootTaskID, hint.ID,
	).First(&batch).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return hint, batch, root, false, nil
		}
		return hint, batch, root, false, err
	}
	var attempt SubTask
	if err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
		"id = ? AND tenant_id = ? AND project_id = ? AND root_task_id = ? AND batch_id = ?",
		hint.ID, hint.TenantID, hint.ProjectID, hint.RootTaskID, hint.BatchID,
	).First(&attempt).Error; err != nil {
		return attempt, batch, root, false, err
	}
	rootState := CanonicalTaskState(root.Status)
	rootActive := root.ArchivedAt == nil && (rootState == TaskStateQueued || rootState == TaskStateRunning || rootState == TaskStatePartial)
	eligible := rootActive && CanonicalBatchControlState(batch.ControlState) == BatchControlActive && scanReuseAttemptClaimable(attempt)
	return attempt, batch, root, eligible, nil
}

func scanReuseAttemptClaimable(attempt SubTask) bool {
	if strings.TrimSpace(attempt.AgentID) != "" {
		return false
	}
	switch CanonicalAttemptState(attempt.Status) {
	case AttemptStateQueued, AttemptStateRecovered, AttemptStateDispatching:
		return true
	default:
		return false
	}
}

func decodeReusableScanConfig(raw string) (reusableScanConfig, bool) {
	var config reusableScanConfig
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &fields) != nil || json.Unmarshal([]byte(raw), &config) != nil {
		return config, false
	}
	for _, required := range []string{
		"Hunter", "Fofa", "Quake", "OnlyIPPort", "Subdomain", "SkipHostDiscovery", "NoICMPPing", "TCPPing",
		"NoHostBind", "NoDirSearch", "NoPoc", "GolangPoc", "DisableGeneralPoc", "PocNameForSearch",
	} {
		if _, exists := fields[required]; !exists {
			return config, false
		}
	}
	if strings.TrimSpace(config.ExecutionMode) != "" || config.Hunter || config.Fofa || config.Quake || config.OnlyIPPort {
		return config, false
	}
	if !config.NoPoc || config.GolangPoc || !config.DisableGeneralPoc || strings.TrimSpace(config.PocNameForSearch) != "" {
		return config, false
	}
	return config, true
}

func reusableStagesForTarget(target string, config reusableScanConfig) ([]scanplan.Stage, bool, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, false, false
	}
	common := []scanplan.Stage{scanplan.StageHTTPProbe}
	if !config.NoHostBind {
		common = append(common, scanplan.StageHostBinding)
	}
	if !config.NoDirSearch {
		common = append(common, scanplan.StageDirectoryProbe)
	}
	common = append(common, scanplan.StageFingerprint)

	switch reusableTargetKind(target) {
	case "url":
		return common, false, true
	case "ip", "cidr", "ip_range":
		stages := make([]scanplan.Stage, 0, len(common)+3)
		if !config.SkipHostDiscovery && !config.NoICMPPing {
			stages = append(stages, scanplan.StageICMPDiscovery)
		}
		if !config.SkipHostDiscovery {
			stages = append(stages, scanplan.StageTCPLiveness)
		}
		stages = append(stages, scanplan.StagePortScan)
		stages = append(stages, common...)
		return stages, true, true
	case "domain":
		stages := make([]scanplan.Stage, 0, len(common)+4)
		if config.Subdomain {
			stages = append(stages, scanplan.StageSubdomainDiscovery)
		}
		stages = append(stages, scanplan.StageCDNClassification)
		if !config.NoResolvedIPScan {
			stages = append(stages, scanplan.StagePortScan)
		}
		stages = append(stages, common...)
		return stages, true, true
	case "ip_port", "domain_port":
		return append([]scanplan.Stage{scanplan.StageProtocolIdentify}, common...), false, true
	default:
		return nil, false, false
	}
}

func reusableTargetKind(target string) string {
	if parsed, err := url.Parse(target); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return "url"
	}
	if net.ParseIP(target) != nil {
		return "ip"
	}
	if _, _, err := net.ParseCIDR(target); err == nil {
		return "cidr"
	}
	if parts := strings.SplitN(target, "-", 2); len(parts) == 2 && net.ParseIP(strings.TrimSpace(parts[0])) != nil && net.ParseIP(strings.TrimSpace(parts[1])) != nil {
		return "ip_range"
	}
	if host, port, err := net.SplitHostPort(target); err == nil && validReusePort(port) {
		if net.ParseIP(host) != nil {
			return "ip_port"
		}
		return "domain_port"
	}
	if parts := strings.Split(target, ":"); len(parts) == 2 && validReusePort(parts[1]) {
		if net.ParseIP(parts[0]) != nil {
			return "ip_port"
		}
		return "domain_port"
	}
	if !strings.ContainsAny(target, " /?#") {
		return "domain"
	}
	return ""
}

func reusableTargetIPCount(targets []string) int {
	count := 0
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if _, network, err := net.ParseCIDR(target); err == nil {
			ones, bits := network.Mask.Size()
			if bits != 32 || ones < 0 || bits-ones > 8 {
				return 257
			}
			count += 1 << (bits - ones)
		} else if parts := strings.SplitN(target, "-", 2); len(parts) == 2 {
			start := net.ParseIP(strings.TrimSpace(parts[0])).To4()
			end := net.ParseIP(strings.TrimSpace(parts[1])).To4()
			if start == nil || end == nil {
				count++
			} else {
				first := binary.BigEndian.Uint32(start)
				last := binary.BigEndian.Uint32(end)
				if last < first || uint64(last)-uint64(first)+1 > 256 {
					return 257
				}
				count += int(last-first) + 1
			}
		} else {
			count++
		}
		if count > 256 {
			return 257
		}
	}
	return count
}

func validReusePort(raw string) bool {
	port, err := strconv.Atoi(raw)
	return err == nil && port > 0 && port < 65536
}

func reusableCoverageValid(coverage ScanCoverage, networkZone string, now time.Time) bool {
	if coverage.NetworkZone != networkZone || scanplan.CoverageStatus(coverage.Status) != scanplan.CoverageComplete {
		return false
	}
	outcome := scanplan.ObservationOutcome(coverage.Outcome)
	if outcome != scanplan.ObservationSuccess && outcome != scanplan.ObservationNegative {
		return false
	}
	return coverage.ValidUntil == nil || coverage.ValidUntil.After(now)
}
