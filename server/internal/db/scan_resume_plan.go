package db

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ValidateResumePlanAtLease rebuilds the plan while holding the destination
// lifecycle, Agent, Coverage, and checkpoint evidence rows. Only the exact
// canonical plan selected by this final transaction may authorize stage reuse.
func ValidateResumePlanAtLease(store *gorm.DB, attemptID, tenantID, agentID string, plan *scanplan.ResumePlan, planHash string) ([]TaskCoverageLink, error) {
	if store == nil || plan == nil || len(plan.ReusedStages) == 0 {
		return nil, ErrReusableCoverageChanged
	}
	if err := plan.Validate(); err != nil {
		return nil, ErrReusableCoverageChanged
	}
	digest, err := plan.Digest()
	if err != nil || digest != strings.TrimSpace(planHash) {
		return nil, ErrReusableCoverageChanged
	}

	attempt, batch, _, eligible, err := lockReusableAttemptContext(store, attemptID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("reload resume attempt: %w", err)
	}
	if !eligible || strings.EqualFold(strings.TrimSpace(batch.Kind), "risk_validation") || normalizeAttemptTrigger(attempt.Trigger) == AttemptTriggerManualRetry {
		return nil, ErrReusableCoverageChanged
	}
	var targets []string
	if json.Unmarshal([]byte(attempt.ChunkTargets), &targets) != nil || len(targets) != 1 || strings.TrimSpace(targets[0]) != plan.Target {
		return nil, ErrReusableCoverageChanged
	}
	config, ok := decodeReusableScanConfig(attempt.Config)
	if !ok || strings.TrimSpace(attempt.RuleVersion) == "" {
		return nil, ErrReusableCoverageChanged
	}
	if !config.TCPPing && !config.SkipHostDiscovery && reusableTargetIPCount(targets) <= 256 {
		config.SkipHostDiscovery = true
	}
	var project Project
	if err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
		"id = ? AND tenant_id = ? AND status = ?", attempt.ProjectID, attempt.TenantID, "active",
	).First(&project).Error; err != nil {
		return nil, ErrReusableCoverageChanged
	}
	scopeHash, validScope := canonicalJSONHash(project.Scope)
	if !validScope {
		return nil, ErrReusableCoverageChanged
	}
	configHash := observationConfigHash(store, attempt)
	var node Node
	if err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Select("agent_id", "tenant_id", "status", "tags", "rule_version").Where(
		"agent_id = ? AND tenant_id = ? AND UPPER(status) = ?", agentID, attempt.TenantID, "ALIVE",
	).First(&node).Error; err != nil || strings.TrimSpace(node.RuleVersion) != strings.TrimSpace(attempt.RuleVersion) {
		return nil, ErrReusableCoverageChanged
	}
	required, protocolAfterPort, validTarget := reusableStagesForTarget(plan.Target, config)
	if !validTarget {
		return nil, ErrReusableCoverageChanged
	}
	targetPlan := targetCoveragePlan{
		target: plan.Target, networkZone: scanNetworkZoneForTarget(agentID, node.Tags, plan.Target),
		required: required, protocolAfterPort: protocolAfterPort,
		workHashes: make(map[scanplan.Stage]string, len(required)+1),
	}
	workHashes := make([]string, 0, len(required)+1)
	for _, stage := range materializedResumeStages(targetPlan) {
		workKey := scanplan.WorkKey{
			TenantID: attempt.TenantID, ProjectID: attempt.ProjectID, NetworkZone: targetPlan.networkZone,
			NormalizedTarget: plan.Target, Stage: stage, ScopeHash: scopeHash, ConfigHash: configHash,
			RuleVersion: attempt.RuleVersion,
		}
		workHash, err := workKey.Digest()
		if err != nil {
			return nil, ErrReusableCoverageChanged
		}
		targetPlan.workHashes[stage] = workHash
		workHashes = append(workHashes, workHash)
	}
	var coverages []ScanCoverage
	if err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
		"tenant_id = ? AND project_id = ? AND work_key_hash IN ?", attempt.TenantID, attempt.ProjectID, workHashes,
	).Find(&coverages).Error; err != nil {
		return nil, fmt.Errorf("reload resume coverage: %w", err)
	}
	completedSources, err := completedReusableSourceAttempts(store, attempt.TenantID, attempt.ProjectID, coverages)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	coverageByWork := make(map[string]ScanCoverage, len(coverages))
	for _, coverage := range coverages {
		if coverage.ValidUntil != nil && coverage.ValidUntil.After(now) &&
			reusableCoverageValid(coverage, targetPlan.networkZone, now) && coverage.SourceAttemptID != attempt.ID && completedSources[coverage.SourceAttemptID] {
			coverageByWork[coverage.WorkKeyHash] = coverage
		}
	}
	expected, expectedHash, err := buildCheckpointAwareResumePlan(store, attempt, targetPlan, coverageByWork, scopeHash, configHash)
	if err != nil || expected == nil || expectedHash != digest {
		return nil, ErrReusableCoverageChanged
	}
	expectedJSON, expectedErr := expected.CanonicalJSON()
	actualJSON, actualErr := plan.CanonicalJSON()
	if expectedErr != nil || actualErr != nil || !bytes.Equal(expectedJSON, actualJSON) {
		return nil, ErrReusableCoverageChanged
	}

	links := make([]TaskCoverageLink, 0, len(plan.ReusedStages))
	for _, stage := range plan.ReusedStages {
		coverage, exists := coverageByWork[targetPlan.workHashes[stage]]
		if !exists {
			return nil, ErrReusableCoverageChanged
		}
		links = append(links, TaskCoverageLink{
			SchemaVersion: scanplan.SchemaVersion,
			TenantID:      attempt.TenantID, ProjectID: attempt.ProjectID, RootTaskID: attempt.RootTaskID,
			BatchID: attempt.BatchID, AttemptID: attempt.ID, WorkKeyHash: coverage.WorkKeyHash,
			LinkType: "reused", Status: "active", CoverageID: coverage.ID,
			SourceTaskID: coverage.SourceTaskID, SourceBatchID: coverage.SourceBatchID,
			SourceAttemptID: coverage.SourceAttemptID, Reason: "resume_plan:" + digest,
		})
	}
	return links, nil
}

// buildCheckpointAwareResumePlan computes a single-target execution suffix but
// deliberately does not change the Attempt or its outbound Agent config.
// ClaimTask applies the validated contract at the final lease boundary.
func buildCheckpointAwareResumePlan(
	store *gorm.DB,
	attempt SubTask,
	targetPlan targetCoveragePlan,
	coverageByWork map[string]ScanCoverage,
	scopeHash string,
	configHash string,
) (*scanplan.ResumePlan, string, error) {
	// Stage resume is stricter than legacy full-target reuse: a persisted,
	// unexpired TTL is mandatory. Older pre-TTL rows remain auditable but can
	// never authorize a partial pipeline skip.
	now := time.Now().UTC()
	resumeCoverage := make(map[string]ScanCoverage, len(coverageByWork))
	for workKeyHash, coverage := range coverageByWork {
		if coverage.ValidUntil != nil && coverage.ValidUntil.After(now) {
			resumeCoverage[workKeyHash] = coverage
		}
	}
	coverageByWork = resumeCoverage
	required := materializedResumeStages(targetPlan)
	firstMissing := -1
	for index, stage := range required {
		if _, covered := coverageByWork[targetPlan.workHashes[stage]]; !covered {
			firstMissing = index
			break
		}
	}
	if firstMissing < 0 {
		return nil, "", nil
	}

	start := rewindHTTPContentDependency(required, firstMissing)
	fallbackReason := ""
	checkpoints := make([]scanplan.ResumeCheckpoint, 0, 2)
	kind := reusableTargetKind(targetPlan.target)

	switch kind {
	case "url":
		if start > 0 {
			start = 0
		}
		if firstMissing > 0 {
			fallbackReason = "http_content_not_replayable"
		}
	case "domain":
		// Subdomain and CDN stages currently do not persist a trusted DNS
		// mapping from discovered names to the resolved endpoints consumed by
		// port scanning. Re-run the domain chain instead of replaying bare IPs.
		if start > 0 {
			start = 0
		}
		if firstMissing > 0 {
			fallbackReason = "domain_resolution_not_replayable"
		}
	case "ip", "cidr", "ip_range":
		var reason string
		var err error
		start, checkpoints, reason, err = rewindNetworkResumeStart(store, attempt, targetPlan, required, start, coverageByWork)
		if err != nil {
			return nil, "", err
		}
		fallbackReason = reason
	case "ip_port", "domain_port":
		if required[start] == scanplan.StageHTTPProbe {
			protocolIndex := stageIndex(required, scanplan.StageProtocolIdentify)
			evidence, ok, err := reusableCheckpointEvidence(store, attempt, targetPlan, coverageByWork, scanplan.StageProtocolIdentify)
			if err != nil {
				return nil, "", err
			}
			if ok {
				checkpoints = append(checkpoints, evidence)
			} else if protocolIndex >= 0 {
				start = protocolIndex
				fallbackReason = "checkpoint_unavailable:protocol_identification"
			}
		}
	default:
		return nil, "", nil
	}

	if start < 0 || start >= len(required) {
		return nil, "", errors.New("resume planner produced an invalid execution boundary")
	}
	if start == 0 && fallbackReason == "" {
		fallbackReason = "no_replayable_prefix"
	}
	plan := &scanplan.ResumePlan{
		SchemaVersion:   scanplan.ResumePlanSchemaVersion,
		TenantID:        attempt.TenantID,
		ProjectID:       attempt.ProjectID,
		NetworkZone:     targetPlan.networkZone,
		Target:          targetPlan.target,
		ScopeHash:       scopeHash,
		ConfigHash:      configHash,
		RuleVersion:     attempt.RuleVersion,
		RequiredStages:  append([]scanplan.Stage(nil), required...),
		ReusedStages:    append([]scanplan.Stage(nil), required[:start]...),
		ExecutionStages: append([]scanplan.Stage(nil), required[start:]...),
		StartStage:      required[start],
		Checkpoints:     checkpoints,
		FallbackReason:  fallbackReason,
	}
	if err := plan.Validate(); err != nil {
		return nil, "", fmt.Errorf("validate checkpoint-aware resume plan: %w", err)
	}
	planHash, err := plan.Digest()
	if err != nil {
		return nil, "", fmt.Errorf("hash checkpoint-aware resume plan: %w", err)
	}
	return plan, planHash, nil
}

// materializedResumeStages includes the conditional protocol stage whenever a
// port scan may be re-executed. A previously negative port observation cannot
// predict that the next port execution will also be negative.
func materializedResumeStages(plan targetCoveragePlan) []scanplan.Stage {
	stages := make([]scanplan.Stage, 0, len(plan.required)+1)
	for _, stage := range plan.required {
		stages = append(stages, stage)
		if stage == scanplan.StagePortScan && plan.protocolAfterPort {
			stages = append(stages, scanplan.StageProtocolIdentify)
		}
	}
	return stages
}

func rewindHTTPContentDependency(required []scanplan.Stage, firstMissing int) int {
	if firstMissing < 0 || firstMissing >= len(required) {
		return firstMissing
	}
	switch required[firstMissing] {
	case scanplan.StageHostBinding, scanplan.StageDirectoryProbe, scanplan.StageFingerprint:
		if httpIndex := stageIndex(required, scanplan.StageHTTPProbe); httpIndex >= 0 && httpIndex < firstMissing {
			return httpIndex
		}
	}
	return firstMissing
}

func rewindNetworkResumeStart(
	store *gorm.DB,
	attempt SubTask,
	targetPlan targetCoveragePlan,
	required []scanplan.Stage,
	start int,
	coverageByWork map[string]ScanCoverage,
) (int, []scanplan.ResumeCheckpoint, string, error) {
	checkpoints := make([]scanplan.ResumeCheckpoint, 0, 2)
	fallbackReason := ""
	for {
		switch required[start] {
		case scanplan.StageICMPDiscovery, scanplan.StageTCPLiveness:
			// ICMP and TCP liveness are independent producers whose union feeds
			// the later port stage. If one producer is reused while the other is
			// executed, replay every earlier liveness output into that union.
			liveness := stagesBefore(required, start, scanplan.StageICMPDiscovery, scanplan.StageTCPLiveness)
			for _, stage := range liveness {
				evidence, ok, err := reusableCheckpointEvidence(store, attempt, targetPlan, coverageByWork, stage)
				if err != nil {
					return start, nil, "", err
				}
				if !ok {
					return stageIndex(required, stage), nil, "checkpoint_unavailable:" + string(stage), nil
				}
				checkpoints = append(checkpoints, evidence)
			}
			return start, checkpoints, fallbackReason, nil
		case scanplan.StageHTTPProbe:
			protocolIndex := stageIndex(required, scanplan.StageProtocolIdentify)
			evidence, ok, err := reusableCheckpointEvidence(store, attempt, targetPlan, coverageByWork, scanplan.StageProtocolIdentify)
			if err != nil {
				return start, nil, "", err
			}
			if ok && protocolIndex >= 0 && protocolIndex < start {
				return start, []scanplan.ResumeCheckpoint{evidence}, fallbackReason, nil
			}
			if protocolIndex < 0 || protocolIndex >= start {
				return 0, nil, "protocol_dependency_not_replayable", nil
			}
			start = protocolIndex
			fallbackReason = "checkpoint_unavailable:protocol_identification"
		case scanplan.StageProtocolIdentify:
			portIndex := stageIndex(required, scanplan.StagePortScan)
			evidence, ok, err := reusableCheckpointEvidence(store, attempt, targetPlan, coverageByWork, scanplan.StagePortScan)
			if err != nil {
				return start, nil, "", err
			}
			if ok && portIndex >= 0 && portIndex < start {
				return start, []scanplan.ResumeCheckpoint{evidence}, fallbackReason, nil
			}
			if portIndex < 0 || portIndex >= start {
				return 0, nil, "port_dependency_not_replayable", nil
			}
			start = portIndex
			fallbackReason = "checkpoint_unavailable:port_scan"
		case scanplan.StagePortScan:
			liveness := stagesBefore(required, start, scanplan.StageICMPDiscovery, scanplan.StageTCPLiveness)
			if len(liveness) == 0 {
				return start, nil, fallbackReason, nil
			}
			checkpoints = checkpoints[:0]
			for _, stage := range liveness {
				evidence, ok, err := reusableCheckpointEvidence(store, attempt, targetPlan, coverageByWork, stage)
				if err != nil {
					return start, nil, "", err
				}
				if !ok {
					return stageIndex(required, stage), nil, "checkpoint_unavailable:" + string(stage), nil
				}
				checkpoints = append(checkpoints, evidence)
			}
			return start, checkpoints, fallbackReason, nil
		default:
			return start, nil, fallbackReason, nil
		}
	}
}

func reusableCheckpointEvidence(
	store *gorm.DB,
	attempt SubTask,
	targetPlan targetCoveragePlan,
	coverageByWork map[string]ScanCoverage,
	stage scanplan.Stage,
) (scanplan.ResumeCheckpoint, bool, error) {
	coverage, exists := coverageByWork[targetPlan.workHashes[stage]]
	if !exists || coverage.SourceObservationID == 0 {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	var observation ScanObservation
	err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
		"id = ? AND tenant_id = ? AND project_id = ?",
		coverage.SourceObservationID, attempt.TenantID, attempt.ProjectID,
	).First(&observation).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	if err != nil {
		return scanplan.ResumeCheckpoint{}, false, fmt.Errorf("load resume checkpoint observation: %w", err)
	}
	if observation.WorkKeyHash != coverage.WorkKeyHash || observation.NetworkZone != targetPlan.networkZone ||
		observation.NormalizedTarget != targetPlan.target || observation.Stage != string(stage) ||
		observation.ScopeHash != coverage.ScopeHash || observation.ConfigHash != coverage.ConfigHash ||
		observation.RuleVersion != coverage.RuleVersion || observation.Outcome != coverage.Outcome ||
		observation.RootTaskID != coverage.SourceTaskID || observation.BatchID != coverage.SourceBatchID ||
		observation.AttemptID != coverage.SourceAttemptID || observation.EvidenceHash == "" ||
		observation.EvidenceHash != coverage.ObservationHash || observation.CheckpointHash == "" {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	workKey := scanplan.WorkKey{
		TenantID:            coverage.TenantID,
		ProjectID:           coverage.ProjectID,
		NetworkZone:         coverage.NetworkZone,
		NormalizedTarget:    coverage.NormalizedTarget,
		Stage:               stage,
		ScopeHash:           coverage.ScopeHash,
		ConfigHash:          coverage.ConfigHash,
		RuleVersion:         coverage.RuleVersion,
		POCSetHash:          coverage.POCSetHash,
		EndpointContentHash: coverage.EndpointContentHash,
	}
	workKeyHash, err := workKey.Digest()
	if err != nil || workKeyHash != coverage.WorkKeyHash {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	observationContract := scanplan.Observation{
		SchemaVersion:  scanplan.SchemaVersion,
		WorkKey:        workKey,
		Outcome:        scanplan.ObservationOutcome(observation.Outcome),
		ObservedAt:     observation.ObservedAt,
		ContentHash:    observation.ContentHash,
		CheckpointHash: observation.CheckpointHash,
		ErrorCode:      observation.ErrorCode,
		ErrorMessage:   observation.ErrorMessage,
	}
	if observation.SchemaVersion != scanplan.SchemaVersion || observationContract.Validate() != nil {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	evidenceHash, err := canonicalContractHash(observationContract)
	if err != nil || evidenceHash != observation.EvidenceHash {
		return scanplan.ResumeCheckpoint{}, false, nil
	}

	var checkpoint scanplan.StageCheckpoint
	decoder := json.NewDecoder(strings.NewReader(observation.Checkpoint))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	if checkpoint.Stage != stage || checkpoint.ValidateForTarget(targetPlan.target) != nil {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	canonical, err := checkpoint.CanonicalJSON()
	if err != nil {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	digest := sha256.Sum256(canonical)
	checkpointHash := hex.EncodeToString(digest[:])
	if checkpointHash != observation.CheckpointHash {
		return scanplan.ResumeCheckpoint{}, false, nil
	}
	return scanplan.ResumeCheckpoint{
		Stage:               stage,
		WorkKeyHash:         coverage.WorkKeyHash,
		CoverageID:          coverage.ID,
		SourceObservationID: observation.ID,
		ObservationHash:     observation.EvidenceHash,
		CheckpointHash:      checkpointHash,
		Checkpoint:          checkpoint,
	}, true, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func stageIndex(stages []scanplan.Stage, wanted scanplan.Stage) int {
	for index, stage := range stages {
		if stage == wanted {
			return index
		}
	}
	return -1
}

func stagesBefore(stages []scanplan.Stage, end int, wanted ...scanplan.Stage) []scanplan.Stage {
	allowed := make(map[scanplan.Stage]struct{}, len(wanted))
	for _, stage := range wanted {
		allowed[stage] = struct{}{}
	}
	matched := make([]scanplan.Stage, 0, len(wanted))
	for index, stage := range stages {
		if index >= end {
			break
		}
		if _, ok := allowed[stage]; ok {
			matched = append(matched, stage)
		}
	}
	return matched
}
