package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ScanObservationMergeResult struct {
	ObservationsCreated  int
	CoveragesCreated     int
	CoveragesUpdated     int
	CoveragesInvalidated int
}

// MergeStageObservationEvent enriches an Agent event with Server-owned trust
// dimensions and atomically appends observations plus their current coverage.
// It does not decide whether future tasks may reuse that coverage.
func MergeStageObservationEvent(store *gorm.DB, attempt SubTask, event scanplan.StageObservationEvent) (ScanObservationMergeResult, error) {
	var result ScanObservationMergeResult
	if store == nil {
		return result, errors.New("scan observation store is unavailable")
	}
	if err := event.Validate(); err != nil {
		return result, err
	}
	if strings.TrimSpace(attempt.ID) == "" || event.AttemptID != attempt.ID || event.AgentID != attempt.AgentID {
		return result, errors.New("stage observation source does not match the assigned attempt")
	}

	err := store.Transaction(func(tx *gorm.DB) error {
		var project Project
		if err := tx.Unscoped().Where("id = ? AND tenant_id = ?", attempt.ProjectID, attempt.TenantID).First(&project).Error; err != nil {
			return fmt.Errorf("load observation project scope: %w", err)
		}
		scopeHash, scopeValid := canonicalJSONHash(project.Scope)
		configHash := observationConfigHash(tx, attempt)
		rawConfigHash := sha256Hex([]byte(attempt.Config))
		ruleVersion := strings.TrimSpace(event.RuleVersion)
		if ruleVersion == "" {
			ruleVersion = "_unknown"
		}
		expectedRuleVersion := strings.TrimSpace(attempt.RuleVersion)
		if expectedRuleVersion == "" {
			expectedRuleVersion = "_unknown"
		}
		nodeTags := ""
		var node Node
		if err := tx.Select("tags").Where("agent_id = ? AND tenant_id = ?", attempt.AgentID, attempt.TenantID).First(&node).Error; err == nil {
			nodeTags = node.Tags
		}
		checkpointTarget := ""
		if len(event.Targets) == 1 {
			checkpointTarget = event.Targets[0]
		}
		checkpointJSON, checkpointHash, err := observationCheckpointEvidence(event.Checkpoint, checkpointTarget)
		if err != nil {
			return err
		}

		for _, target := range event.Targets {
			target = strings.TrimSpace(target)
			networkZone := scanNetworkZoneForTarget(attempt.AgentID, nodeTags, target)
			targetHash := sha256Hex([]byte(target))
			pocSetHash := ""
			endpointContentHash := ""
			invalidReasons := make([]string, 0, 5)
			if !scopeValid {
				invalidReasons = append(invalidReasons, "project_scope_invalid")
			}
			if event.ConfigHash != rawConfigHash {
				invalidReasons = append(invalidReasons, "agent_config_hash_mismatch")
			}
			if ruleVersion == "_unknown" || expectedRuleVersion == "_unknown" || ruleVersion != expectedRuleVersion {
				invalidReasons = append(invalidReasons, "rule_version_mismatch_or_unknown")
			}
			if event.Stage == scanplan.StageRiskValidation {
				var known bool
				pocSetHash, known = riskValidationPOCSetHash(attempt.Config, target)
				if !known {
					pocSetHash = "_unknown"
					invalidReasons = append(invalidReasons, "poc_set_unknown")
				}
				endpointContentHash, known = latestEndpointContentHash(tx, attempt.TenantID, attempt.ProjectID, networkZone, targetHash)
				if !known {
					endpointContentHash = "_unknown"
					invalidReasons = append(invalidReasons, "endpoint_content_unknown")
				}
			}

			workKey := scanplan.WorkKey{
				TenantID: attempt.TenantID, ProjectID: attempt.ProjectID, NetworkZone: networkZone,
				NormalizedTarget: target, Stage: event.Stage, ScopeHash: scopeHash, ConfigHash: configHash,
				RuleVersion: ruleVersion, POCSetHash: pocSetHash, EndpointContentHash: endpointContentHash,
			}
			workKeyHash, err := workKey.Digest()
			if err != nil {
				return fmt.Errorf("build stage observation WorkKey: %w", err)
			}
			observationContract := scanplan.Observation{
				SchemaVersion:  scanplan.SchemaVersion,
				WorkKey:        workKey,
				Outcome:        event.Outcome,
				ObservedAt:     event.FinishedAt,
				ContentHash:    event.ContentHash,
				CheckpointHash: checkpointHash,
				ErrorCode:      event.ErrorCode,
				ErrorMessage:   event.ErrorMessage,
			}
			if err := observationContract.Validate(); err != nil {
				return fmt.Errorf("build stage observation: %w", err)
			}
			observationHash, err := canonicalContractHash(observationContract)
			if err != nil {
				return err
			}
			sourceEventID := targetObservationEventID(event, target)
			observation := ScanObservation{
				SchemaVersion: scanplan.SchemaVersion,
				TenantID:      attempt.TenantID, ProjectID: attempt.ProjectID, NetworkZone: networkZone,
				NormalizedTarget: target, TargetHash: targetHash, Stage: string(event.Stage), WorkKeyHash: workKeyHash,
				ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: ruleVersion,
				POCSetHash: pocSetHash, EndpointContentHash: endpointContentHash, SourceEventID: &sourceEventID,
				RootTaskID: attempt.RootTaskID, BatchID: attempt.BatchID, AttemptID: attempt.ID, AgentID: attempt.AgentID,
				Outcome: string(event.Outcome), ContentHash: event.ContentHash, Checkpoint: checkpointJSON, CheckpointHash: checkpointHash, EvidenceHash: observationHash,
				ErrorCode: event.ErrorCode, ErrorMessage: event.ErrorMessage, ObservedAt: event.FinishedAt,
			}
			previousContentHash, hadPreviousContent := "", false
			if len(dependentCoverageStages(event.Stage)) > 0 {
				previousContentHash, hadPreviousContent, err = currentCoverageContentHash(tx, attempt.TenantID, attempt.ProjectID, workKeyHash)
				if err != nil {
					return err
				}
			}
			created, err := appendScanObservation(tx, &observation)
			if err != nil {
				return err
			}
			if created {
				result.ObservationsCreated++
			}

			coverage := coverageFromObservation(observation, event, invalidReasons)
			createdCoverage, updatedCoverage, err := mergeCurrentCoverage(tx, &coverage)
			if err != nil {
				return err
			}
			if createdCoverage {
				result.CoveragesCreated++
			}
			if updatedCoverage {
				result.CoveragesUpdated++
			}
			if updatedCoverage && coverage.Status == string(scanplan.CoverageComplete) && hadPreviousContent && previousContentHash != strings.TrimSpace(observation.ContentHash) {
				invalidated, err := invalidateChangedContentDependents(tx, observation, event.Stage)
				if err != nil {
					return err
				}
				result.CoveragesInvalidated += int(invalidated)
			}
		}
		return nil
	})
	return result, err
}

func observationCheckpointEvidence(checkpoint *scanplan.StageCheckpoint, target string) (string, string, error) {
	if checkpoint == nil {
		return "{}", "", nil
	}
	if err := checkpoint.ValidateForTarget(target); err != nil {
		return "", "", fmt.Errorf("validate stage checkpoint target: %w", err)
	}
	encoded, err := checkpoint.CanonicalJSON()
	if err != nil {
		return "", "", fmt.Errorf("encode stage checkpoint: %w", err)
	}
	return string(encoded), sha256Hex(encoded), nil
}

func appendScanObservation(tx *gorm.DB, observation *ScanObservation) (bool, error) {
	created := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(observation)
	if created.Error != nil {
		return false, fmt.Errorf("append scan observation: %w", created.Error)
	}
	if created.RowsAffected == 1 {
		return true, nil
	}
	var existing ScanObservation
	if err := tx.Where("tenant_id = ? AND source_event_id = ?", observation.TenantID, observation.SourceEventID).First(&existing).Error; err != nil {
		return false, fmt.Errorf("load idempotent scan observation: %w", err)
	}
	if existing.EvidenceHash != observation.EvidenceHash || existing.WorkKeyHash != observation.WorkKeyHash {
		return false, errors.New("coverage event ID was replayed with different evidence")
	}
	*observation = existing
	return false, nil
}

func coverageFromObservation(observation ScanObservation, event scanplan.StageObservationEvent, invalidReasons []string) ScanCoverage {
	status := scanplan.CoverageComplete
	if event.Outcome == scanplan.ObservationFailed || event.Outcome == scanplan.ObservationSkipped {
		status = scanplan.CoverageIncomplete
	} else if len(invalidReasons) > 0 {
		status = scanplan.CoverageInvalidated
	}
	return ScanCoverage{
		SchemaVersion: scanplan.SchemaVersion,
		TenantID:      observation.TenantID, ProjectID: observation.ProjectID, NetworkZone: observation.NetworkZone,
		NormalizedTarget: observation.NormalizedTarget, TargetHash: observation.TargetHash, Stage: observation.Stage, WorkKeyHash: observation.WorkKeyHash,
		ScopeHash: observation.ScopeHash, ConfigHash: observation.ConfigHash, RuleVersion: observation.RuleVersion,
		POCSetHash: observation.POCSetHash, EndpointContentHash: observation.EndpointContentHash,
		Status: string(status), Outcome: observation.Outcome,
		StartedAt: event.StartedAt, FinishedAt: event.FinishedAt, ValidUntil: coverageValidUntil(status, event.Stage, event.FinishedAt), ObservationHash: observation.EvidenceHash,
		SourceObservationID: observation.ID, SourceTaskID: observation.RootTaskID, SourceBatchID: observation.BatchID, SourceAttemptID: observation.AttemptID,
		Revision: 1, InvalidReason: strings.Join(invalidReasons, ","),
	}
}

func mergeCurrentCoverage(tx *gorm.DB, candidate *ScanCoverage) (bool, bool, error) {
	var current ScanCoverage
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("tenant_id = ? AND project_id = ? AND work_key_hash = ?", candidate.TenantID, candidate.ProjectID, candidate.WorkKeyHash).
		First(&current).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := tx.Create(candidate).Error; err != nil {
			return false, false, fmt.Errorf("create scan coverage: %w", err)
		}
		return true, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("load current scan coverage: %w", err)
	}
	if current.SourceObservationID == candidate.SourceObservationID || current.FinishedAt.After(candidate.FinishedAt) {
		return false, false, nil
	}
	updates := map[string]interface{}{
		"schema_version": candidate.SchemaVersion, "network_zone": candidate.NetworkZone,
		"normalized_target": candidate.NormalizedTarget, "target_hash": candidate.TargetHash, "stage": candidate.Stage,
		"scope_hash": candidate.ScopeHash, "config_hash": candidate.ConfigHash, "rule_version": candidate.RuleVersion,
		"poc_set_hash": candidate.POCSetHash, "endpoint_content_hash": candidate.EndpointContentHash,
		"status": candidate.Status, "outcome": candidate.Outcome, "started_at": candidate.StartedAt, "finished_at": candidate.FinishedAt,
		"valid_until": candidate.ValidUntil, "observation_hash": candidate.ObservationHash,
		"source_observation_id": candidate.SourceObservationID, "source_task_id": candidate.SourceTaskID,
		"source_batch_id": candidate.SourceBatchID, "source_attempt_id": candidate.SourceAttemptID,
		"revision": gorm.Expr("revision + 1"), "invalid_reason": candidate.InvalidReason,
	}
	if err := tx.Model(&ScanCoverage{}).Where("id = ? AND tenant_id = ? AND project_id = ?", current.ID, current.TenantID, current.ProjectID).Updates(updates).Error; err != nil {
		return false, false, fmt.Errorf("update scan coverage: %w", err)
	}
	return false, true, nil
}

func canonicalJSONHash(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "{}"
	}
	var value interface{}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return sha256Hex([]byte(raw)), false
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return sha256Hex([]byte(raw)), false
	}
	return sha256Hex(encoded), true
}

func observationConfigHash(tx *gorm.DB, attempt SubTask) string {
	version := attempt.ConfigVersion
	if version < 1 {
		version = 1
	}
	var revision TaskConfigRevision
	if err := tx.Select("config_hash").Where(
		"tenant_id = ? AND project_id = ? AND root_task_id = ? AND version = ?",
		attempt.TenantID, attempt.ProjectID, attempt.RootTaskID, version,
	).First(&revision).Error; err == nil && strings.TrimSpace(revision.ConfigHash) != "" {
		return strings.TrimSpace(revision.ConfigHash)
	}
	selector := strings.TrimSpace(attempt.AgentSelector)
	if selector == "" {
		selector = "{}"
	}
	selectorRules := strings.TrimSpace(attempt.AgentSelectorRules)
	if selectorRules == "" {
		selectorRules = "{}"
	}
	return TaskConfigHash(attempt.Config, attempt.Priority, attempt.TimeoutSec, selector, selectorRules)
}

func canonicalContractHash(value interface{}) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("hash scan observation: %w", err)
	}
	return sha256Hex(encoded), nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func targetObservationEventID(event scanplan.StageObservationEvent, target string) string {
	return sha256Hex([]byte(strings.Join([]string{event.EventID, event.AttemptID, string(event.Stage), target}, "\x00")))
}

func riskValidationPOCSetHash(config, target string) (string, bool) {
	var internal struct {
		ExecutionMode           string
		RiskValidationTargets   map[string][]string
		RiskValidationPocHashes map[string]string
	}
	if json.Unmarshal([]byte(config), &internal) != nil || !strings.EqualFold(strings.TrimSpace(internal.ExecutionMode), "risk_validation") {
		return "", false
	}
	pocs := append([]string(nil), internal.RiskValidationTargets[target]...)
	if len(pocs) == 0 {
		return "", false
	}
	sort.Strings(pocs)
	parts := make([]string, 0, len(pocs)*2)
	for _, poc := range pocs {
		poc = strings.TrimSpace(poc)
		hash := strings.ToLower(strings.TrimSpace(internal.RiskValidationPocHashes[poc]))
		if poc == "" || hash == "" {
			return "", false
		}
		parts = append(parts, poc, hash)
	}
	return sha256Hex([]byte(strings.Join(parts, "\x00"))), true
}

func latestEndpointContentHash(tx *gorm.DB, tenantID, projectID, networkZone, targetHash string) (string, bool) {
	var coverage ScanCoverage
	if err := tx.Where(
		"tenant_id = ? AND project_id = ? AND network_zone = ? AND target_hash = ? AND stage = ? AND status = ?",
		tenantID, projectID, networkZone, targetHash, string(scanplan.StageHTTPProbe), string(scanplan.CoverageComplete),
	).Order("finished_at DESC").First(&coverage).Error; err != nil {
		return "", false
	}
	var observation ScanObservation
	if err := tx.Select("content_hash").Where("id = ? AND tenant_id = ? AND project_id = ?", coverage.SourceObservationID, tenantID, projectID).First(&observation).Error; err != nil {
		return "", false
	}
	contentHash := strings.TrimSpace(observation.ContentHash)
	return contentHash, contentHash != ""
}
