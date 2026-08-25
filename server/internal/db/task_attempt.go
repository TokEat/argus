package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var errAttemptStateChanged = errors.New("attempt state changed")

const (
	AttemptTriggerInitial              = "initial"
	AttemptTriggerAutomaticRetry       = "automatic_retry"
	AttemptTriggerTimeoutRetry         = "timeout_retry"
	AttemptTriggerSplitRetry           = "split_retry"
	AttemptTriggerAgentOfflineRecovery = "agent_offline_recovery"
	AttemptTriggerSpotRecovery         = "spot_recovery"
	AttemptTriggerManualRetry          = "manual_retry"
	AttemptTriggerResume               = "resume"
)

type AttemptRetryOptions struct {
	Trigger              string
	TerminalStatus       string
	FailureReason        string
	ConsumeRetryBudget   bool
	UseCurrentTaskConfig bool
	PreserveRuleVersion  bool
	AllowTerminalRoot    bool
	AllowControlledBatch bool
	PreparedStatus       string
	PreparedControlState BatchControlState
}

func normalizeAttemptTrigger(trigger string) string {
	trigger = strings.TrimSpace(trigger)
	if trigger == "" {
		return AttemptTriggerAutomaticRetry
	}
	return trigger
}

func NormalizeAttemptFailureReason(reason string) string {
	reason = strings.TrimSpace(reason)
	const maxRunes = 2048
	runes := []rune(reason)
	if len(runes) > maxRunes {
		reason = string(runes[:maxRunes])
	}
	return reason
}

func taskTargetCount(raw string) int {
	var targets []string
	if json.Unmarshal([]byte(raw), &targets) == nil {
		return len(targets)
	}
	return 0
}

func nextTaskBatchSequence(tx *gorm.DB, tenantID, rootTaskID string) (int, error) {
	var next int
	err := tx.Model(&TaskBatch{}).
		Select("COALESCE(MAX(sequence), -1) + 1").
		Where("tenant_id = ? AND root_task_id = ?", tenantID, rootTaskID).
		Scan(&next).Error
	return next, err
}

func ensureTaskBatchForAttempt(tx *gorm.DB, current *SubTask, root RootTask) (TaskBatch, error) {
	if strings.TrimSpace(current.BatchID) == "" {
		current.BatchID = current.ID
	}
	if current.AttemptNo < 1 {
		current.AttemptNo = 1
	}
	if strings.TrimSpace(current.Trigger) == "" {
		current.Trigger = AttemptTriggerInitial
	}

	var batch TaskBatch
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND tenant_id = ?", current.BatchID, current.TenantID).
		First(&batch).Error
	if err == nil {
		return batch, nil
	}
	if err != gorm.ErrRecordNotFound {
		return TaskBatch{}, err
	}

	sequence, err := nextTaskBatchSequence(tx, current.TenantID, current.RootTaskID)
	if err != nil {
		return TaskBatch{}, err
	}
	batch = TaskBatch{
		ID:                 current.BatchID,
		TenantID:           current.TenantID,
		ProjectID:          current.ProjectID,
		RootTaskID:         current.RootTaskID,
		Sequence:           sequence,
		Kind:               "asset_scan",
		TargetType:         "legacy",
		Targets:            current.ChunkTargets,
		TargetCount:        taskTargetCount(current.ChunkTargets),
		Status:             current.Status,
		ConfigVersion:      max(current.ConfigVersion, 1),
		RuleVersion:        current.RuleVersion,
		Priority:           current.Priority,
		TimeoutSec:         current.TimeoutSec,
		AgentSelector:      current.AgentSelector,
		AgentSelectorRules: current.AgentSelectorRules,
		CurrentAttemptNo:   current.AttemptNo,
		AttemptCount:       current.AttemptNo,
		LatestAttemptID:    current.ID,
		CreatedBy:          root.UserID,
	}
	if err := tx.Create(&batch).Error; err != nil {
		return TaskBatch{}, err
	}
	if err := tx.Model(&SubTask{}).
		Where("id = ? AND tenant_id = ?", current.ID, current.TenantID).
		Updates(map[string]interface{}{
			"batch_id":   current.BatchID,
			"attempt_no": current.AttemptNo,
			"trigger":    current.Trigger,
		}).Error; err != nil {
		return TaskBatch{}, err
	}
	return batch, nil
}

func retrySelectorSnapshot(revision TaskConfigRevision, batch TaskBatch, current SubTask) (string, string) {
	selector := map[string]string{}
	_ = json.Unmarshal([]byte(revision.AgentSelector), &selector)
	if batch.TargetType != "" && batch.TargetType != "legacy" {
		if _, exists := selector["target_type"]; !exists {
			selector["target_type"] = batch.TargetType
		}
	}
	selectorJSON, err := json.Marshal(selector)
	if err != nil {
		selectorJSON = []byte(current.AgentSelector)
	}

	rules := ParseSelectorRulesJSON(revision.AgentSelectorRules)
	effectiveRules := MergeSelectorRules(selector, rules)
	return string(selectorJSON), SelectorRulesToJSON(effectiveRules)
}

// immutableDerivedExecutionConfig reports whether the attempt carries a
// derived validation-stage snapshot (risk or credential validation). These
// snapshots are immutable: recovery paths must re-dispatch them verbatim
// because replacing them with the Root's asset-discovery revision silently
// disables POC execution (NoPoc=true) and marks the stage DONE unreached.
func immutableDerivedExecutionConfig(config string) bool {
	var execution struct{ ExecutionMode string }
	if err := json.Unmarshal([]byte(config), &execution); err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(execution.ExecutionMode)) {
	case "risk_validation", "credential_validation":
		return true
	}
	return false
}

func applyCurrentTaskConfig(tx *gorm.DB, attempt *SubTask, batch TaskBatch, root RootTask) {
	if root.ID == "" || root.CurrentConfigVersion < 1 {
		return
	}
	var revision TaskConfigRevision
	if err := tx.Where("tenant_id = ? AND root_task_id = ? AND version = ?", root.TenantID, root.ID, root.CurrentConfigVersion).
		First(&revision).Error; err != nil {
		return
	}
	attempt.Config = revision.Config
	attempt.ConfigVersion = revision.Version
	attempt.Priority = revision.Priority
	attempt.TimeoutSec = revision.TimeoutSec
	attempt.AgentSelector, attempt.AgentSelectorRules = retrySelectorSnapshot(revision, batch, *attempt)
}

func currentAttemptRuleVersion(tx *gorm.DB, fallback string) string {
	var cfg SystemConfig
	if err := tx.Where("key = ?", "rule_version").First(&cfg).Error; err == nil && strings.TrimSpace(cfg.Value) != "" {
		return cfg.Value
	}
	return fallback
}

// AppendSubTaskAttempt terminalizes the current execution when requested and
// atomically appends a new Attempt under the same stable TaskBatch. The old
// row retains its Agent, timing, config/rule snapshot and failure evidence.
func AppendSubTaskAttempt(expected *SubTask, options AttemptRetryOptions) (prepared SubTask, ok bool) {
	if DB == nil || expected == nil || strings.TrimSpace(expected.ID) == "" {
		return SubTask{}, false
	}

	err := DB.Transaction(func(tx *gorm.DB) error {
		var err error
		prepared, ok, err = AppendSubTaskAttemptTx(tx, expected, options)
		return err
	})
	if err != nil {
		if !errors.Is(err, errAttemptStateChanged) {
			log.Printf("[Attempt] Failed to append retry after %s: %v", expected.ID, err)
		}
		return SubTask{}, false
	}
	if ok {
		*expected = prepared
	}
	return prepared, ok
}

// AppendSubTaskAttemptTx is the transaction-aware form used by audited API
// mutations. Callers own the surrounding transaction and may append their
// audit row before committing the newly created Attempt.
func AppendSubTaskAttemptTx(tx *gorm.DB, expected *SubTask, options AttemptRetryOptions) (prepared SubTask, ok bool, err error) {
	if tx == nil || expected == nil || strings.TrimSpace(expected.ID) == "" {
		return SubTask{}, false, nil
	}

	current, allowed, err := lockRetryableSubTask(tx, expected, options.AllowTerminalRoot, options.AllowControlledBatch)
	if err != nil {
		return SubTask{}, false, err
	}
	if !allowed {
		return SubTask{}, false, nil
	}
	if options.ConsumeRetryBudget && current.RetryCount >= current.MaxRetry {
		return SubTask{}, false, nil
	}

	var root RootTask
	if current.RootTaskID != "" {
		if err := tx.Where("id = ? AND tenant_id = ?", current.RootTaskID, current.TenantID).First(&root).Error; err != nil {
			return SubTask{}, false, err
		}
	}
	batch, err := ensureTaskBatchForAttempt(tx, &current, root)
	if err != nil {
		return SubTask{}, false, err
	}
	if batch.LatestAttemptID != "" && batch.LatestAttemptID != current.ID {
		return SubTask{}, false, nil
	}

	now := time.Now()
	terminalStatus := strings.TrimSpace(options.TerminalStatus)
	failureReason := NormalizeAttemptFailureReason(options.FailureReason)
	oldUpdates := map[string]interface{}{
		"batch_id":      current.BatchID,
		"attempt_no":    current.AttemptNo,
		"trigger":       current.Trigger,
		"stream_msg_id": "",
	}
	if terminalStatus != "" {
		oldUpdates["status"] = terminalStatus
		current.Status = terminalStatus
	}
	if CanonicalAttemptState(current.Status) == AttemptStateCompleted ||
		CanonicalAttemptState(current.Status) == AttemptStateFailed ||
		CanonicalAttemptState(current.Status) == AttemptStateTimeout ||
		CanonicalAttemptState(current.Status) == AttemptStateStopped {
		if current.FinishedAt == nil {
			oldUpdates["finished_at"] = now
			current.FinishedAt = &now
		}
	}
	if failureReason != "" {
		oldUpdates["failure_reason"] = failureReason
		current.FailureReason = failureReason
	}
	update := tx.Model(&SubTask{}).
		Where("id = ? AND tenant_id = ? AND status = ?", current.ID, current.TenantID, expected.Status).
		Updates(oldUpdates)
	if update.Error != nil {
		return SubTask{}, false, update.Error
	}
	if update.RowsAffected != 1 {
		return SubTask{}, false, nil
	}

	nextAttemptNo := max(max(batch.CurrentAttemptNo, current.AttemptNo), 1) + 1
	nextRetryCount := current.RetryCount
	if options.ConsumeRetryBudget {
		nextRetryCount++
	}
	prepared = current
	prepared.ID = fmt.Sprintf("%s-attempt-%d", batch.ID, nextAttemptNo)
	prepared.BatchID = batch.ID
	prepared.AttemptNo = nextAttemptNo
	prepared.ParentAttemptID = current.ID
	prepared.Trigger = normalizeAttemptTrigger(options.Trigger)
	preparedStatus := strings.TrimSpace(options.PreparedStatus)
	if preparedStatus == "" {
		preparedStatus = "Dispatching"
	}
	prepared.Status = preparedStatus
	prepared.AgentID = ""
	prepared.StreamMsgID = ""
	prepared.FailureReason = ""
	prepared.RetryCount = nextRetryCount
	prepared.StartedAt = nil
	prepared.FinishedAt = nil
	prepared.CreatedAt = time.Time{}
	prepared.UpdatedAt = time.Time{}
	if options.UseCurrentTaskConfig && !immutableDerivedExecutionConfig(current.Config) {
		applyCurrentTaskConfig(tx, &prepared, batch, root)
	}
	if !options.PreserveRuleVersion && !immutableDerivedExecutionConfig(current.Config) {
		prepared.RuleVersion = currentAttemptRuleVersion(tx, prepared.RuleVersion)
	}
	if err := tx.Create(&prepared).Error; err != nil {
		return SubTask{}, false, err
	}
	controlState := options.PreparedControlState
	if controlState == "" {
		controlState = BatchControlActive
	}

	batchUpdate := tx.Model(&TaskBatch{}).
		Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", batch.ID, batch.TenantID, current.ID).
		Updates(map[string]interface{}{
			"status":             preparedStatus,
			"control_state":      controlState,
			"current_attempt_no": nextAttemptNo,
			"attempt_count":      gorm.Expr("attempt_count + 1"),
			"latest_attempt_id":  prepared.ID,
		})
	if batchUpdate.Error != nil {
		return SubTask{}, false, batchUpdate.Error
	}
	if batchUpdate.RowsAffected != 1 {
		return SubTask{}, false, errAttemptStateChanged
	}
	return prepared, true, nil
}

// SettlePausedTaskBatchAttempt terminalizes a claimed Attempt when recovery
// cannot append new work because the operator paused its stable batch. The
// pause intent remains intact so a later resume can append a new Attempt.
func SettlePausedTaskBatchAttempt(expected *SubTask, terminalStatus, failureReason string) bool {
	if DB == nil || expected == nil || strings.TrimSpace(expected.ID) == "" || !IsTerminalAttemptStatus(terminalStatus) {
		return false
	}
	settled := false
	err := DB.Transaction(func(tx *gorm.DB) error {
		if strings.TrimSpace(expected.BatchID) == "" {
			return nil
		}
		var batch TaskBatch
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ? AND latest_attempt_id = ? AND archived_at IS NULL", expected.BatchID, expected.TenantID, expected.ID).
			First(&batch).Error; err != nil {
			return err
		}
		if CanonicalBatchControlState(batch.ControlState) != BatchControlPaused {
			return nil
		}
		var current SubTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", expected.ID, expected.TenantID).
			First(&current).Error; err != nil {
			return err
		}
		if NormalizeSubTaskStatus(current.Status) != NormalizeSubTaskStatus(expected.Status) || current.BatchID != batch.ID {
			return nil
		}
		now := time.Now()
		update := tx.Model(&SubTask{}).
			Where("id = ? AND tenant_id = ? AND status = ?", current.ID, current.TenantID, current.Status).
			Updates(map[string]interface{}{
				"status": terminalStatus, "stream_msg_id": "",
				"failure_reason": NormalizeAttemptFailureReason(failureReason), "finished_at": now,
			})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return nil
		}
		batchUpdate := tx.Model(&TaskBatch{}).
			Where("id = ? AND tenant_id = ? AND latest_attempt_id = ? AND control_state = ?", batch.ID, batch.TenantID, current.ID, BatchControlPaused).
			Update("status", terminalStatus)
		if batchUpdate.Error != nil {
			return batchUpdate.Error
		}
		if batchUpdate.RowsAffected != 1 {
			return errAttemptStateChanged
		}
		settled = true
		return nil
	})
	if err != nil && !errors.Is(err, errAttemptStateChanged) {
		log.Printf("[Attempt] Failed to settle paused attempt %s: %v", expected.ID, err)
	}
	return settled
}

// IsImmutableDerivedExecutionConfig exposes the immutability check to recovery
// paths outside this package: derived validation snapshots must never be
// binary-split (RiskValidationTargets stays global, so each half would reject
// the other half's targets during coverage validation).
func IsImmutableDerivedExecutionConfig(config string) bool {
	return immutableDerivedExecutionConfig(config)
}
