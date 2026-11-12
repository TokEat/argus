package db

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type subTaskStatusCounter struct {
	Status string
	Cnt    int64
}

// RefreshRootTaskStatus 聚合子任务状态并刷新 RootTask 状态、completed_chunks 与 completed_targets。
func RefreshRootTaskStatus(rootTaskID string) {
	refreshRootTaskStatus(rootTaskID, 0)
}

func refreshRootTaskStatus(rootTaskID string, attempt int) {
	if DB == nil || strings.TrimSpace(rootTaskID) == "" {
		return
	}
	const maxCASAttempts = 5
	if attempt >= maxCASAttempts {
		log.Printf("[TaskLifecycle] Root task %s status refresh did not converge after %d CAS attempts", rootTaskID, maxCASAttempts)
		return
	}

	var root RootTask
	if err := DB.Select("id", "tenant_id", "status").Where("id = ?", rootTaskID).First(&root).Error; err != nil {
		return
	}
	currentPaused := CanonicalTaskState(root.Status) == TaskStatePaused
	currentStopping := CanonicalTaskState(root.Status) == TaskStateStopping
	currentCancelled := CanonicalTaskState(root.Status) == TaskStateStopped
	if currentCancelled {
		return
	}

	var counters []subTaskStatusCounter
	batchBacked := true
	if err := DB.Table("task_batches AS tb").
		Select("st.status AS status, count(*) AS cnt").
		Joins("JOIN sub_tasks AS st ON st.id = tb.latest_attempt_id AND st.tenant_id = tb.tenant_id").
		Where("tb.root_task_id = ? AND tb.tenant_id = ? AND tb.archived_at IS NULL", rootTaskID, root.TenantID).
		Group("st.status").
		Scan(&counters).Error; err != nil {
		batchBacked = false
		counters = nil
		DB.Model(&SubTask{}).
			Select("status, count(*) as cnt").
			Where("root_task_id = ? AND tenant_id = ?", rootTaskID, root.TenantID).
			Group("status").
			Scan(&counters)
	} else if len(counters) == 0 {
		var batchCount int64
		if countErr := DB.Model(&TaskBatch{}).
			Where("root_task_id = ? AND tenant_id = ?", rootTaskID, root.TenantID).
			Count(&batchCount).Error; countErr != nil || batchCount == 0 {
			batchBacked = false
			DB.Model(&SubTask{}).
				Select("status, count(*) as cnt").
				Where("root_task_id = ? AND tenant_id = ?", rootTaskID, root.TenantID).
				Group("status").
				Scan(&counters)
		}
	}

	total := int64(0)
	done := int64(0)
	active := int64(0)
	timeout := int64(0)
	failed := int64(0)
	cancelled := int64(0)
	paused := int64(0)

	for _, c := range counters {
		total += c.Cnt
		switch CanonicalAttemptState(c.Status) {
		case AttemptStateCompleted:
			done += c.Cnt
		case AttemptStateQueued, AttemptStateRunning, AttemptStateStopping, AttemptStateRecovered, AttemptStateDispatching:
			active += c.Cnt
		case AttemptStatePaused:
			paused += c.Cnt
			active += c.Cnt
		case AttemptStateTimeout:
			timeout += c.Cnt
		case AttemptStateFailed:
			failed += c.Cnt
		case AttemptStateStopped:
			cancelled += c.Cnt
		}
	}
	semanticTask := false
	semanticPending := false
	var pendingIntents int64
	if err := DB.Model(&ScanPolicyIntent{}).Where("tenant_id = ? AND root_task_id = ?", root.TenantID, rootTaskID).Count(&pendingIntents).Error; err == nil && pendingIntents > 0 {
		semanticTask = true
		var pendingStages int64
		DB.Model(&ScanPolicyIntent{}).Where("tenant_id = ? AND root_task_id = ? AND (risk_status = ? OR credential_status = ?)", root.TenantID, rootTaskID, ScanStageIntentPending, ScanStageIntentPending).Count(&pendingStages)
		if pendingStages > 0 {
			semanticPending = true
		}
	}

	if total == 0 && batchBacked {
		DB.Model(&RootTask{}).
			Where("id = ? AND tenant_id = ?", rootTaskID, root.TenantID).
			Updates(map[string]interface{}{
				"total_chunks":      0,
				"completed_chunks":  0,
				"total_targets":     0,
				"completed_targets": 0,
			})
		return
	}
	if total == 0 {
		return
	}
	nextStatus := "Running"
	switch {
	case currentStopping && active > 0:
		nextStatus = root.Status
	case currentPaused && done < total:
		nextStatus = root.Status
	case semanticPending:
		nextStatus = "Running"
	case semanticTask && active > 0:
		nextStatus = "Running"
	case active > 0:
		if done > 0 {
			nextStatus = "PartialDone"
		} else {
			nextStatus = "Running"
		}
	case semanticTask && done > 0 && (timeout > 0 || failed > 0 || cancelled > 0):
		nextStatus = "PartialDone"
	case timeout > 0:
		nextStatus = "Timeout"
	case failed > 0:
		nextStatus = "Failed"
	case cancelled > 0:
		nextStatus = "Cancelled"
	case done == total:
		nextStatus = "FINISHED"
	default:
		nextStatus = "Queued"
	}

	// 计算已完成目标数。新模型只聚合每个稳定批次的最新 Attempt，
	// 避免历史失败尝试污染最终任务状态和进度。
	var completedTargets int64
	var totalTargets int64
	var doneChunks []SubTask
	if batchBacked {
		DB.Model(&TaskBatch{}).
			Select("COALESCE(SUM(target_count), 0)").
			Where("root_task_id = ? AND tenant_id = ? AND archived_at IS NULL", rootTaskID, root.TenantID).
			Scan(&totalTargets)
		DB.Table("task_batches AS tb").
			Select("tb.targets AS chunk_targets").
			Joins("JOIN sub_tasks AS st ON st.id = tb.latest_attempt_id AND st.tenant_id = tb.tenant_id").
			Where("tb.root_task_id = ? AND tb.tenant_id = ? AND tb.archived_at IS NULL AND UPPER(st.status) IN ?", rootTaskID, root.TenantID, []string{"DONE", "FINISHED", "COMPLETED", "SUCCESS", "SUCCEEDED"}).
			Scan(&doneChunks)
	} else {
		DB.Select("chunk_targets").
			Where("root_task_id = ? AND tenant_id = ? AND UPPER(status) IN ?", rootTaskID, root.TenantID, []string{"DONE", "FINISHED", "COMPLETED", "SUCCESS", "SUCCEEDED"}).
			Find(&doneChunks)
	}
	for _, chunk := range doneChunks {
		var targets []string
		if err := json.Unmarshal([]byte(chunk.ChunkTargets), &targets); err != nil {
			continue
		}
		completedTargets += int64(len(targets))
	}

	rootUpdates := map[string]interface{}{
		"status":            nextStatus,
		"total_chunks":      total,
		"completed_chunks":  done,
		"completed_targets": completedTargets,
	}
	if batchBacked {
		rootUpdates["total_targets"] = totalTargets
	}
	result := DB.Model(&RootTask{}).
		Where("id = ? AND tenant_id = ? AND status = ?", rootTaskID, root.TenantID, root.Status).
		Updates(rootUpdates)
	if result.Error != nil {
		log.Printf("[TaskLifecycle] Failed to refresh root task %s: %v", rootTaskID, result.Error)
		return
	}
	if result.RowsAffected == 0 {
		refreshRootTaskStatus(rootTaskID, attempt+1)
	}
}

// ============================================================================
// 失败批次二分拆分重试
//
// 对 FAILED/TIMEOUT 且 len(chunk_targets)>1 且仍有重试预算的 SubTask：
//   - 原 SubTask 改写为第一半目标并回到 Dispatching
//   - 新建兄弟 SubTask 承载第二半目标
//   - RootTask.total_chunks += 1
//   - 返回两个需要重新入队的 SubTask
//
// 单目标失败仍走现有重试/终态逻辑，避免无限拆分。
// ============================================================================

func lockRetryableSubTask(tx *gorm.DB, expected *SubTask, allowTerminalRoot, allowControlledBatch bool) (SubTask, bool, error) {
	var root RootTask
	if strings.TrimSpace(expected.RootTaskID) != "" {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id", "tenant_id", "status").
			Where("id = ? AND tenant_id = ?", expected.RootTaskID, expected.TenantID).
			First(&root).Error; err != nil {
			return SubTask{}, false, err
		}
	}
	var batch TaskBatch
	if strings.TrimSpace(expected.BatchID) != "" {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id", "tenant_id", "root_task_id", "control_state", "archived_at").
			Where("id = ? AND tenant_id = ?", expected.BatchID, expected.TenantID).
			First(&batch).Error; err != nil && err != gorm.ErrRecordNotFound {
			return SubTask{}, false, err
		} else if err == nil {
			if batch.ArchivedAt != nil || (batch.RootTaskID != "" && expected.RootTaskID != "" && batch.RootTaskID != expected.RootTaskID) {
				return SubTask{}, false, nil
			}
			controlState := CanonicalBatchControlState(batch.ControlState)
			if controlState != BatchControlActive && !allowControlledBatch {
				return SubTask{}, false, nil
			}
		}
	}

	var current SubTask
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND tenant_id = ?", expected.ID, expected.TenantID).
		First(&current).Error; err != nil {
		return current, false, err
	}
	if NormalizeSubTaskStatus(current.Status) != NormalizeSubTaskStatus(expected.Status) {
		return current, false, nil
	}
	if expected.RootTaskID != "" && current.RootTaskID != expected.RootTaskID {
		return current, false, nil
	}
	if expected.BatchID != "" && current.BatchID != expected.BatchID {
		return current, false, nil
	}
	if current.RootTaskID == "" {
		return current, true, nil
	}
	if root.ID == "" {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id", "tenant_id", "status").
			Where("id = ? AND tenant_id = ?", current.RootTaskID, current.TenantID).
			First(&root).Error; err != nil {
			return current, false, err
		}
	}
	if CanRetryTaskStatus(root.Status) {
		return current, true, nil
	}
	if allowTerminalRoot && (IsTerminalTaskStatus(root.Status) || CanonicalTaskState(root.Status) == TaskStatePaused) {
		return current, true, nil
	}
	return current, false, nil
}

// PrepareSubTaskRetry preserves the terminal execution row and appends a new
// Attempt under the same stable TaskBatch.
func PrepareSubTaskRetry(sub *SubTask) (prepared SubTask, ok bool) {
	options := AttemptRetryOptions{
		Trigger:              AttemptTriggerAutomaticRetry,
		ConsumeRetryBudget:   true,
		UseCurrentTaskConfig: true,
	}
	// Validation batches (risk/credential) must inherit their sealed attempt
	// config (ExecutionMode, ValidationBudget*, NoPoc=false). Rebuilding from the
	// root asset-scan config would silently disable POC execution and report a
	// false-success DONE with zero findings.
	if validationBatchKind(sub) {
		options.UseCurrentTaskConfig = false
		options.PreserveRuleVersion = true
	}
	return AppendSubTaskAttempt(sub, options)
}

// validationBatchKind reports whether the SubTask's batch is a risk/credential
// validation batch. TaskBatch.ID is the sole primary key, so it is queried
// directly (robust to an empty TenantID on the inbound SubTask).
func validationBatchKind(sub *SubTask) bool {
	if DB == nil || sub == nil || strings.TrimSpace(sub.BatchID) == "" {
		return false
	}
	var batch TaskBatch
	if err := DB.Select("kind").Where("id = ?", sub.BatchID).First(&batch).Error; err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(batch.Kind)) {
	case "risk_validation", "credential_validation":
		return true
	}
	return false
}

// SplitFailedSubTask preserves the failed Attempt, appends a retry Attempt for
// the first target half, and creates a sibling TaskBatch/Attempt for the second.
// resetRetryBudget is reserved for the timeout daemon's last-resort split.
func SplitFailedSubTask(sub *SubTask, resetRetryBudget bool) (split []SubTask, didSplit, retryAllowed bool) {
	if DB == nil || sub == nil || strings.TrimSpace(sub.ID) == "" {
		return nil, false, false
	}

	var firstAttempt SubTask
	var siblingAttempt SubTask
	err := DB.Transaction(func(tx *gorm.DB) error {
		current, allowed, err := lockRetryableSubTask(tx, sub, false, false)
		if err != nil {
			return err
		}
		if !allowed {
			return nil
		}
		retryAllowed = true

		var targets []string
		if err := json.Unmarshal([]byte(current.ChunkTargets), &targets); err != nil {
			log.Printf("[SplitRetry] Failed to parse ChunkTargets for subtask %s: %v", current.ID, err)
			return nil
		}
		retryCount := current.RetryCount
		if resetRetryBudget {
			retryCount = 0
		}
		if len(targets) <= 1 || retryCount >= current.MaxRetry {
			return nil
		}

		mid := len(targets) / 2
		firstJSON, _ := json.Marshal(targets[:mid])
		secondJSON, _ := json.Marshal(targets[mid:])

		var root RootTask
		if current.RootTaskID != "" {
			if err := tx.Where("id = ? AND tenant_id = ?", current.RootTaskID, current.TenantID).First(&root).Error; err != nil {
				return err
			}
		}
		currentBatch, err := ensureTaskBatchForAttempt(tx, &current, root)
		if err != nil {
			return err
		}
		if currentBatch.LatestAttemptID != "" && currentBatch.LatestAttemptID != current.ID {
			retryAllowed = false
			return nil
		}

		now := time.Now()
		terminalStatus := current.Status
		switch CanonicalAttemptState(current.Status) {
		case AttemptStateQueued, AttemptStateDispatching, AttemptStateRecovered, AttemptStateRunning, AttemptStateStopping, AttemptStatePaused:
			if resetRetryBudget {
				terminalStatus = "Timeout"
			} else {
				terminalStatus = "Failed"
			}
		}
		failureReason := NormalizeAttemptFailureReason(current.FailureReason)
		if failureReason == "" {
			if CanonicalAttemptState(terminalStatus) == AttemptStateTimeout {
				failureReason = "attempt timed out before split retry"
			} else {
				failureReason = "attempt failed before split retry"
			}
		}
		oldUpdate := tx.Model(&SubTask{}).
			Where("id = ? AND tenant_id = ? AND status = ?", current.ID, current.TenantID, sub.Status).
			Updates(map[string]interface{}{
				"batch_id":       current.BatchID,
				"attempt_no":     current.AttemptNo,
				"trigger":        current.Trigger,
				"status":         terminalStatus,
				"failure_reason": failureReason,
				"finished_at":    now,
				"stream_msg_id":  "",
			})
		if oldUpdate.Error != nil {
			return oldUpdate.Error
		}
		if oldUpdate.RowsAffected != 1 {
			retryAllowed = false
			return nil
		}

		splitStamp := time.Now().UnixNano()
		siblingBatchID := fmt.Sprintf("%s-split-%d", currentBatch.ID, splitStamp)
		siblingAttemptID := fmt.Sprintf("%s-attempt-1", siblingBatchID)
		nextAttemptNo := max(max(currentBatch.CurrentAttemptNo, current.AttemptNo), 1) + 1
		firstAttempt = current
		firstAttempt.ID = fmt.Sprintf("%s-attempt-%d", currentBatch.ID, nextAttemptNo)
		firstAttempt.BatchID = currentBatch.ID
		firstAttempt.AttemptNo = nextAttemptNo
		firstAttempt.ParentAttemptID = current.ID
		firstAttempt.Trigger = AttemptTriggerSplitRetry
		firstAttempt.ChunkTargets = string(firstJSON)
		firstAttempt.Status = "Dispatching"
		firstAttempt.AgentID = ""
		firstAttempt.StreamMsgID = ""
		// Fresh split attempts start unrouted; the dispatch controller assigns a
		// new routing. Both halves inherit the parent's dispatch strategy and are
		// held for one backoff step based on their incremented retry count.
		firstAttempt.RoutedAgentID = ""
		firstAttempt.RoutedAt = nil
		eligibleAt := RetryEligibleAt(retryCount+1, now)
		firstAttempt.NextEligibleAt = &eligibleAt
		firstAttempt.FailureReason = ""
		firstAttempt.RetryCount = retryCount + 1
		firstAttempt.StartedAt = nil
		firstAttempt.FinishedAt = nil
		firstAttempt.CreatedAt = time.Time{}
		firstAttempt.UpdatedAt = time.Time{}
		// Derived validation snapshots are immutable: keep the attempt's own
		// stage config and pinned rule version instead of the Root's current
		// asset-discovery revision, which would silently disable POC execution.
		if !immutableDerivedExecutionConfig(current.Config) {
			applyCurrentTaskConfig(tx, &firstAttempt, currentBatch, root)
			firstAttempt.RuleVersion = currentAttemptRuleVersion(tx, firstAttempt.RuleVersion)
		}

		siblingAttempt = firstAttempt
		siblingAttempt.ID = siblingAttemptID
		siblingAttempt.BatchID = siblingBatchID
		siblingAttempt.AttemptNo = 1
		siblingAttempt.ChunkTargets = string(secondJSON)
		siblingBatch := TaskBatch{
			ID: siblingBatchID, TenantID: current.TenantID, ProjectID: current.ProjectID, RootTaskID: current.RootTaskID,
			Sequence: root.TotalChunks, Kind: currentBatch.Kind, TargetType: currentBatch.TargetType,
			Targets: string(secondJSON), TargetCount: len(targets[mid:]), Status: "Dispatching",
			ConfigVersion: siblingAttempt.ConfigVersion, RuleVersion: siblingAttempt.RuleVersion, Priority: siblingAttempt.Priority,
			TimeoutSec: siblingAttempt.TimeoutSec, AgentSelector: siblingAttempt.AgentSelector, AgentSelectorRules: siblingAttempt.AgentSelectorRules,
			CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: siblingAttemptID, CreatedBy: root.UserID,
		}
		if err := tx.Create(&firstAttempt).Error; err != nil {
			return err
		}
		if err := tx.Create(&siblingBatch).Error; err != nil {
			return err
		}
		if err := tx.Create(&siblingAttempt).Error; err != nil {
			return err
		}
		batchUpdate := tx.Model(&TaskBatch{}).
			Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", currentBatch.ID, currentBatch.TenantID, current.ID).
			Updates(map[string]interface{}{
				"targets":            string(firstJSON),
				"target_count":       len(targets[:mid]),
				"status":             "Dispatching",
				"current_attempt_no": nextAttemptNo,
				"attempt_count":      gorm.Expr("attempt_count + 1"),
				"latest_attempt_id":  firstAttempt.ID,
			})
		if batchUpdate.Error != nil {
			return batchUpdate.Error
		}
		if batchUpdate.RowsAffected != 1 {
			return errAttemptStateChanged
		}
		if current.RootTaskID != "" {
			rootUpdate := tx.Model(&RootTask{}).
				Where("id = ? AND tenant_id = ?", current.RootTaskID, current.TenantID).
				UpdateColumn("total_chunks", gorm.Expr("total_chunks + 1"))
			if rootUpdate.Error != nil {
				return rootUpdate.Error
			}
			if rootUpdate.RowsAffected != 1 {
				return fmt.Errorf("root task %s not found for tenant %s", current.RootTaskID, current.TenantID)
			}
		}

		didSplit = true
		return nil
	})
	if err != nil {
		log.Printf("[SplitRetry] Failed to split subtask %s: %v", sub.ID, err)
		return nil, false, false
	}
	if !didSplit {
		return nil, false, retryAllowed
	}

	*sub = firstAttempt
	log.Printf("[SplitRetry] SubTask %s split into 2 batches (retry %d/%d)", sub.ID, sub.RetryCount, sub.MaxRetry)
	return []SubTask{firstAttempt, siblingAttempt}, true, true
}
