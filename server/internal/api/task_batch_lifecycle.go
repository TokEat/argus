package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type taskBatchSummary struct {
	ID               string     `json:"id"`
	Sequence         int        `json:"sequence"`
	Kind             string     `json:"kind"`
	TargetType       string     `json:"target_type"`
	TargetCount      int        `json:"target_count"`
	Status           string     `json:"status"`
	DisplayStatus    string     `json:"display_status"`
	ControlState     string     `json:"control_state"`
	ConfigVersion    int        `json:"config_version"`
	RuleVersion      string     `json:"rule_version"`
	Priority         int        `json:"priority"`
	TimeoutSec       int        `json:"timeout_sec"`
	CurrentAttemptNo int        `json:"current_attempt_no"`
	AttemptCount     int        `json:"attempt_count"`
	LatestAttemptID  string     `json:"latest_attempt_id"`
	AgentID          string     `json:"agent_id"`
	FailureReason    string     `json:"failure_reason"`
	RetryCount       int        `json:"retry_count"`
	MaxRetry         int        `json:"max_retry"`
	StartedAt        *time.Time `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	ArchivedAt       *time.Time `json:"archived_at"`
}

func batchDisplayStatus(batch db.TaskBatch) string {
	switch db.CanonicalBatchControlState(batch.ControlState) {
	case db.BatchControlPaused:
		return "Paused"
	case db.BatchControlStopping:
		return "CancelPending"
	case db.BatchControlStopped:
		return "Cancelled"
	default:
		return batch.Status
	}
}

func buildTaskBatchSummaries(batches []db.TaskBatch, attempts map[string]db.SubTask) []taskBatchSummary {
	items := make([]taskBatchSummary, 0, len(batches))
	for _, batch := range batches {
		attempt := attempts[batch.LatestAttemptID]
		items = append(items, taskBatchSummary{
			ID: batch.ID, Sequence: batch.Sequence, Kind: batch.Kind, TargetType: batch.TargetType,
			TargetCount: batch.TargetCount, Status: batch.Status, DisplayStatus: batchDisplayStatus(batch),
			ControlState: string(db.CanonicalBatchControlState(batch.ControlState)), ConfigVersion: batch.ConfigVersion,
			RuleVersion: batch.RuleVersion, Priority: batch.Priority, TimeoutSec: batch.TimeoutSec,
			CurrentAttemptNo: batch.CurrentAttemptNo, AttemptCount: batch.AttemptCount, LatestAttemptID: batch.LatestAttemptID,
			AgentID: attempt.AgentID, FailureReason: attempt.FailureReason, RetryCount: attempt.RetryCount,
			MaxRetry: attempt.MaxRetry, StartedAt: attempt.StartedAt, FinishedAt: attempt.FinishedAt,
			CreatedAt: batch.CreatedAt, UpdatedAt: batch.UpdatedAt, ArchivedAt: batch.ArchivedAt,
		})
	}
	return items
}

func listTaskBatches(c *gin.Context) {
	root, ok := requireTaskAccess(c)
	if !ok {
		return
	}
	query := db.DB.Where("root_task_id = ? AND tenant_id = ?", root.ID, root.TenantID)
	switch strings.ToLower(strings.TrimSpace(c.Query("archived"))) {
	case "only":
		query = query.Where("archived_at IS NOT NULL")
	case "include":
	default:
		query = query.Where("archived_at IS NULL")
	}
	var batches []db.TaskBatch
	if err := query.Order("sequence asc").Find(&batches).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	attemptIDs := make([]string, 0, len(batches))
	for _, batch := range batches {
		if batch.LatestAttemptID != "" {
			attemptIDs = append(attemptIDs, batch.LatestAttemptID)
		}
	}
	attemptsByID := make(map[string]db.SubTask, len(attemptIDs))
	if len(attemptIDs) > 0 {
		var attempts []db.SubTask
		if err := db.DB.Where("tenant_id = ? AND root_task_id = ? AND id IN ?", root.TenantID, root.ID, attemptIDs).Find(&attempts).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, attempt := range attempts {
			attemptsByID[attempt.ID] = attempt
		}
	}
	c.JSON(http.StatusOK, gin.H{"task_id": root.ID, "items": buildTaskBatchSummaries(batches, attemptsByID)})
}

func requireTaskAccess(c *gin.Context) (db.RootTask, bool) {
	var root db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", strings.TrimSpace(c.Param("id")), currentTenantID(c)).First(&root).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return root, false
	}
	if !canAccessProject(c, root.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return root, false
	}
	return root, true
}

var (
	errBatchStateChanged  = errors.New("batch state changed during operation")
	errBatchNotPausable   = errors.New("batch is not in a pausable state")
	errBatchNotResumable  = errors.New("batch is not paused")
	errBatchNotStoppable  = errors.New("batch is not in a stoppable state")
	errBatchNotRetryable  = errors.New("batch must reach a terminal state before retry")
	errBatchNotArchivable = errors.New("batch must reach a terminal state before it can be archived")
	errTaskBlocksBatch    = errors.New("task lifecycle currently blocks this batch operation")
	errRiskBatchRuleDrift = errors.New("risk validation rules changed; generate and confirm a new preview")
)

func recordBatchAudit(tx *gorm.DB, task db.RootTask, batch db.TaskBatch, attemptID, action, beforeStatus, afterStatus, operatorID string, details map[string]interface{}) error {
	payload := "{}"
	if len(details) > 0 {
		encoded, err := json.Marshal(details)
		if err != nil {
			return err
		}
		payload = string(encoded)
	}
	return tx.Create(&db.TaskAudit{
		TenantID: task.TenantID, ProjectID: task.ProjectID, RootTaskID: task.ID,
		BatchID: batch.ID, AttemptID: attemptID, OperatorID: operatorID,
		Action: action, BeforeStatus: beforeStatus, AfterStatus: afterStatus, Details: payload,
	}).Error
}

func writeBatchMutationError(c *gin.Context, err error) bool {
	for _, candidate := range []error{
		errBatchStateChanged, errBatchNotPausable, errBatchNotResumable,
		errBatchNotStoppable, errBatchNotRetryable, errBatchNotArchivable,
		errTaskBlocksBatch,
		errRiskBatchRuleDrift,
	} {
		if errors.Is(err, candidate) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return true
		}
	}
	return false
}

func requireTaskBatchAccess(c *gin.Context) (db.RootTask, db.TaskBatch, bool) {
	tenantID := currentTenantID(c)
	taskID := strings.TrimSpace(c.Param("id"))
	batchID := strings.TrimSpace(c.Param("batch_id"))
	var root db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", taskID, tenantID).First(&root).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return root, db.TaskBatch{}, false
	}
	if !canAccessProject(c, root.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return root, db.TaskBatch{}, false
	}
	var batch db.TaskBatch
	if err := db.DB.Where("id = ? AND root_task_id = ? AND tenant_id = ?", batchID, taskID, tenantID).First(&batch).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Batch not found"})
		return root, batch, false
	}
	return root, batch, true
}

func lockTaskBatchMutation(tx *gorm.DB, tenantID, taskID, batchID string) (db.RootTask, db.TaskBatch, db.SubTask, error) {
	var root db.RootTask
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND tenant_id = ?", taskID, tenantID).First(&root).Error; err != nil {
		return root, db.TaskBatch{}, db.SubTask{}, err
	}
	var batch db.TaskBatch
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND root_task_id = ? AND tenant_id = ?", batchID, taskID, tenantID).
		First(&batch).Error; err != nil {
		return root, batch, db.SubTask{}, err
	}
	var attempt db.SubTask
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND batch_id = ? AND root_task_id = ? AND tenant_id = ?", batch.LatestAttemptID, batch.ID, root.ID, tenantID).
		First(&attempt).Error; err != nil {
		return root, batch, attempt, err
	}
	return root, batch, attempt, nil
}

func taskAllowsBatchDispatch(root db.RootTask) bool {
	if root.ArchivedAt != nil {
		return false
	}
	switch db.CanonicalTaskState(root.Status) {
	case db.TaskStatePaused, db.TaskStatePausing, db.TaskStateStopping, db.TaskStateCreated, db.TaskStateUnknown:
		return false
	default:
		return true
	}
}

func pauseTaskBatch(c *gin.Context) {
	root, batch, ok := requireTaskBatchAccess(c)
	if !ok {
		return
	}
	if root.ArchivedAt != nil || batch.ArchivedAt != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archived task or batch cannot be paused"})
		return
	}

	pausedWithoutClaim := false
	runningContinues := false
	alreadyPaused := false
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		currentRoot, currentBatch, attempt, err := lockTaskBatchMutation(tx, root.TenantID, root.ID, batch.ID)
		if err != nil {
			return err
		}
		if currentRoot.ArchivedAt != nil || currentBatch.ArchivedAt != nil {
			return errBatchNotPausable
		}
		if db.CanonicalBatchControlState(currentBatch.ControlState) == db.BatchControlPaused {
			alreadyPaused = true
			return nil
		}
		if db.CanonicalBatchControlState(currentBatch.ControlState) != db.BatchControlActive {
			return errBatchNotPausable
		}

		batchStatus := currentBatch.Status
		switch db.CanonicalAttemptState(attempt.Status) {
		case db.AttemptStateQueued, db.AttemptStateDispatching, db.AttemptStateRecovered:
			update := tx.Model(&db.SubTask{}).
				Where("id = ? AND tenant_id = ? AND status = ?", attempt.ID, attempt.TenantID, attempt.Status).
				Updates(map[string]interface{}{"status": "Paused", "agent_id": "", "stream_msg_id": ""})
			if update.Error != nil {
				return update.Error
			}
			if update.RowsAffected != 1 {
				return errBatchStateChanged
			}
			pausedWithoutClaim = true
			batchStatus = "Paused"
		case db.AttemptStateRunning:
			runningContinues = true
		case db.AttemptStatePaused:
			pausedWithoutClaim = true
			batchStatus = "Paused"
		default:
			return errBatchNotPausable
		}

		update := tx.Model(&db.TaskBatch{}).
			Where("id = ? AND tenant_id = ? AND latest_attempt_id = ? AND control_state IN ?", currentBatch.ID, currentBatch.TenantID, attempt.ID, []string{"", string(db.BatchControlActive)}).
			Updates(map[string]interface{}{"status": batchStatus, "control_state": db.BatchControlPaused})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return errBatchStateChanged
		}
		return recordBatchAudit(tx, currentRoot, currentBatch, attempt.ID, "batch_pause", attempt.Status, "Paused", taskOperatorID(c), map[string]interface{}{
			"paused_without_claim": pausedWithoutClaim,
			"running_continues":    runningContinues,
			"automatic_retry":      false,
		})
	})
	if err != nil {
		if writeBatchMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !alreadyPaused {
		db.RefreshRootTaskStatus(root.ID)
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "paused", "already_paused": alreadyPaused,
		"paused_without_claim": pausedWithoutClaim, "running_attempt_continues": runningContinues,
	})
}

func resumeTaskBatch(c *gin.Context) {
	root, batch, ok := requireTaskBatchAccess(c)
	if !ok {
		return
	}
	if routerRuntime().TaskQueue == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "task queue not initialized"})
		return
	}
	var prepared *db.SubTask
	runningContinues := false
	completedWhilePaused := false
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		currentRoot, currentBatch, attempt, err := lockTaskBatchMutation(tx, root.TenantID, root.ID, batch.ID)
		if err != nil {
			return err
		}
		if currentRoot.ArchivedAt != nil || currentBatch.ArchivedAt != nil || !taskAllowsBatchDispatch(currentRoot) {
			return errTaskBlocksBatch
		}
		if db.CanonicalBatchControlState(currentBatch.ControlState) != db.BatchControlPaused {
			return errBatchNotResumable
		}

		beforeStatus := attempt.Status
		isRiskValidation := strings.EqualFold(strings.TrimSpace(currentBatch.Kind), "risk_validation")
		attemptState := db.CanonicalAttemptState(attempt.Status)
		if isRiskValidation && attemptState != db.AttemptStateRunning && attemptState != db.AttemptStateCompleted && currentRuleVersionTx(tx) != attempt.RuleVersion {
			return errRiskBatchRuleDrift
		}
		switch attemptState {
		case db.AttemptStateRunning:
			runningContinues = true
			update := tx.Model(&db.TaskBatch{}).
				Where("id = ? AND tenant_id = ? AND latest_attempt_id = ? AND control_state = ?", currentBatch.ID, currentBatch.TenantID, attempt.ID, db.BatchControlPaused).
				Update("control_state", db.BatchControlActive)
			if update.Error != nil || update.RowsAffected != 1 {
				if update.Error != nil {
					return update.Error
				}
				return errBatchStateChanged
			}
		case db.AttemptStatePaused:
			update := tx.Model(&db.SubTask{}).
				Where("id = ? AND tenant_id = ? AND status = ?", attempt.ID, attempt.TenantID, attempt.Status).
				Updates(map[string]interface{}{"status": subTaskStatusDispatching, "agent_id": "", "stream_msg_id": ""})
			if update.Error != nil || update.RowsAffected != 1 {
				if update.Error != nil {
					return update.Error
				}
				return errBatchStateChanged
			}
			attempt.Status = subTaskStatusDispatching
			if err := tx.Model(&db.TaskBatch{}).
				Where("id = ? AND tenant_id = ? AND latest_attempt_id = ? AND control_state = ?", currentBatch.ID, currentBatch.TenantID, attempt.ID, db.BatchControlPaused).
				Updates(map[string]interface{}{"status": subTaskStatusDispatching, "control_state": db.BatchControlActive}).Error; err != nil {
				return err
			}
			prepared = &attempt
		case db.AttemptStateFailed, db.AttemptStateTimeout, db.AttemptStateStopped:
			next, appended, err := db.AppendSubTaskAttemptTx(tx, &attempt, db.AttemptRetryOptions{
				Trigger: db.AttemptTriggerResume, UseCurrentTaskConfig: !isRiskValidation,
				PreserveRuleVersion: isRiskValidation,
				AllowTerminalRoot:   true, AllowControlledBatch: true,
				PreparedStatus: subTaskStatusDispatching, PreparedControlState: db.BatchControlActive,
			})
			if err != nil {
				return err
			}
			if !appended {
				return errBatchStateChanged
			}
			prepared = &next
		case db.AttemptStateCompleted:
			completedWhilePaused = true
			if err := tx.Model(&db.TaskBatch{}).
				Where("id = ? AND tenant_id = ? AND latest_attempt_id = ? AND control_state = ?", currentBatch.ID, currentBatch.TenantID, attempt.ID, db.BatchControlPaused).
				Updates(map[string]interface{}{"status": attempt.Status, "control_state": db.BatchControlActive}).Error; err != nil {
				return err
			}
		default:
			return errBatchNotResumable
		}

		if prepared != nil && db.IsTerminalTaskStatus(currentRoot.Status) {
			update := tx.Model(&db.RootTask{}).
				Where("id = ? AND tenant_id = ? AND status = ? AND archived_at IS NULL", currentRoot.ID, currentRoot.TenantID, currentRoot.Status).
				Update("status", "Running")
			if update.Error != nil || update.RowsAffected != 1 {
				if update.Error != nil {
					return update.Error
				}
				return errBatchStateChanged
			}
		}
		afterStatus := beforeStatus
		attemptID := attempt.ID
		if prepared != nil {
			afterStatus = prepared.Status
			attemptID = prepared.ID
		}
		return recordBatchAudit(tx, currentRoot, currentBatch, attemptID, "batch_resume", beforeStatus, afterStatus, taskOperatorID(c), map[string]interface{}{
			"running_attempt_continues": runningContinues,
			"completed_while_paused":    completedWhilePaused,
		})
	})
	if err != nil {
		if writeBatchMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	dispatchPending := 0
	if prepared != nil {
		pushed, pending := dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, []db.SubTask{*prepared})
		dispatchPending = pending
		if totalDispatchedTasks(pushed) > 0 {
			broadcastDispatchedTasks(pushed)
		}
	}
	db.RefreshRootTaskStatus(root.ID)
	c.JSON(http.StatusOK, gin.H{
		"status": "resumed", "running_attempt_continues": runningContinues,
		"completed_while_paused": completedWhilePaused, "dispatch_pending": dispatchPending,
	})
}

func stopTaskBatch(c *gin.Context) {
	root, batch, ok := requireTaskBatchAccess(c)
	if !ok {
		return
	}
	if root.ArchivedAt != nil || batch.ArchivedAt != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archived task or batch cannot be stopped"})
		return
	}
	var cancelledWithoutClaim, cancelPending bool
	alreadyStopped := false
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		currentRoot, currentBatch, attempt, err := lockTaskBatchMutation(tx, root.TenantID, root.ID, batch.ID)
		if err != nil {
			return err
		}
		control := db.CanonicalBatchControlState(currentBatch.ControlState)
		if control == db.BatchControlStopped || db.CanonicalAttemptState(attempt.Status) == db.AttemptStateStopped {
			alreadyStopped = true
			return nil
		}
		if control == db.BatchControlStopping {
			cancelPending = true
			return nil
		}
		if db.CanonicalTaskState(currentRoot.Status) == db.TaskStateStopping {
			return errTaskBlocksBatch
		}

		beforeStatus := attempt.Status
		now := time.Now()
		switch db.CanonicalAttemptState(attempt.Status) {
		case db.AttemptStateQueued, db.AttemptStateDispatching, db.AttemptStateRecovered, db.AttemptStatePaused:
			update := tx.Model(&db.SubTask{}).
				Where("id = ? AND tenant_id = ? AND status = ?", attempt.ID, attempt.TenantID, attempt.Status).
				Updates(map[string]interface{}{
					"status": "Cancelled", "agent_id": "", "stream_msg_id": "",
					"failure_reason": "stopped before Agent assignment", "finished_at": now,
				})
			if update.Error != nil || update.RowsAffected != 1 {
				if update.Error != nil {
					return update.Error
				}
				return errBatchStateChanged
			}
			cancelledWithoutClaim = true
			if err := tx.Model(&db.TaskBatch{}).
				Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", currentBatch.ID, currentBatch.TenantID, attempt.ID).
				Updates(map[string]interface{}{"status": "Cancelled", "control_state": db.BatchControlStopped}).Error; err != nil {
				return err
			}
		case db.AttemptStateRunning:
			update := tx.Model(&db.SubTask{}).
				Where("id = ? AND tenant_id = ? AND status = ?", attempt.ID, attempt.TenantID, attempt.Status).
				Update("status", "CancelPending")
			if update.Error != nil || update.RowsAffected != 1 {
				if update.Error != nil {
					return update.Error
				}
				return errBatchStateChanged
			}
			cancelPending = true
			if err := tx.Model(&db.TaskBatch{}).
				Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", currentBatch.ID, currentBatch.TenantID, attempt.ID).
				Updates(map[string]interface{}{"status": "CancelPending", "control_state": db.BatchControlStopping}).Error; err != nil {
				return err
			}
		default:
			return errBatchNotStoppable
		}
		afterStatus := "Cancelled"
		if cancelPending {
			afterStatus = "CancelPending"
		}
		return recordBatchAudit(tx, currentRoot, currentBatch, attempt.ID, "batch_stop", beforeStatus, afterStatus, taskOperatorID(c), map[string]interface{}{
			"cancelled_without_claim": cancelledWithoutClaim,
			"cancel_pending_on_agent": cancelPending,
		})
	})
	if err != nil {
		if writeBatchMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !alreadyStopped {
		db.RefreshRootTaskStatus(root.ID)
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "stop_requested", "already_stopped": alreadyStopped,
		"cancelled_without_claim": cancelledWithoutClaim, "cancel_pending_on_agent": cancelPending,
	})
}

func retryTaskBatch(c *gin.Context) {
	root, batch, ok := requireTaskBatchAccess(c)
	if !ok {
		return
	}
	operatorID := taskOperatorID(c)
	idempotencyKey, idempotencyRequested, err := parseTaskBatchRetryIdempotencyKey(c.Request.Header)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_idempotency_key", "error": err.Error()})
		return
	}
	if root.ArchivedAt != nil || batch.ArchivedAt != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archived task or batch cannot be retried"})
		return
	}
	var prepared db.SubTask
	result := taskBatchRetryResponseInput{}
	requestHash := ""
	if idempotencyRequested {
		requestHash, err = buildTaskBatchRetryRequestHash(canonicalTaskBatchRetryRequest{
			TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, OperatorID: operatorID,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		currentRoot, currentBatch, attempt, err := lockTaskBatchMutation(tx, root.TenantID, root.ID, batch.ID)
		if err != nil {
			return err
		}
		// Archive state is an object-access boundary, not retryability. It must
		// be enforced before consulting the ledger so a key cannot replay an
		// outcome after the batch has been archived.
		if currentRoot.ArchivedAt != nil || currentBatch.ArchivedAt != nil {
			return errTaskBlocksBatch
		}
		if idempotencyRequested {
			lookup, err := db.LookupTaskBatchRetryIdempotencyTx(tx, currentRoot.TenantID, currentRoot.ProjectID, currentRoot.ID, currentBatch.ID, operatorID, taskBatchRetryIdempotencyOperation, idempotencyKey, requestHash)
			if err != nil {
				return err
			}
			if lookup.Replayed {
				pending, err := taskBatchRetryReplayDispatchPending(tx, lookup.Record)
				if err != nil {
					return err
				}
				result = taskBatchRetryResponseInput{AttemptID: lookup.Record.AttemptID, Status: "retried", BeforeStatus: lookup.Record.BeforeStatus, AfterStatus: lookup.Record.AfterStatus, AttemptNo: lookup.Record.AttemptNo, ConfigVersion: lookup.Record.ConfigVersion, RuleVersion: lookup.Record.RuleVersion, DispatchPending: pending, Replayed: true}
				return nil
			}
		}
		if routerRuntime().TaskQueue == nil {
			return errTaskRetryQueueUnavailable
		}
		if !taskAllowsBatchDispatch(currentRoot) {
			return errTaskBlocksBatch
		}
		if db.CanonicalBatchControlState(currentBatch.ControlState) == db.BatchControlPaused ||
			db.CanonicalBatchControlState(currentBatch.ControlState) == db.BatchControlStopping {
			return errBatchNotRetryable
		}
		if !db.IsTerminalAttemptStatus(attempt.Status) {
			return errBatchNotRetryable
		}
		beforeStatus := attempt.Status
		isRiskValidation := strings.EqualFold(strings.TrimSpace(currentBatch.Kind), "risk_validation")
		if isRiskValidation && currentRuleVersionTx(tx) != attempt.RuleVersion {
			return errRiskBatchRuleDrift
		}
		next, appended, err := db.AppendSubTaskAttemptTx(tx, &attempt, db.AttemptRetryOptions{
			Trigger: db.AttemptTriggerManualRetry, UseCurrentTaskConfig: !isRiskValidation,
			PreserveRuleVersion: isRiskValidation,
			AllowTerminalRoot:   true, AllowControlledBatch: true, PreparedStatus: subTaskStatusDispatching,
			PreparedControlState: db.BatchControlActive,
		})
		if err != nil {
			return err
		}
		if !appended {
			return errBatchStateChanged
		}
		prepared = next
		if db.IsTerminalTaskStatus(currentRoot.Status) {
			update := tx.Model(&db.RootTask{}).
				Where("id = ? AND tenant_id = ? AND status = ? AND archived_at IS NULL", currentRoot.ID, currentRoot.TenantID, currentRoot.Status).
				Update("status", "Running")
			if update.Error != nil || update.RowsAffected != 1 {
				if update.Error != nil {
					return update.Error
				}
				return errBatchStateChanged
			}
		}
		if err := recordBatchAudit(tx, currentRoot, currentBatch, prepared.ID, "batch_retry", beforeStatus, prepared.Status, operatorID, map[string]interface{}{
			"previous_attempt_id": attempt.ID,
			"new_attempt_id":      prepared.ID,
			"config_version":      prepared.ConfigVersion,
			"rule_version":        prepared.RuleVersion,
			"force_retest":        true,
		}); err != nil {
			return err
		}
		result = taskBatchRetryResponseInput{AttemptID: prepared.ID, Status: "retried", BeforeStatus: beforeStatus, AfterStatus: prepared.Status, AttemptNo: prepared.AttemptNo, ConfigVersion: prepared.ConfigVersion, RuleVersion: prepared.RuleVersion}
		if !idempotencyRequested {
			return nil
		}
		ledger, err := db.RecordTaskBatchRetryIdempotencyTx(tx, db.TaskBatchRetryIdempotencyDraft{
			TenantID: currentRoot.TenantID, ProjectID: currentRoot.ProjectID, RootTaskID: currentRoot.ID, BatchID: currentBatch.ID, OperatorID: operatorID, Operation: taskBatchRetryIdempotencyOperation,
			IdempotencyKey: idempotencyKey, RequestHash: requestHash, AttemptID: prepared.ID, AttemptNo: prepared.AttemptNo, ConfigVersion: prepared.ConfigVersion, ConfigHash: taskBatchRetryConfigHash(prepared.Config), RuleVersion: prepared.RuleVersion, BeforeStatus: beforeStatus, AfterStatus: prepared.Status,
		})
		if err != nil {
			return err
		}
		return requireFreshTaskBatchRetryIdempotency(ledger)
	})
	if err != nil {
		if errors.Is(err, db.ErrTaskBatchRetryIdempotencyConflict) {
			c.JSON(http.StatusConflict, gin.H{"code": "idempotency_conflict", "error": "Idempotency-Key was already used for a different task batch retry request"})
			return
		}
		if errors.Is(err, errTaskBatchRetryIdempotencyRace) {
			c.JSON(http.StatusConflict, gin.H{"code": "idempotency_conflict", "error": "Idempotency-Key was committed concurrently; retry the same request"})
			return
		}
		if errors.Is(err, errTaskRetryQueueUnavailable) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		if writeBatchMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if result.Replayed {
		c.JSON(http.StatusOK, buildTaskBatchRetryResponse(result))
		return
	}
	pushed, dispatchPending := dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, []db.SubTask{prepared})
	if totalDispatchedTasks(pushed) > 0 {
		broadcastDispatchedTasks(pushed)
	}
	db.RefreshRootTaskStatus(root.ID)
	result.DispatchPending = dispatchPending
	c.JSON(http.StatusOK, buildTaskBatchRetryResponse(result))
}

func archiveTaskBatch(c *gin.Context) {
	root, batch, ok := requireTaskBatchAccess(c)
	if !ok {
		return
	}
	if batch.ArchivedAt != nil {
		c.JSON(http.StatusOK, gin.H{"status": "archived", "archived_at": batch.ArchivedAt, "already_archived": true})
		return
	}
	archivedAt := time.Now().UTC()
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		currentRoot, currentBatch, attempt, err := lockTaskBatchMutation(tx, root.TenantID, root.ID, batch.ID)
		if err != nil {
			return err
		}
		if currentBatch.ArchivedAt != nil {
			archivedAt = currentBatch.ArchivedAt.UTC()
			return nil
		}
		if !db.IsTerminalAttemptStatus(attempt.Status) || db.CanonicalBatchControlState(currentBatch.ControlState) == db.BatchControlStopping {
			return errBatchNotArchivable
		}
		update := tx.Model(&db.TaskBatch{}).
			Where("id = ? AND root_task_id = ? AND tenant_id = ? AND archived_at IS NULL", currentBatch.ID, currentRoot.ID, currentRoot.TenantID).
			Update("archived_at", archivedAt)
		if update.Error != nil || update.RowsAffected != 1 {
			if update.Error != nil {
				return update.Error
			}
			return errBatchStateChanged
		}
		return recordBatchAudit(tx, currentRoot, currentBatch, attempt.ID, "batch_archive", attempt.Status, attempt.Status, taskOperatorID(c), map[string]interface{}{
			"archived_at": archivedAt,
		})
	})
	if err != nil {
		if writeBatchMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	db.RefreshRootTaskStatus(root.ID)
	c.JSON(http.StatusOK, gin.H{"status": "archived", "archived_at": archivedAt})
}
