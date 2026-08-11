package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	errTaskStateChanged         = errors.New("task state changed during operation")
	errTaskNotArchivable        = errors.New("task must reach a terminal state before it can be archived")
	errTaskNotRetryable         = errors.New("task has no failed, timed out, or stopped batches to retry")
	errTaskCannotAppend         = errors.New("task is not in a state that accepts new batches")
	errProjectInactive          = errors.New("project is not active")
	errTaskRetryIdempotencyRace = errors.New("task retry idempotency record was committed concurrently")
)

func taskOperatorID(c *gin.Context) string {
	if operatorID := strings.TrimSpace(currentUserID(c)); operatorID != "" {
		return operatorID
	}
	return "legacy-token"
}

func recordTaskAudit(tx *gorm.DB, task db.RootTask, action, beforeStatus, afterStatus, operatorID string, details map[string]interface{}) error {
	payload := "{}"
	if len(details) > 0 {
		encoded, err := json.Marshal(details)
		if err != nil {
			return err
		}
		payload = string(encoded)
	}
	return tx.Create(&db.TaskAudit{
		TenantID:     task.TenantID,
		ProjectID:    task.ProjectID,
		RootTaskID:   task.ID,
		OperatorID:   operatorID,
		Action:       action,
		BeforeStatus: beforeStatus,
		AfterStatus:  afterStatus,
		Details:      payload,
	}).Error
}

func writeTaskMutationError(c *gin.Context, err error) bool {
	if errors.Is(err, errTaskStateChanged) || errors.Is(err, errTaskNotArchivable) || errors.Is(err, errTaskNotRetryable) || errors.Is(err, errTaskCannotAppend) || errors.Is(err, errProjectInactive) || errors.Is(err, errRiskBatchRuleDrift) {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return true
	}
	return false
}

// requireFreshTaskRetryIdempotency makes a unique-key race fail the enclosing
// transaction. Continuing after Record... returns Replayed would otherwise
// commit this transaction's newly appended Attempts and audit alongside an
// already-committed retry outcome.
func requireFreshTaskRetryIdempotency(result db.TaskRetryIdempotencyRecordResult) error {
	if result.Replayed {
		return errTaskRetryIdempotencyRace
	}
	return nil
}

type taskCurrentExecutions struct {
	BatchBacked bool
	Batches     []db.TaskBatch
	Attempts    map[string]db.SubTask
	Legacy      []db.SubTask
}

// loadTaskCurrentExecutions locks stable batches and their latest Attempts in
// deterministic order. Repositories upgraded from the legacy model may still
// have no TaskBatch rows, so the old SubTask-only representation remains a
// supported fallback until migration backfill has run.
func loadTaskCurrentExecutions(tx *gorm.DB, root db.RootTask) (taskCurrentExecutions, error) {
	result := taskCurrentExecutions{Attempts: make(map[string]db.SubTask)}
	var allBatches []db.TaskBatch
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("root_task_id = ? AND tenant_id = ?", root.ID, root.TenantID).
		Order("sequence asc").Find(&allBatches).Error; err != nil {
		return result, err
	}
	if len(allBatches) == 0 {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("root_task_id = ? AND tenant_id = ?", root.ID, root.TenantID).
			Order("created_at asc, id asc").Find(&result.Legacy).Error; err != nil {
			return result, err
		}
		return result, nil
	}

	result.BatchBacked = true
	attemptIDs := make([]string, 0, len(allBatches))
	for _, batch := range allBatches {
		if batch.ArchivedAt != nil {
			continue
		}
		result.Batches = append(result.Batches, batch)
		if strings.TrimSpace(batch.LatestAttemptID) != "" {
			attemptIDs = append(attemptIDs, batch.LatestAttemptID)
		}
	}
	if len(attemptIDs) == 0 {
		return result, nil
	}
	var attempts []db.SubTask
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("tenant_id = ? AND root_task_id = ? AND id IN ?", root.TenantID, root.ID, attemptIDs).
		Order("id asc").Find(&attempts).Error; err != nil {
		return result, err
	}
	for _, attempt := range attempts {
		result.Attempts[attempt.ID] = attempt
	}
	return result, nil
}

func deleteTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	if rootTask.ArchivedAt != nil {
		c.JSON(http.StatusOK, gin.H{"status": "archived", "archived_at": rootTask.ArchivedAt, "already_archived": true})
		return
	}
	if !db.IsTerminalTaskStatus(rootTask.Status) {
		c.JSON(http.StatusConflict, gin.H{"error": errTaskNotArchivable.Error()})
		return
	}

	archivedAt := time.Now().UTC()
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		var current db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", id, tenantID).
			First(&current).Error; err != nil {
			return err
		}
		if current.ArchivedAt != nil {
			archivedAt = current.ArchivedAt.UTC()
			return nil
		}
		if !db.IsTerminalTaskStatus(current.Status) {
			return errTaskNotArchivable
		}
		if err := tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ? AND archived_at IS NULL", id, tenantID).
			Update("archived_at", archivedAt).Error; err != nil {
			return err
		}
		return recordTaskAudit(tx, current, "archive", current.Status, current.Status, taskOperatorID(c), map[string]interface{}{
			"archived_before": false,
			"archived_after":  true,
			"archived_at":     archivedAt,
		})
	})
	if err != nil {
		if writeTaskMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "archived", "archived_at": archivedAt})
}

func cancelTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	if rootTask.ArchivedAt != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archived task cannot be stopped"})
		return
	}
	if !db.CanStopTaskStatus(rootTask.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not in a stoppable state"})
		return
	}
	cancelledWithoutClaim := int64(0)
	cancelPendingRunning := int64(0)

	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		var current db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", id, tenantID).First(&current).Error; err != nil {
			return err
		}
		if current.ArchivedAt != nil || !db.CanStopTaskStatus(current.Status) {
			return errTaskStateChanged
		}
		executions, err := loadTaskCurrentExecutions(tx, current)
		if err != nil {
			return err
		}
		finishedAt := time.Now()
		stopAttempt := func(attempt db.SubTask, batch *db.TaskBatch) error {
			switch db.CanonicalAttemptState(attempt.Status) {
			case db.AttemptStateQueued, db.AttemptStateDispatching, db.AttemptStateRecovered, db.AttemptStatePaused:
				update := tx.Model(&db.SubTask{}).
					Where("id = ? AND tenant_id = ? AND status = ?", attempt.ID, attempt.TenantID, attempt.Status).
					Updates(map[string]interface{}{
						"status": "Cancelled", "agent_id": "", "stream_msg_id": "",
						"failure_reason": "stopped before Agent assignment", "finished_at": finishedAt,
					})
				if update.Error != nil {
					return update.Error
				}
				if update.RowsAffected != 1 {
					return errTaskStateChanged
				}
				cancelledWithoutClaim++
				if batch != nil {
					batchUpdate := tx.Model(&db.TaskBatch{}).
						Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", batch.ID, batch.TenantID, attempt.ID).
						Updates(map[string]interface{}{"status": "Cancelled", "control_state": db.BatchControlStopped})
					if batchUpdate.Error != nil || batchUpdate.RowsAffected != 1 {
						if batchUpdate.Error != nil {
							return batchUpdate.Error
						}
						return errTaskStateChanged
					}
				}
			case db.AttemptStateRunning, db.AttemptStateStopping:
				if db.CanonicalAttemptState(attempt.Status) == db.AttemptStateRunning {
					update := tx.Model(&db.SubTask{}).
						Where("id = ? AND tenant_id = ? AND status = ?", attempt.ID, attempt.TenantID, attempt.Status).
						Update("status", "CancelPending")
					if update.Error != nil || update.RowsAffected != 1 {
						if update.Error != nil {
							return update.Error
						}
						return errTaskStateChanged
					}
				}
				cancelPendingRunning++
				if batch != nil {
					batchUpdate := tx.Model(&db.TaskBatch{}).
						Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", batch.ID, batch.TenantID, attempt.ID).
						Updates(map[string]interface{}{"status": "CancelPending", "control_state": db.BatchControlStopping})
					if batchUpdate.Error != nil || batchUpdate.RowsAffected != 1 {
						if batchUpdate.Error != nil {
							return batchUpdate.Error
						}
						return errTaskStateChanged
					}
				}
			}
			return nil
		}

		if executions.BatchBacked {
			for i := range executions.Batches {
				batch := &executions.Batches[i]
				attempt, exists := executions.Attempts[batch.LatestAttemptID]
				if !exists || db.CanonicalBatchControlState(batch.ControlState) == db.BatchControlStopped {
					continue
				}
				if err := stopAttempt(attempt, batch); err != nil {
					return err
				}
			}
		} else {
			for _, attempt := range executions.Legacy {
				if err := stopAttempt(attempt, nil); err != nil {
					return err
				}
			}
		}

		afterStatus := "Cancelled"
		if cancelPendingRunning > 0 {
			afterStatus = "CancelPending"
		}
		rootUpdate := tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND archived_at IS NULL", id, tenantID, current.Status).
			Update("status", afterStatus)
		if rootUpdate.Error != nil {
			return rootUpdate.Error
		}
		if rootUpdate.RowsAffected != 1 {
			return errTaskStateChanged
		}
		if err := db.SyncTaskBatchStatuses(tx, tenantID, id); err != nil {
			return err
		}
		return recordTaskAudit(tx, current, "stop", current.Status, afterStatus, taskOperatorID(c), map[string]interface{}{
			"cancelled_without_claim":  cancelledWithoutClaim,
			"cancel_pending_on_agents": cancelPendingRunning,
		})
	}); err != nil {
		if writeTaskMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":                   "cancellation dispatched",
		"cancelled_without_claim":  cancelledWithoutClaim,
		"cancel_pending_on_agents": cancelPendingRunning,
	})
}

func pauseTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	if rootTask.ArchivedAt != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archived task cannot be paused"})
		return
	}
	if !db.CanPauseTaskStatus(rootTask.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not in a pausable state"})
		return
	}

	var pausedWithoutClaim int64
	var runningContinues int64
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		var current db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", id, tenantID).First(&current).Error; err != nil {
			return err
		}
		if current.ArchivedAt != nil || !db.CanPauseTaskStatus(current.Status) {
			return errTaskStateChanged
		}
		executions, err := loadTaskCurrentExecutions(tx, current)
		if err != nil {
			return err
		}
		pauseAttempt := func(attempt db.SubTask) error {
			switch db.CanonicalAttemptState(attempt.Status) {
			case db.AttemptStateQueued, db.AttemptStateDispatching, db.AttemptStateRecovered:
				update := tx.Model(&db.SubTask{}).
					Where("id = ? AND tenant_id = ? AND status = ?", attempt.ID, attempt.TenantID, attempt.Status).
					Updates(map[string]interface{}{"status": "Paused", "agent_id": "", "stream_msg_id": ""})
				if update.Error != nil {
					return update.Error
				}
				if update.RowsAffected != 1 {
					return errTaskStateChanged
				}
				pausedWithoutClaim++
			case db.AttemptStateRunning:
				runningContinues++
			}
			return nil
		}
		if executions.BatchBacked {
			for _, batch := range executions.Batches {
				if db.CanonicalBatchControlState(batch.ControlState) != db.BatchControlActive {
					continue
				}
				if attempt, exists := executions.Attempts[batch.LatestAttemptID]; exists {
					if err := pauseAttempt(attempt); err != nil {
						return err
					}
				}
			}
		} else {
			for _, attempt := range executions.Legacy {
				if err := pauseAttempt(attempt); err != nil {
					return err
				}
			}
		}
		rootUpdate := tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND archived_at IS NULL", id, tenantID, current.Status).
			Update("status", "Paused")
		if rootUpdate.Error != nil {
			return rootUpdate.Error
		}
		if rootUpdate.RowsAffected != 1 {
			return errTaskStateChanged
		}
		if err := db.SyncTaskBatchStatuses(tx, tenantID, id); err != nil {
			return err
		}
		return recordTaskAudit(tx, current, "pause", current.Status, "Paused", taskOperatorID(c), map[string]interface{}{
			"paused_without_claim":   pausedWithoutClaim,
			"running_tasks_continue": true,
			"running_attempts":       runningContinues,
		})
	}); err != nil {
		if writeTaskMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":                 "paused",
		"paused_without_claim":   pausedWithoutClaim,
		"running_tasks_continue": true,
		"running_attempts":       runningContinues,
	})
}

func resumeTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	if rootTask.ArchivedAt != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archived task cannot be resumed"})
		return
	}
	if !db.CanResumeTaskStatus(rootTask.Status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not paused"})
		return
	}

	var prepared []db.SubTask
	var reusedAttempts, appendedAttempts, runningContinues, manuallyPaused int
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		var current db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", id, tenantID).First(&current).Error; err != nil {
			return err
		}
		if current.ArchivedAt != nil || !db.CanResumeTaskStatus(current.Status) {
			return errTaskStateChanged
		}
		executions, err := loadTaskCurrentExecutions(tx, current)
		if err != nil {
			return err
		}
		resumeAttempt := func(attempt db.SubTask, batch *db.TaskBatch) error {
			attemptState := db.CanonicalAttemptState(attempt.Status)
			isRiskValidation := batch != nil && strings.EqualFold(strings.TrimSpace(batch.Kind), "risk_validation")
			if isRiskValidation && attemptState != db.AttemptStateRunning && attemptState != db.AttemptStateCompleted && currentRuleVersionTx(tx) != attempt.RuleVersion {
				return errRiskBatchRuleDrift
			}
			switch attemptState {
			case db.AttemptStatePaused:
				update := tx.Model(&db.SubTask{}).
					Where("id = ? AND tenant_id = ? AND status = ?", attempt.ID, attempt.TenantID, attempt.Status).
					Updates(map[string]interface{}{"status": subTaskStatusDispatching, "agent_id": "", "stream_msg_id": ""})
				if update.Error != nil || update.RowsAffected != 1 {
					if update.Error != nil {
						return update.Error
					}
					return errTaskStateChanged
				}
				attempt.Status = subTaskStatusDispatching
				if batch != nil {
					batchUpdate := tx.Model(&db.TaskBatch{}).
						Where("id = ? AND tenant_id = ? AND latest_attempt_id = ? AND control_state = ?", batch.ID, batch.TenantID, attempt.ID, db.BatchControlActive).
						Update("status", subTaskStatusDispatching)
					if batchUpdate.Error != nil || batchUpdate.RowsAffected != 1 {
						if batchUpdate.Error != nil {
							return batchUpdate.Error
						}
						return errTaskStateChanged
					}
				}
				prepared = append(prepared, attempt)
				reusedAttempts++
			case db.AttemptStateFailed, db.AttemptStateTimeout, db.AttemptStateStopped:
				next, appended, err := db.AppendSubTaskAttemptTx(tx, &attempt, db.AttemptRetryOptions{
					Trigger: db.AttemptTriggerResume, UseCurrentTaskConfig: !isRiskValidation,
					PreserveRuleVersion: isRiskValidation,
					AllowTerminalRoot:   true, PreparedStatus: subTaskStatusDispatching,
					PreparedControlState: db.BatchControlActive,
				})
				if err != nil {
					return err
				}
				if !appended {
					return errTaskStateChanged
				}
				prepared = append(prepared, next)
				appendedAttempts++
			case db.AttemptStateRunning:
				runningContinues++
			}
			return nil
		}

		if executions.BatchBacked {
			for i := range executions.Batches {
				batch := &executions.Batches[i]
				if db.CanonicalBatchControlState(batch.ControlState) != db.BatchControlActive {
					if db.CanonicalBatchControlState(batch.ControlState) == db.BatchControlPaused {
						manuallyPaused++
					}
					continue
				}
				if attempt, exists := executions.Attempts[batch.LatestAttemptID]; exists {
					if err := resumeAttempt(attempt, batch); err != nil {
						return err
					}
				}
			}
		} else {
			for _, attempt := range executions.Legacy {
				if err := resumeAttempt(attempt, nil); err != nil {
					return err
				}
			}
		}
		rootUpdate := tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND archived_at IS NULL", id, tenantID, current.Status).
			Update("status", "Queued")
		if rootUpdate.Error != nil {
			return rootUpdate.Error
		}
		if rootUpdate.RowsAffected != 1 {
			return errTaskStateChanged
		}
		if err := db.SyncTaskBatchStatuses(tx, tenantID, id); err != nil {
			return err
		}
		return recordTaskAudit(tx, current, "resume", current.Status, "Queued", taskOperatorID(c), map[string]interface{}{
			"reactivated":               reusedAttempts + appendedAttempts,
			"reused_unclaimed_attempts": reusedAttempts,
			"appended_attempts":         appendedAttempts,
			"running_attempts_continue": runningContinues,
			"manually_paused_batches":   manuallyPaused,
		})
	}); err != nil {
		if writeTaskMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, prepared)
	if totalDispatchedTasks(pushedByPriority) > 0 {
		broadcastDispatchedTasks(pushedByPriority)
	}
	db.RefreshRootTaskStatus(id)

	c.JSON(http.StatusOK, gin.H{
		"status":            "resumed",
		"reactivated":       reusedAttempts + appendedAttempts,
		"reused_attempts":   reusedAttempts,
		"appended_attempts": appendedAttempts,
		"running_attempts":  runningContinues,
		"paused_batches":    manuallyPaused,
		"dispatch_pending":  dispatchPending,
	})
}

// retryTask appends a new Attempt for each unsuccessful current batch. It does
// not re-run completed batches, and it never rewrites historical execution
// evidence. This explicit operator action is also the force-retest boundary
// used by later coverage deduplication goals.
func retryTask(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	tenantID := currentTenantID(c)
	operatorID := taskOperatorID(c)
	idempotencyKey, idempotencyRequested, err := parseTaskRetryIdempotencyKey(c.Request.Header)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	if rootTask.ArchivedAt != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archived task cannot be retried"})
		return
	}
	requestHash := ""
	if idempotencyRequested {
		requestHash, err = buildTaskRetryRequestHash(canonicalTaskRetryRequest{
			TenantID: tenantID, ProjectID: rootTask.ProjectID, RootTaskID: rootTask.ID, OperatorID: operatorID,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	prepared := make([]db.SubTask, 0)
	skippedCompleted := 0
	skippedPaused := 0
	result := taskRetryResponseInput{}
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var current db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", id, tenantID).First(&current).Error; err != nil {
			return err
		}
		if current.ArchivedAt != nil {
			return errTaskStateChanged
		}
		if idempotencyRequested {
			lookup, err := db.LookupTaskRetryIdempotencyTx(tx, tenantID, current.ProjectID, current.ID, operatorID, taskRetryIdempotencyOperation, idempotencyKey, requestHash)
			if err != nil {
				return err
			}
			if lookup.Replayed {
				attemptIDs, err := decodeTaskRetryAttemptIDs(lookup.Record)
				if err != nil {
					return err
				}
				pending, err := taskRetryReplayDispatchPending(tx, lookup.Record)
				if err != nil {
					return err
				}
				result = taskRetryResponseInput{
					Status: "retried", BeforeStatus: lookup.Record.BeforeStatus, AfterStatus: lookup.Record.AfterStatus,
					RetriedBatches: len(attemptIDs), CompletedSkipped: lookup.Record.CompletedSkipped,
					PausedSkipped: lookup.Record.PausedSkipped, DispatchPending: pending, Replayed: true,
				}
				return nil
			}
		}
		if !db.CanExplicitRetryTaskStatus(current.Status) {
			return errTaskStateChanged
		}
		if routerRuntime().TaskQueue == nil {
			return errTaskRetryQueueUnavailable
		}
		executions, err := loadTaskCurrentExecutions(tx, current)
		if err != nil {
			return err
		}
		retryAttempt := func(attempt db.SubTask, batch *db.TaskBatch) error {
			isRiskValidation := batch != nil && strings.EqualFold(strings.TrimSpace(batch.Kind), "risk_validation")
			switch db.CanonicalAttemptState(attempt.Status) {
			case db.AttemptStateCompleted:
				skippedCompleted++
				return nil
			case db.AttemptStateFailed, db.AttemptStateTimeout, db.AttemptStateStopped:
				if isRiskValidation && currentRuleVersionTx(tx) != attempt.RuleVersion {
					return errRiskBatchRuleDrift
				}
				next, appended, err := db.AppendSubTaskAttemptTx(tx, &attempt, db.AttemptRetryOptions{
					Trigger: db.AttemptTriggerManualRetry, UseCurrentTaskConfig: !isRiskValidation,
					PreserveRuleVersion: isRiskValidation,
					AllowTerminalRoot:   true, AllowControlledBatch: true,
					PreparedStatus: subTaskStatusDispatching, PreparedControlState: db.BatchControlActive,
				})
				if err != nil {
					return err
				}
				if !appended {
					return errTaskStateChanged
				}
				prepared = append(prepared, next)
			}
			return nil
		}
		if executions.BatchBacked {
			for _, batch := range executions.Batches {
				control := db.CanonicalBatchControlState(batch.ControlState)
				if control == db.BatchControlPaused || control == db.BatchControlStopping {
					skippedPaused++
					continue
				}
				if attempt, exists := executions.Attempts[batch.LatestAttemptID]; exists {
					if err := retryAttempt(attempt, &batch); err != nil {
						return err
					}
				}
			}
		} else {
			for _, attempt := range executions.Legacy {
				if err := retryAttempt(attempt, nil); err != nil {
					return err
				}
			}
		}
		if len(prepared) == 0 {
			return errTaskNotRetryable
		}
		rootUpdate := tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND archived_at IS NULL", id, tenantID, current.Status).
			Update("status", "Running")
		if rootUpdate.Error != nil || rootUpdate.RowsAffected != 1 {
			if rootUpdate.Error != nil {
				return rootUpdate.Error
			}
			return errTaskStateChanged
		}
		if err := recordTaskAudit(tx, current, "retry", current.Status, "Running", operatorID, map[string]interface{}{
			"retried_batches":   len(prepared),
			"completed_skipped": skippedCompleted,
			"paused_skipped":    skippedPaused,
			"force_retest":      true,
		}); err != nil {
			return err
		}
		result = taskRetryResponseInput{Status: "retried", BeforeStatus: current.Status, AfterStatus: "Running", RetriedBatches: len(prepared), CompletedSkipped: skippedCompleted, PausedSkipped: skippedPaused}
		if idempotencyRequested {
			attemptIDs := make([]string, 0, len(prepared))
			for _, attempt := range prepared {
				attemptIDs = append(attemptIDs, attempt.ID)
			}
			idempotencyResult, err := db.RecordTaskRetryIdempotencyTx(tx, db.TaskRetryIdempotencyDraft{
				TenantID: tenantID, ProjectID: current.ProjectID, RootTaskID: current.ID, OperatorID: operatorID, Operation: taskRetryIdempotencyOperation,
				IdempotencyKey: idempotencyKey, RequestHash: requestHash, BeforeStatus: current.Status, AfterStatus: "Running", AttemptIDs: attemptIDs,
				CompletedSkipped: skippedCompleted, PausedSkipped: skippedPaused,
			})
			if err != nil {
				return err
			}
			if err := requireFreshTaskRetryIdempotency(idempotencyResult); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, db.ErrTaskRetryIdempotencyConflict) {
			c.JSON(http.StatusConflict, gin.H{"code": "idempotency_conflict", "error": "Idempotency-Key was already used for a different task retry request"})
			return
		}
		if errors.Is(err, errTaskRetryIdempotencyRace) {
			c.JSON(http.StatusConflict, gin.H{"code": "idempotency_conflict", "error": "Idempotency-Key was committed concurrently; retry the same request"})
			return
		}
		if errors.Is(err, errTaskRetryQueueUnavailable) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		if writeTaskMutationError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if result.Replayed {
		c.JSON(http.StatusOK, buildTaskRetryResponse(result))
		return
	}

	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, prepared)
	if totalDispatchedTasks(pushedByPriority) > 0 {
		broadcastDispatchedTasks(pushedByPriority)
	}
	db.RefreshRootTaskStatus(id)
	result.DispatchPending = dispatchPending
	c.JSON(http.StatusOK, buildTaskRetryResponse(result))
}

// appendTargets 向运行中的任务动态追加目标
// POST /tasks/:id/append  body: { "targets": "1.1.1.1\n2.2.2.2" }
func appendTargets(c *gin.Context) {
	rootTaskID := strings.TrimSpace(c.Param("id"))
	idempotencyKey, idempotencyRequested, err := parseTaskAppendIdempotencyKey(c.Request.Header)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_idempotency_key", "error": err.Error()})
		return
	}
	var req struct {
		Targets json.RawMessage `json:"targets"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rawTargets, err := parseTargets(req.Targets)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(rawTargets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No targets to append"})
		return
	}

	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", rootTaskID, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	if rootTask.ArchivedAt != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "archived task cannot accept new targets"})
		return
	}
	if !idempotencyRequested && routerRuntime().TaskQueue == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "task queue not initialized"})
		return
	}
	operatorID := taskOperatorID(c)

	type appendResult struct {
		newTargets        []string
		duplicateTargets  []string
		newTaskBatches    []db.TaskBatch
		newSubTasks       []db.SubTask
		targetSummary     taskTargetSummary
		profile           batchProfile
		configVersion     int
		totalChunks       int
		totalTargets      int
		projectScopeAdded int
		projectSeedsAdded int
		dispatch          bool
		replayed          bool
		outcome           string
		dispatched        int
		dispatchPending   int
	}
	result := appendResult{
		profile: batchProfile{
			BatchesByType: make(map[string]int),
			BatchSize:     make(map[string]int),
		},
	}
	var validationErr error
	var requestHash string

	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var current db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", rootTaskID, tenantID).
			First(&current).Error; err != nil {
			return err
		}
		if current.ArchivedAt != nil {
			return errTaskCannotAppend
		}
		switch db.CanonicalTaskState(current.Status) {
		case db.TaskStateStopping, db.TaskStateCreated, db.TaskStateUnknown:
			return errTaskCannotAppend
		}

		var project db.Project
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", current.ProjectID, tenantID).
			First(&project).Error; err != nil {
			return err
		}
		if !strings.EqualFold(strings.TrimSpace(project.Status), "active") {
			return errProjectInactive
		}
		var existingIdempotency db.TaskAppendIdempotency
		var hasExistingIdempotency bool
		if idempotencyRequested {
			existingIdempotency, hasExistingIdempotency, err = db.FindTaskAppendIdempotencyTx(tx, tenantID, current.ProjectID, current.ID, operatorID, taskAppendIdempotencyOperation, idempotencyKey)
			if err != nil {
				return err
			}
		}

		var configRevision db.TaskConfigRevision
		if hasExistingIdempotency {
			err = tx.Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND version = ?", tenantID, current.ProjectID, current.ID, existingIdempotency.ConfigVersion).First(&configRevision).Error
		} else {
			configRevision, err = db.CurrentTaskConfigRevision(tx, current)
		}
		if err != nil {
			return err
		}
		result.configVersion = configRevision.Version
		if legacyProviderConfigJSON(configRevision.Config) {
			return fmt.Errorf("Provider discovery configuration is Server-only; append is rejected")
		}
		targetMode := detectTargetModeFromStoredConfig(configRevision.Config)
		requested := normalizeTargetsForMode(rawTargets, targetMode)
		if idempotencyRequested {
			requestHash, err = buildTaskAppendRequestHash(canonicalTaskAppendRequest{
				TenantID: tenantID, ProjectID: current.ProjectID, RootTaskID: current.ID,
				OperatorID: operatorID, Targets: requested,
			})
			if err != nil {
				return fmt.Errorf("canonicalize task append request: %w", err)
			}
		}
		requested, _, validationErr = validateTargetsByMode(requested, targetMode)
		if validationErr != nil {
			return validationErr
		}
		if hasExistingIdempotency {
			idempotencyResult, err := db.LookupTaskAppendIdempotencyTx(tx, tenantID, current.ProjectID, current.ID, operatorID, taskAppendIdempotencyOperation, idempotencyKey, requestHash)
			if err != nil {
				return err
			}
			record := idempotencyResult.Record
			result.replayed, result.outcome = true, record.Outcome
			result.configVersion, result.totalChunks, result.totalTargets = record.ConfigVersion, record.TotalChunks, record.TotalTargets
			result.projectScopeAdded, result.projectSeedsAdded = record.ProjectScopeAdded, record.ProjectSeedsAdded
			result.newTargets = make([]string, record.NewTargets)
			result.duplicateTargets = make([]string, record.DuplicateTargets)
			result.dispatched, result.dispatchPending, err = taskAppendReplayDispatchCounts(tx, record)
			if err != nil {
				return err
			}
			result.targetSummary, result.profile, err = taskAppendReplayScanSummary(tx, record)
			return err
		}

		var existingBatches []db.TaskBatch
		if err := tx.Where("root_task_id = ? AND tenant_id = ?", rootTaskID, tenantID).
			Order("sequence asc").Find(&existingBatches).Error; err != nil {
			return err
		}
		existingTargets, err := existingTaskTargetSet(existingBatches)
		if err != nil {
			return err
		}
		originalTargets, err := decodeStoredTargetList(current.OriginalTargets, true)
		if err != nil {
			return err
		}
		for _, target := range normalizeTargetsForMode(originalTargets, targetMode) {
			existingTargets[target] = struct{}{}
		}
		result.newTargets, result.duplicateTargets = filterNewTaskTargets(requested, existingTargets)
		result.totalChunks = current.TotalChunks
		result.totalTargets = current.TotalTargets
		if len(result.newTargets) == 0 {
			result.outcome = "unchanged"
			if idempotencyRequested {
				ruleVersion := current.RuleVersion
				if strings.TrimSpace(ruleVersion) == "" {
					ruleVersion = "_unknown"
				}
				_, err := db.RecordTaskAppendIdempotencyTx(tx, db.TaskAppendIdempotencyDraft{
					TenantID: tenantID, ProjectID: current.ProjectID, RootTaskID: current.ID, OperatorID: operatorID, Operation: taskAppendIdempotencyOperation,
					IdempotencyKey: idempotencyKey, RequestHash: requestHash, Outcome: result.outcome, ConfigVersion: configRevision.Version,
					ConfigHash: configRevision.ConfigHash, RuleVersion: ruleVersion, BeforeStatus: current.Status, AfterStatus: current.Status,
					RequestedTargets: len(requested), DuplicateTargets: len(result.duplicateTargets), TotalChunks: current.TotalChunks, TotalTargets: current.TotalTargets,
				})
				return err
			}
			return nil
		}

		_, _, result.targetSummary = classifyTargets(result.newTargets, targetMode)
		groups := groupAndBatchTargets(result.newTargets, targetMode)
		result.profile.TotalTargets = len(result.newTargets)
		result.profile.TotalBatches = len(groups)

		var maxSequence int
		if err := tx.Model(&db.TaskBatch{}).
			Select("COALESCE(MAX(sequence), -1)").
			Where("root_task_id = ? AND tenant_id = ?", rootTaskID, tenantID).
			Scan(&maxSequence).Error; err != nil {
			return err
		}
		baseSequence := maxSequence + 1
		userSelector := parseSelectorJSONString(configRevision.AgentSelector)
		userRules := db.ParseSelectorRulesJSON(configRevision.AgentSelectorRules)
		ruleVersion := currentRuleVersion()
		if strings.TrimSpace(ruleVersion) == "" {
			ruleVersion = current.RuleVersion
		}
		if strings.TrimSpace(ruleVersion) == "" {
			ruleVersion = "_unknown"
		}

		attemptStatus := subTaskStatusDispatching
		afterStatus := "Running"
		result.dispatch = true
		if db.CanonicalTaskState(current.Status) == db.TaskStatePaused {
			attemptStatus = "Paused"
			afterStatus = "Paused"
			result.dispatch = false
		}
		if routerRuntime().TaskQueue == nil {
			return errTaskAppendQueueUnavailable
		}

		batchIDs := make([]string, 0, len(groups))
		for index, group := range groups {
			chunkJSON, _ := json.Marshal(group.Targets)
			_, _, rulesJSON := effectiveSelectorRules(group.SelectorJSON, userSelector, userRules)
			sequence := baseSequence + index
			batchID := fmt.Sprintf("%s-batch-%d-%s", rootTaskID, sequence, group.TargetType)
			attemptID := fmt.Sprintf("%s-attempt-1", batchID)
			effectiveSelector := mergeAgentSelector(group.SelectorJSON, userSelector)
			result.newTaskBatches = append(result.newTaskBatches, db.TaskBatch{
				ID: batchID, TenantID: tenantID, ProjectID: current.ProjectID, RootTaskID: rootTaskID,
				Sequence: sequence, Kind: "asset_scan", TargetType: group.TargetType,
				Targets: string(chunkJSON), TargetCount: len(group.Targets), Status: attemptStatus,
				ConfigVersion: configRevision.Version, RuleVersion: ruleVersion,
				Priority: configRevision.Priority, TimeoutSec: configRevision.TimeoutSec,
				AgentSelector: effectiveSelector, AgentSelectorRules: rulesJSON,
				CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: attemptID, CreatedBy: operatorID,
			})
			result.newSubTasks = append(result.newSubTasks, db.SubTask{
				ID: attemptID, TenantID: tenantID, ProjectID: current.ProjectID, RootTaskID: rootTaskID,
				BatchID: batchID, AttemptNo: 1, Trigger: db.AttemptTriggerInitial,
				ChunkTargets: string(chunkJSON), Status: attemptStatus, Config: configRevision.Config,
				Priority: configRevision.Priority, TimeoutSec: configRevision.TimeoutSec, MaxRetry: 3,
				ConfigVersion: configRevision.Version, RuleVersion: ruleVersion,
				AgentSelector: effectiveSelector, AgentSelectorRules: rulesJSON,
			})
			batchIDs = append(batchIDs, batchID)
			result.profile.BatchesByType[group.TargetType]++
			if _, exists := result.profile.BatchSize[group.TargetType]; !exists {
				result.profile.BatchSize[group.TargetType] = batchSizeForTargetType(group.TargetType)
			}
		}

		seedTargets, seedAdded, _, err := mergeStoredTargetList(project.SeedTargets, result.newTargets, false)
		if err != nil {
			return err
		}
		scopeTargets, scopeAdded, scopeTotal, err := mergeStoredTargetList(project.Scope, result.newTargets, false)
		if err != nil {
			return err
		}
		originalTargetsJSON, _, _, err := mergeStoredTargetList(current.OriginalTargets, result.newTargets, true)
		if err != nil {
			return err
		}
		result.projectSeedsAdded = len(seedAdded)
		result.projectScopeAdded = len(scopeAdded)

		if err := tx.CreateInBatches(result.newTaskBatches, 100).Error; err != nil {
			return err
		}
		if err := tx.CreateInBatches(result.newSubTasks, 100).Error; err != nil {
			return err
		}
		rootUpdate := tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND archived_at IS NULL", current.ID, tenantID, current.Status).
			Updates(map[string]interface{}{
				"original_targets": originalTargetsJSON,
				"total_chunks":     current.TotalChunks + len(result.newTaskBatches),
				"total_targets":    current.TotalTargets + len(result.newTargets),
				"rule_version":     ruleVersion,
				"status":           afterStatus,
			})
		if rootUpdate.Error != nil {
			return rootUpdate.Error
		}
		if rootUpdate.RowsAffected != 1 {
			return errTaskStateChanged
		}
		projectUpdate := tx.Model(&db.Project{}).
			Where("id = ? AND tenant_id = ? AND status = ?", project.ID, tenantID, project.Status).
			Updates(map[string]interface{}{
				"seed_targets": seedTargets,
				"scope":        scopeTargets,
				"updated_at":   time.Now(),
			})
		if projectUpdate.Error != nil {
			return projectUpdate.Error
		}
		if projectUpdate.RowsAffected != 1 {
			return errTaskStateChanged
		}

		result.totalChunks = current.TotalChunks + len(result.newTaskBatches)
		result.totalTargets = current.TotalTargets + len(result.newTargets)
		result.outcome = "appended"
		if idempotencyRequested {
			attemptIDs := make([]string, 0, len(result.newSubTasks))
			for _, attempt := range result.newSubTasks {
				attemptIDs = append(attemptIDs, attempt.ID)
			}
			idempotencyResult, err := db.RecordTaskAppendIdempotencyTx(tx, db.TaskAppendIdempotencyDraft{
				TenantID: tenantID, ProjectID: current.ProjectID, RootTaskID: current.ID, OperatorID: operatorID, Operation: taskAppendIdempotencyOperation,
				IdempotencyKey: idempotencyKey, RequestHash: requestHash, Outcome: result.outcome, ConfigVersion: configRevision.Version,
				ConfigHash: configRevision.ConfigHash, RuleVersion: ruleVersion, BeforeStatus: current.Status, AfterStatus: afterStatus,
				BatchIDs: batchIDs, AttemptIDs: attemptIDs, RequestedTargets: len(requested), NewTargets: len(result.newTargets), DuplicateTargets: len(result.duplicateTargets),
				ProjectScopeAdded: result.projectScopeAdded, ProjectSeedsAdded: result.projectSeedsAdded, TotalChunks: result.totalChunks, TotalTargets: result.totalTargets,
			})
			if err != nil {
				return err
			}
			if idempotencyResult.Replayed {
				return errors.New("task append idempotency replay raced after mutation planning")
			}
		}
		return recordTaskAudit(tx, current, "batch_append", current.Status, afterStatus, operatorID, map[string]interface{}{
			"batch_ids":                batchIDs,
			"new_targets":              result.newTargets,
			"duplicate_target_count":   len(result.duplicateTargets),
			"config_version":           configRevision.Version,
			"scope_added_targets":      scopeAdded,
			"scope_after_count":        scopeTotal,
			"seed_targets_added_count": len(seedAdded),
		})
	})
	if err != nil {
		if errors.Is(err, db.ErrTaskAppendIdempotencyConflict) {
			c.JSON(http.StatusConflict, gin.H{"code": "idempotency_conflict", "error": "Idempotency-Key was already used for a different task append request"})
			return
		}
		if errors.Is(err, errTaskAppendQueueUnavailable) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		if writeTaskMutationError(c, err) {
			return
		}
		if validationErr != nil && errors.Is(err, validationErr) {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result.replayed {
		c.JSON(http.StatusOK, buildTaskAppendResponse(taskAppendResponseInput{
			Outcome: result.outcome, NewBatches: result.profile.TotalBatches, NewTargets: len(result.newTargets), DuplicateTargets: len(result.duplicateTargets),
			ConfigVersion: result.configVersion, TotalChunks: result.totalChunks, TotalTargets: result.totalTargets,
			ProjectScopeAdded: result.projectScopeAdded, ProjectSeedsAdded: result.projectSeedsAdded,
			Dispatched: result.dispatched, DispatchPending: result.dispatchPending, TargetSummary: result.targetSummary, Profile: result.profile, Replayed: true,
		}))
		return
	}

	if len(result.newSubTasks) == 0 {
		c.JSON(http.StatusOK, buildTaskAppendResponse(taskAppendResponseInput{
			Outcome: "unchanged", NewTargets: 0, DuplicateTargets: len(result.duplicateTargets),
			ConfigVersion: result.configVersion, TotalChunks: result.totalChunks, TotalTargets: result.totalTargets,
			Replayed: false,
		}))
		return
	}

	pushedByPriority := map[int]int{}
	dispatchPending := 0
	if result.dispatch {
		pushedByPriority, dispatchPending = dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, result.newSubTasks)
		broadcastDispatchedTasks(pushedByPriority)
		if dispatchPending > 0 {
			log.Printf("[AppendTargets] RootTask %s has %d batches pending dispatch recovery", rootTaskID, dispatchPending)
		}
	}
	pushedCount := totalDispatchedTasks(pushedByPriority)
	log.Printf("[AppendTargets] RootTask %s: appended %d normalized targets into %d batches", rootTaskID, len(result.newTargets), len(result.newSubTasks))

	c.JSON(http.StatusOK, buildTaskAppendResponse(taskAppendResponseInput{
		Outcome: "appended", NewBatches: len(result.newTaskBatches), NewTargets: len(result.newTargets), DuplicateTargets: len(result.duplicateTargets),
		ConfigVersion: result.configVersion, TotalChunks: result.totalChunks, TotalTargets: result.totalTargets,
		ProjectScopeAdded: result.projectScopeAdded, ProjectSeedsAdded: result.projectSeedsAdded,
		Dispatched: pushedCount, DispatchPending: dispatchPending, TargetSummary: result.targetSummary, Profile: result.profile, Replayed: false,
	}))
}
