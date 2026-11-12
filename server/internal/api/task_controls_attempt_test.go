package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type taskRetryIdempotencyResponse struct {
	Status           string `json:"status"`
	RetriedBatches   int    `json:"retried_batches"`
	CompletedSkipped int    `json:"completed_skipped"`
	PausedSkipped    int    `json:"paused_skipped"`
	DispatchPending  int    `json:"dispatch_pending"`
	Replayed         bool   `json:"replayed"`
}

func retryIdempotentTaskRequest(t *testing.T, taskID, key string) (taskRetryIdempotencyResponse, *httptest.ResponseRecorder) {
	t.Helper()
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+taskID+"/retry", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: taskID}}
	if key != "" {
		ctx.Request.Header.Set("Idempotency-Key", key)
	}
	retryTask(ctx)
	var response taskRetryIdempotencyResponse
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode retry response: %v", err)
		}
	}
	return response, recorder
}

func TestResumeTaskAppendsFailedAttemptAndPreservesManualBatchPause(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	queue := withBatchTestQueue(t)
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).Update("status", "Paused").Error; err != nil {
		t.Fatal(err)
	}
	manualBatch := db.TaskBatch{
		ID: "batch-manual-pause", TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID,
		Sequence: 1, Kind: "asset_scan", TargetType: "url", Targets: `["https://paused.test"]`, TargetCount: 1,
		Status: "Paused", ControlState: string(db.BatchControlPaused), ConfigVersion: 1, RuleVersion: "rules-v1",
		Priority: 1, TimeoutSec: 60, CurrentAttemptNo: 1, AttemptCount: 1,
		LatestAttemptID: "batch-manual-pause-attempt-1", CreatedBy: "1",
	}
	manualAttempt := db.SubTask{
		ID: manualBatch.LatestAttemptID, TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID,
		BatchID: manualBatch.ID, AttemptNo: 1, Trigger: db.AttemptTriggerInitial, ChunkTargets: manualBatch.Targets,
		Status: "Paused", Config: `{"NoPoc":true}`, Priority: 1, TimeoutSec: 60, MaxRetry: 3,
		ConfigVersion: 1, RuleVersion: "rules-v1",
	}
	if err := db.DB.Create(&manualBatch).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Create(&manualAttempt).Error; err != nil {
		t.Fatal(err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+seed.root.ID+"/resume", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: seed.root.ID}}
	resumeTask(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("resume status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var attempts []db.SubTask
	if err := db.DB.Where("batch_id = ?", seed.batch.ID).Order("attempt_no asc").Find(&attempts).Error; err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 || attempts[1].Trigger != db.AttemptTriggerResume || attempts[1].ParentAttemptID != attempts[0].ID {
		t.Fatalf("failed attempt was not resumed append-only: %+v", attempts)
	}
	var manualAttempts int64
	db.DB.Model(&db.SubTask{}).Where("batch_id = ?", manualBatch.ID).Count(&manualAttempts)
	if manualAttempts != 1 {
		t.Fatalf("manual batch pause was overridden: attempts=%d", manualAttempts)
	}
	if err := db.DB.First(&manualBatch, "id = ?", manualBatch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalBatchControlState(manualBatch.ControlState) != db.BatchControlPaused {
		t.Fatalf("manual pause control changed: %+v", manualBatch)
	}
	queued, _, err := queue.TryPopTask(t.Context(), "agent-task-resume")
	if err != nil || queued == nil || queued.TaskId != attempts[1].ID {
		t.Fatalf("resumed attempt not queued: task=%+v err=%v", queued, err)
	}
	var audit db.TaskAudit
	if err := db.DB.First(&audit, "root_task_id = ? AND action = ?", seed.root.ID, "resume").Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(audit.Details, `"appended_attempts":1`) || !strings.Contains(audit.Details, `"manually_paused_batches":1`) {
		t.Fatalf("resume audit lacks execution decisions: %+v", audit)
	}
}

func TestStopPausedTaskOnlyTerminalizesLatestAttempt(t *testing.T) {
	seed := seedBatchLifecycle(t, "Paused")
	withBatchTestQueue(t)
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).Update("status", "Paused").Error; err != nil {
		t.Fatal(err)
	}
	historical := seed.attempt
	historical.ID = "batch-control-attempt-history"
	historical.Status = "Failed"
	historical.AttemptNo = 0
	historical.FailureReason = "historical evidence"
	if err := db.DB.Create(&historical).Error; err != nil {
		t.Fatal(err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+seed.root.ID+"/cancel", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: seed.root.ID}}
	cancelTask(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("stop paused status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.First(&seed.attempt, "id = ?", seed.attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if seed.attempt.Status != "Cancelled" {
		t.Fatalf("latest paused attempt not stopped: %+v", seed.attempt)
	}
	if err := db.DB.First(&historical, "id = ?", historical.ID).Error; err != nil {
		t.Fatal(err)
	}
	if historical.Status != "Failed" || historical.FailureReason != "historical evidence" {
		t.Fatalf("historical attempt was mutated: %+v", historical)
	}
	if err := db.DB.First(&seed.batch, "id = ?", seed.batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalBatchControlState(seed.batch.ControlState) != db.BatchControlStopped {
		t.Fatalf("batch control did not settle stopped: %+v", seed.batch)
	}
	if err := db.DB.First(&seed.root, "id = ?", seed.root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalTaskState(seed.root.Status) != db.TaskStateStopped {
		t.Fatalf("paused root did not stop: %+v", seed.root)
	}
}

func TestRetryTaskAppendsOnlyUnsuccessfulCurrentBatches(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	queue := withBatchTestQueue(t)
	rootV2 := seed.root
	rootV2.Status = "Failed"
	rootV2.CurrentConfigVersion = 2
	rootV2.Config = `{"NoPoc":true,"Threads":7}`
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).
		Updates(map[string]interface{}{"status": rootV2.Status, "config": rootV2.Config, "current_config_version": 2}).Error; err != nil {
		t.Fatal(err)
	}
	revision := db.NewTaskConfigRevision(rootV2, 2, `{}`, `{}`, "1", "current")
	if err := db.DB.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}

	additional := []struct {
		batch   db.TaskBatch
		attempt db.SubTask
	}{
		{
			batch: db.TaskBatch{
				ID: "batch-done", TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID,
				// A completed risk-validation batch is historical evidence and must
				// not block retrying unrelated failed asset batches after rule drift.
				Sequence: 1, Kind: "risk_validation", TargetType: "risk_validation", Targets: `["https://done.test"]`, TargetCount: 1,
				Status: "Done", ControlState: string(db.BatchControlActive), ConfigVersion: 1, RuleVersion: "rules-v1",
				Priority: 1, TimeoutSec: 60, CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: "batch-done-attempt-1", CreatedBy: "1",
			},
			attempt: db.SubTask{ID: "batch-done-attempt-1", TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID, BatchID: "batch-done", AttemptNo: 1, Trigger: db.AttemptTriggerInitial, Status: "Done", ConfigVersion: 1, RuleVersion: "rules-v1"},
		},
		{
			batch: db.TaskBatch{
				ID: "batch-stopped", TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID,
				Sequence: 2, Kind: "asset_scan", TargetType: "url", Targets: `["https://stopped.test"]`, TargetCount: 1,
				Status: "Cancelled", ControlState: string(db.BatchControlStopped), ConfigVersion: 1, RuleVersion: "rules-v1",
				Priority: 1, TimeoutSec: 60, CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: "batch-stopped-attempt-1", CreatedBy: "1",
			},
			attempt: db.SubTask{ID: "batch-stopped-attempt-1", TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID, BatchID: "batch-stopped", AttemptNo: 1, Trigger: db.AttemptTriggerInitial, Status: "Cancelled", ConfigVersion: 1, RuleVersion: "rules-v1"},
		},
	}
	for _, item := range additional {
		if err := db.DB.Create(&item.batch).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.DB.Create(&item.attempt).Error; err != nil {
			t.Fatal(err)
		}
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+seed.root.ID+"/retry", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: seed.root.ID}}
	retryTask(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var failedAttempts, doneAttempts, stoppedAttempts []db.SubTask
	db.DB.Where("batch_id = ?", seed.batch.ID).Order("attempt_no asc").Find(&failedAttempts)
	db.DB.Where("batch_id = ?", "batch-done").Order("attempt_no asc").Find(&doneAttempts)
	db.DB.Where("batch_id = ?", "batch-stopped").Order("attempt_no asc").Find(&stoppedAttempts)
	if len(failedAttempts) != 2 || len(stoppedAttempts) != 2 || len(doneAttempts) != 1 {
		t.Fatalf("unexpected retry fanout: failed=%d stopped=%d done=%d", len(failedAttempts), len(stoppedAttempts), len(doneAttempts))
	}
	for _, attempt := range []db.SubTask{failedAttempts[1], stoppedAttempts[1]} {
		if attempt.Trigger != db.AttemptTriggerManualRetry || attempt.ConfigVersion != 2 {
			t.Fatalf("retry did not bind current snapshots: %+v", attempt)
		}
	}
	queuedIDs := map[string]bool{}
	for index := 0; index < 2; index++ {
		queued, _, err := queue.TryPopTask(t.Context(), "agent-task-retry")
		if err != nil || queued == nil {
			t.Fatalf("retry queue pop %d: task=%+v err=%v", index, queued, err)
		}
		queuedIDs[queued.TaskId] = true
	}
	if !queuedIDs[failedAttempts[1].ID] || !queuedIDs[stoppedAttempts[1].ID] {
		t.Fatalf("retried attempts missing from queue: %+v", queuedIDs)
	}
	var audit db.TaskAudit
	if err := db.DB.First(&audit, "root_task_id = ? AND action = ?", seed.root.ID, "retry").Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(audit.Details, `"retried_batches":2`) || !strings.Contains(audit.Details, `"force_retest":true`) {
		t.Fatalf("retry audit mismatch: %+v", audit)
	}
}

func TestRetryTaskIdempotencyReplayDoesNotMutateOrRequireQueue(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).Update("status", "Failed").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.AutoMigrate(&db.TaskRetryIdempotency{}); err != nil {
		t.Fatal(err)
	}
	queue := withBatchTestQueue(t)
	first, recorder := retryIdempotentTaskRequest(t, seed.root.ID, "retry-replay-key")
	if recorder.Code != http.StatusOK || first.Replayed || first.RetriedBatches != 1 {
		t.Fatalf("first retry status=%d response=%+v body=%s", recorder.Code, first, recorder.Body.String())
	}
	var attemptsBefore, auditsBefore, ledgerBefore int64
	db.DB.Model(&db.SubTask{}).Where("root_task_id = ?", seed.root.ID).Count(&attemptsBefore)
	db.DB.Model(&db.TaskAudit{}).Where("root_task_id = ? AND action = ?", seed.root.ID, "retry").Count(&auditsBefore)
	db.DB.Model(&db.TaskRetryIdempotency{}).Where("root_task_id = ?", seed.root.ID).Count(&ledgerBefore)
	routerRuntime().TaskQueue = nil // replay must not enqueue or require delivery infrastructure.
	second, recorder := retryIdempotentTaskRequest(t, seed.root.ID, "retry-replay-key")
	routerRuntime().TaskQueue = queue
	if recorder.Code != http.StatusOK || !second.Replayed || second.RetriedBatches != first.RetriedBatches {
		t.Fatalf("replay status=%d response=%+v body=%s", recorder.Code, second, recorder.Body.String())
	}
	var attemptsAfter, auditsAfter, ledgerAfter int64
	db.DB.Model(&db.SubTask{}).Where("root_task_id = ?", seed.root.ID).Count(&attemptsAfter)
	db.DB.Model(&db.TaskAudit{}).Where("root_task_id = ? AND action = ?", seed.root.ID, "retry").Count(&auditsAfter)
	db.DB.Model(&db.TaskRetryIdempotency{}).Where("root_task_id = ?", seed.root.ID).Count(&ledgerAfter)
	if attemptsAfter != attemptsBefore || auditsAfter != auditsBefore || ledgerAfter != ledgerBefore {
		t.Fatalf("replay mutated attempts=%d/%d audits=%d/%d ledger=%d/%d", attemptsAfter, attemptsBefore, auditsAfter, auditsBefore, ledgerAfter, ledgerBefore)
	}
	var retriedAttempt db.SubTask
	if err := db.DB.Where("root_task_id = ? AND attempt_no = ?", seed.root.ID, 2).First(&retriedAttempt).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Model(&db.SubTask{}).Where("id = ?", retriedAttempt.ID).Update("status", subTaskStatusDispatching).Error; err != nil {
		t.Fatal(err)
	}
	projected, recorder := retryIdempotentTaskRequest(t, seed.root.ID, "retry-replay-key")
	if recorder.Code != http.StatusOK || !projected.Replayed || projected.DispatchPending != 1 {
		t.Fatalf("replay did not project current pending delivery: status=%d response=%+v", recorder.Code, projected)
	}
}

func TestRetryTaskIdempotencyRejectsInvalidKeyAndRollsBackQueueOrAuditFailures(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).Update("status", "Failed").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.AutoMigrate(&db.TaskRetryIdempotency{}); err != nil {
		t.Fatal(err)
	}
	ctx, invalid := newTenantContextWithRole(http.MethodPost, "/tasks/"+seed.root.ID+"/retry", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: seed.root.ID}}
	ctx.Request.Header.Set("Idempotency-Key", "bad key")
	retryTask(ctx)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid key status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	_, unavailable := retryIdempotentTaskRequest(t, seed.root.ID, "retry-queue-key")
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("queue unavailable status=%d body=%s", unavailable.Code, unavailable.Body.String())
	}
	var attempts, audits, ledgers int64
	db.DB.Model(&db.SubTask{}).Where("root_task_id = ?", seed.root.ID).Count(&attempts)
	db.DB.Model(&db.TaskAudit{}).Where("root_task_id = ?", seed.root.ID).Count(&audits)
	db.DB.Model(&db.TaskRetryIdempotency{}).Where("root_task_id = ?", seed.root.ID).Count(&ledgers)
	if attempts != 1 || audits != 0 || ledgers != 0 {
		t.Fatalf("queue failure mutated attempts=%d audits=%d ledgers=%d", attempts, audits, ledgers)
	}
	queue := withBatchTestQueue(t)
	const callbackName = "test:reject_task_retry_audit"
	if err := db.DB.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "TaskAudit" {
			tx.AddError(errors.New("forced task retry audit failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	_, failed := retryIdempotentTaskRequest(t, seed.root.ID, "retry-audit-key")
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure status=%d body=%s", failed.Code, failed.Body.String())
	}
	if err := db.DB.Callback().Create().Remove(callbackName); err != nil {
		t.Fatal(err)
	}
	db.DB.Model(&db.SubTask{}).Where("root_task_id = ?", seed.root.ID).Count(&attempts)
	db.DB.Model(&db.TaskAudit{}).Where("root_task_id = ?", seed.root.ID).Count(&audits)
	db.DB.Model(&db.TaskRetryIdempotency{}).Where("root_task_id = ?", seed.root.ID).Count(&ledgers)
	if attempts != 1 || audits != 0 || ledgers != 0 {
		t.Fatalf("audit failure mutated attempts=%d audits=%d ledgers=%d", attempts, audits, ledgers)
	}
	success, recorder := retryIdempotentTaskRequest(t, seed.root.ID, "retry-audit-key")
	if recorder.Code != http.StatusOK || success.Replayed || success.RetriedBatches != 1 {
		t.Fatalf("retry after rollback status=%d response=%+v", recorder.Code, success)
	}
	_ = queue
}

func TestRetryTaskIdempotencyRejectsDifferentRequestHashWithoutMutation(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).Update("status", "Failed").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.AutoMigrate(&db.TaskRetryIdempotency{}); err != nil {
		t.Fatal(err)
	}
	const key = "retry-conflict-key"
	hash, err := buildTaskRetryRequestHash(canonicalTaskRetryRequest{TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID, OperatorID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	// This represents a prior version of the retry request under the same key.
	// The endpoint must reject it before preparing an Attempt or writing audit.
	differentHash := strings.Repeat("0", 64)
	if differentHash == hash {
		differentHash = strings.Repeat("1", 64)
	}
	if _, err := db.RecordTaskRetryIdempotency(db.DB, db.TaskRetryIdempotencyDraft{
		TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID, OperatorID: "1", Operation: taskRetryIdempotencyOperation,
		IdempotencyKey: key, RequestHash: differentHash, BeforeStatus: "Failed", AfterStatus: "Running", AttemptIDs: []string{"prior-attempt"},
	}); err != nil {
		t.Fatal(err)
	}
	withBatchTestQueue(t)
	_, recorder := retryIdempotentTaskRequest(t, seed.root.ID, key)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"idempotency_conflict"`) {
		t.Fatalf("changed retry request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var attempts, audits, ledgers int64
	db.DB.Model(&db.SubTask{}).Where("root_task_id = ?", seed.root.ID).Count(&attempts)
	db.DB.Model(&db.TaskAudit{}).Where("root_task_id = ?", seed.root.ID).Count(&audits)
	db.DB.Model(&db.TaskRetryIdempotency{}).Where("root_task_id = ?", seed.root.ID).Count(&ledgers)
	if attempts != 1 || audits != 0 || ledgers != 1 {
		t.Fatalf("conflict mutated attempts=%d audits=%d ledgers=%d", attempts, audits, ledgers)
	}
}

func TestTaskRetryIdempotencyRaceSentinelRollsBackTransaction(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	if err := db.DB.AutoMigrate(&db.TaskRetryIdempotency{}); err != nil {
		t.Fatal(err)
	}
	const key = "retry-race-key"
	hash, err := buildTaskRetryRequestHash(canonicalTaskRetryRequest{TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID, OperatorID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	draft := db.TaskRetryIdempotencyDraft{
		TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID, OperatorID: "1", Operation: taskRetryIdempotencyOperation,
		IdempotencyKey: key, RequestHash: hash, BeforeStatus: "Failed", AfterStatus: "Running", AttemptIDs: []string{"race-attempt"},
	}
	if _, err := db.RecordTaskRetryIdempotency(db.DB, draft); err != nil {
		t.Fatal(err)
	}
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&db.TaskAudit{TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID, OperatorID: "1", Action: "retry", BeforeStatus: "Failed", AfterStatus: "Running", Details: `{}`}).Error; err != nil {
			return err
		}
		result, err := db.RecordTaskRetryIdempotencyTx(tx, draft)
		if err != nil {
			return err
		}
		return requireFreshTaskRetryIdempotency(result)
	})
	if !errors.Is(err, errTaskRetryIdempotencyRace) {
		t.Fatalf("race transaction error=%v", err)
	}
	var audits, ledgers int64
	db.DB.Model(&db.TaskAudit{}).Where("root_task_id = ?", seed.root.ID).Count(&audits)
	db.DB.Model(&db.TaskRetryIdempotency{}).Where("root_task_id = ?", seed.root.ID).Count(&ledgers)
	if audits != 0 || ledgers != 1 {
		t.Fatalf("race transaction committed audit=%d ledgers=%d", audits, ledgers)
	}
}

func TestRetryTaskEnforcesProjectOwnership(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	withBatchTestQueue(t)
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).Update("status", "Failed").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Model(&db.Project{}).Where("id = ?", seed.project.ID).Update("owner_user_id", "99").Error; err != nil {
		t.Fatal(err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+seed.root.ID+"/retry", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: seed.root.ID}}
	retryTask(ctx)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("private project retry=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var attempts int64
	db.DB.Model(&db.SubTask{}).Where("batch_id = ?", seed.batch.ID).Count(&attempts)
	if attempts != 1 {
		t.Fatalf("rejected retry appended attempts: %d", attempts)
	}
	var audits int64
	db.DB.Model(&db.TaskAudit{}).Where("root_task_id = ? AND action = ?", seed.root.ID, "retry").Count(&audits)
	if audits != 0 {
		t.Fatalf("rejected retry wrote audit: %d", audits)
	}
}
