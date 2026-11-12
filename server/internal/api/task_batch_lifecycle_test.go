package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/server/internal/scheduler"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type seededBatchLifecycle struct {
	project db.Project
	root    db.RootTask
	batch   db.TaskBatch
	attempt db.SubTask
}

func seedBatchLifecycle(t *testing.T, status string) seededBatchLifecycle {
	t.Helper()
	store := setupAITestDB(t)
	seed := seededBatchLifecycle{
		project: db.Project{ID: "project-batch-control", TenantID: "default", OwnerUserID: "1", Status: "active", Scope: `[]`, SeedTargets: `[]`},
		root: db.RootTask{
			ID: "task-batch-control", TenantID: "default", ProjectID: "project-batch-control", UserID: "1",
			Status: "Running", Config: `{"NoPoc":true}`, CurrentConfigVersion: 1,
			TotalChunks: 1, TotalTargets: 1,
		},
		batch: db.TaskBatch{
			ID: "batch-control", TenantID: "default", ProjectID: "project-batch-control", RootTaskID: "task-batch-control",
			Sequence: 0, Kind: "asset_scan", TargetType: "url", Targets: `["https://one.test"]`, TargetCount: 1,
			Status: status, ControlState: string(db.BatchControlActive), ConfigVersion: 1, RuleVersion: "rules-v1",
			Priority: 1, TimeoutSec: 60, CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: "batch-control-attempt-1", CreatedBy: "1",
		},
		attempt: db.SubTask{
			ID: "batch-control-attempt-1", TenantID: "default", ProjectID: "project-batch-control", RootTaskID: "task-batch-control",
			BatchID: "batch-control", AttemptNo: 1, Trigger: db.AttemptTriggerInitial, ChunkTargets: `["https://one.test"]`,
			Status: status, Config: `{"NoPoc":true}`, Priority: 1, TimeoutSec: 60, MaxRetry: 3,
			ConfigVersion: 1, RuleVersion: "rules-v1",
		},
	}
	if status == "Running" {
		seed.attempt.AgentID = "agent-control"
		seed.attempt.StreamMsgID = "delivery-control"
		now := time.Now()
		seed.attempt.StartedAt = &now
	}
	for _, value := range []interface{}{&seed.project, &seed.root, &seed.batch, &seed.attempt} {
		if err := store.Create(value).Error; err != nil {
			t.Fatalf("seed lifecycle row: %v", err)
		}
	}
	revision := db.NewTaskConfigRevision(seed.root, 1, `{}`, `{}`, "1", "initial")
	if err := store.Create(&revision).Error; err != nil {
		t.Fatalf("seed config revision: %v", err)
	}
	return seed
}

func withBatchTestQueue(t *testing.T) *scheduler.TaskQueue {
	t.Helper()
	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() {
		queue.Close()
		routerRuntime().TaskQueue = oldQueue
	})
	return queue
}

func batchMutationContext(method, taskID, batchID, action string) (*gin.Context, *httptest.ResponseRecorder) {
	ctx, recorder := newTenantContextWithRole(method, "/tasks/"+taskID+"/batches/"+batchID+"/"+action, "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: taskID}, {Key: "batch_id", Value: batchID}}
	return ctx, recorder
}

func TestPauseQueuedBatchIsIdempotentAndAudited(t *testing.T) {
	seed := seedBatchLifecycle(t, "Pending")
	withBatchTestQueue(t)

	ctx, recorder := batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "pause")
	pauseTaskBatch(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("pause status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.First(&seed.attempt, "id = ?", seed.attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.First(&seed.batch, "id = ?", seed.batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if seed.attempt.Status != "Paused" || seed.batch.Status != "Paused" || db.CanonicalBatchControlState(seed.batch.ControlState) != db.BatchControlPaused {
		t.Fatalf("queued batch not paused: attempt=%+v batch=%+v", seed.attempt, seed.batch)
	}
	var audit db.TaskAudit
	if err := db.DB.First(&audit, "batch_id = ? AND action = ?", seed.batch.ID, "batch_pause").Error; err != nil {
		t.Fatal(err)
	}
	if audit.OperatorID != "1" || audit.AttemptID != seed.attempt.ID || !strings.Contains(audit.Details, `"automatic_retry":false`) {
		t.Fatalf("unexpected pause audit: %+v", audit)
	}

	ctx, recorder = batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "pause")
	pauseTaskBatch(ctx)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"already_paused":true`) {
		t.Fatalf("repeated pause=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var auditCount int64
	db.DB.Model(&db.TaskAudit{}).Where("batch_id = ? AND action = ?", seed.batch.ID, "batch_pause").Count(&auditCount)
	if auditCount != 1 {
		t.Fatalf("repeated pause wrote another audit: %d", auditCount)
	}
}

func TestResumeQueuedBatchReusesUnclaimedAttempt(t *testing.T) {
	seed := seedBatchLifecycle(t, "Pending")
	queue := withBatchTestQueue(t)

	ctx, recorder := batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "pause")
	pauseTaskBatch(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("pause status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "resume")
	resumeTaskBatch(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("resume status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	var attempts []db.SubTask
	if err := db.DB.Where("batch_id = ?", seed.batch.ID).Order("attempt_no asc").Find(&attempts).Error; err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].ID != seed.attempt.ID || attempts[0].Status != "Pending" {
		t.Fatalf("unclaimed resume should reuse the original attempt: %+v", attempts)
	}
	if err := db.DB.First(&seed.batch, "id = ?", seed.batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if seed.batch.LatestAttemptID != seed.attempt.ID || seed.batch.AttemptCount != 1 || db.CanonicalBatchControlState(seed.batch.ControlState) != db.BatchControlActive {
		t.Fatalf("resume changed stable batch history unexpectedly: %+v", seed.batch)
	}
	queued, _, err := queue.TryPopTask(t.Context(), "agent-resume-unclaimed")
	if err != nil || queued == nil || queued.TaskId != seed.attempt.ID {
		t.Fatalf("resumed unclaimed attempt not queued: task=%+v err=%v", queued, err)
	}
}

func TestRunningBatchPauseBlocksAutomaticRetryAndResumeAppendsAttempt(t *testing.T) {
	seed := seedBatchLifecycle(t, "Running")
	queue := withBatchTestQueue(t)

	ctx, recorder := batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "pause")
	pauseTaskBatch(ctx)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"running_attempt_continues":true`) {
		t.Fatalf("pause running=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.First(&seed.attempt, "id = ?", seed.attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if seed.attempt.Status != "Running" {
		t.Fatalf("claimed attempt was interrupted by pause: %s", seed.attempt.Status)
	}

	finished := time.Now()
	if err := db.DB.Model(&db.SubTask{}).Where("id = ?", seed.attempt.ID).
		Updates(map[string]interface{}{"status": "Failed", "failure_reason": "simulated failure", "finished_at": finished}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Model(&db.TaskBatch{}).Where("id = ?", seed.batch.ID).Update("status", "Failed").Error; err != nil {
		t.Fatal(err)
	}
	seed.attempt.Status = "Failed"
	if _, retried := db.PrepareSubTaskRetry(&seed.attempt); retried {
		t.Fatal("paused batch unexpectedly entered automatic retry")
	}

	ctx, recorder = batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "resume")
	resumeTaskBatch(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("resume status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var attempts []db.SubTask
	if err := db.DB.Where("batch_id = ?", seed.batch.ID).Order("attempt_no asc").Find(&attempts).Error; err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 || attempts[1].Trigger != db.AttemptTriggerResume || attempts[1].ParentAttemptID != attempts[0].ID {
		t.Fatalf("resume did not append evidence-preserving attempt: %+v", attempts)
	}
	queued, _, err := queue.TryPopTask(t.Context(), "agent-resume")
	if err != nil || queued == nil || queued.TaskId != attempts[1].ID {
		t.Fatalf("resumed attempt not queued: task=%+v err=%v", queued, err)
	}
}

func TestStopRunningBatchDispatchesAgentCancellation(t *testing.T) {
	seed := seedBatchLifecycle(t, "Running")
	withBatchTestQueue(t)

	ctx, recorder := batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "stop")
	stopTaskBatch(ctx)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"cancel_pending_on_agent":true`) {
		t.Fatalf("stop running=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.First(&seed.attempt, "id = ?", seed.attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.First(&seed.batch, "id = ?", seed.batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if seed.attempt.Status != "CancelPending" || seed.batch.Status != "CancelPending" || db.CanonicalBatchControlState(seed.batch.ControlState) != db.BatchControlStopping {
		t.Fatalf("stop state mismatch: attempt=%+v batch=%+v", seed.attempt, seed.batch)
	}

	commandCtx, commandRecorder := newTenantContext(http.MethodGet, "/agents/agent-control/commands")
	commandCtx.Params = gin.Params{{Key: "id", Value: "agent-control"}}
	getAgentCommands(commandCtx)
	if commandRecorder.Code != http.StatusOK || !strings.Contains(commandRecorder.Body.String(), seed.attempt.ID) {
		t.Fatalf("Agent cancellation command missing: %d %s", commandRecorder.Code, commandRecorder.Body.String())
	}
}

func TestManualRetryUsesCurrentConfigAndReactivatesCompletedTask(t *testing.T) {
	seed := seedBatchLifecycle(t, "Done")
	queue := withBatchTestQueue(t)
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).
		Updates(map[string]interface{}{"status": "FINISHED", "current_config_version": 2, "completed_chunks": 1, "completed_targets": 1}).Error; err != nil {
		t.Fatal(err)
	}
	rootV2 := seed.root
	rootV2.CurrentConfigVersion = 2
	rootV2.Config = `{"NoPoc":true,"Threads":7}`
	revision := db.NewTaskConfigRevision(rootV2, 2, `{}`, `{}`, "1", "current")
	if err := db.DB.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}

	ctx, recorder := batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "retry")
	retryTaskBatch(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var attempts []db.SubTask
	if err := db.DB.Where("batch_id = ?", seed.batch.ID).Order("attempt_no asc").Find(&attempts).Error; err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 || attempts[1].Trigger != db.AttemptTriggerManualRetry || attempts[1].ConfigVersion != 2 {
		t.Fatalf("manual retry did not use current version: %+v", attempts)
	}
	if err := db.DB.First(&seed.root, "id = ?", seed.root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalTaskState(seed.root.Status) != db.TaskStateRunning {
		t.Fatalf("completed task was not reactivated: %s", seed.root.Status)
	}
	queued, _, err := queue.TryPopTask(t.Context(), "agent-retry")
	if err != nil || queued == nil || queued.TaskId != attempts[1].ID {
		t.Fatalf("manual retry not queued: task=%+v err=%v", queued, err)
	}
	var audit db.TaskAudit
	if err := db.DB.First(&audit, "batch_id = ? AND action = ?", seed.batch.ID, "batch_retry").Error; err != nil {
		t.Fatal(err)
	}
	if audit.AttemptID != attempts[1].ID || !strings.Contains(audit.Details, `"force_retest":true`) {
		t.Fatalf("manual retry audit mismatch: %+v", audit)
	}
}

func TestRiskValidationBatchRetryPreservesConfirmedConfigAndRejectsRuleDrift(t *testing.T) {
	for _, test := range []struct {
		name       string
		rule       string
		wantStatus int
	}{
		{name: "same rule version", rule: "rules-v1", wantStatus: http.StatusOK},
		{name: "changed rule version", rule: "rules-v2", wantStatus: http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBatchLifecycle(t, "Failed")
			withBatchTestQueue(t)
			confirmedConfig := `{"ExecutionMode":"risk_validation","RiskValidationTargets":{"https://one.test":["one.yaml"]}}`
			if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).
				Updates(map[string]interface{}{"status": "Failed", "current_config_version": 2}).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.DB.Model(&db.TaskBatch{}).Where("id = ?", seed.batch.ID).
				Updates(map[string]interface{}{"kind": "risk_validation", "target_type": "risk_validation"}).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.DB.Model(&db.SubTask{}).Where("id = ?", seed.attempt.ID).
				Updates(map[string]interface{}{"config": confirmedConfig, "max_retry": 0}).Error; err != nil {
				t.Fatal(err)
			}
			rootV2 := seed.root
			rootV2.CurrentConfigVersion = 2
			rootV2.Config = `{"NoPoc":true}`
			revision := db.NewTaskConfigRevision(rootV2, 2, `{}`, `{}`, "1", "new asset config")
			if err := db.DB.Create(&revision).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.DB.Create(&db.SystemConfig{Key: "rule_version", Value: test.rule}).Error; err != nil {
				t.Fatal(err)
			}

			ctx, recorder := batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "retry")
			retryTaskBatch(ctx)
			if recorder.Code != test.wantStatus {
				t.Fatalf("retry status=%d body=%s want=%d", recorder.Code, recorder.Body.String(), test.wantStatus)
			}
			var attempts []db.SubTask
			if err := db.DB.Where("batch_id = ?", seed.batch.ID).Order("attempt_no asc").Find(&attempts).Error; err != nil {
				t.Fatal(err)
			}
			if test.wantStatus == http.StatusConflict {
				if len(attempts) != 1 {
					t.Fatalf("rule drift created a retry: %+v", attempts)
				}
				return
			}
			if len(attempts) != 2 || attempts[1].Config != confirmedConfig || attempts[1].ConfigVersion != 1 || attempts[1].RuleVersion != "rules-v1" {
				t.Fatalf("risk retry lost confirmed snapshot: %+v", attempts)
			}
		})
	}
}

func batchRetryIdempotentRequest(t *testing.T, taskID, batchID, key string) (taskBatchRetryResponseInput, *httptest.ResponseRecorder) {
	t.Helper()
	ctx, recorder := batchMutationContext(http.MethodPost, taskID, batchID, "retry")
	if key != "" {
		ctx.Request.Header.Set("Idempotency-Key", key)
	}
	retryTaskBatch(ctx)
	var response taskBatchRetryResponseInput
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode batch retry response: %v", err)
		}
	}
	return response, recorder
}

func TestTaskBatchRetryIdempotencyReplayDoesNotRequireQueueOrRepeatAudit(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).Update("status", "Failed").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.AutoMigrate(&db.TaskBatchRetryIdempotency{}); err != nil {
		t.Fatal(err)
	}
	queue := withBatchTestQueue(t)
	first, recorder := batchRetryIdempotentRequest(t, seed.root.ID, seed.batch.ID, "batch-retry-key")
	if recorder.Code != http.StatusOK || first.Replayed || first.AttemptNo != 2 {
		t.Fatalf("first retry=%d response=%+v body=%s", recorder.Code, first, recorder.Body.String())
	}
	var attemptsBefore, auditsBefore, ledgerBefore int64
	db.DB.Model(&db.SubTask{}).Where("batch_id = ?", seed.batch.ID).Count(&attemptsBefore)
	db.DB.Model(&db.TaskAudit{}).Where("batch_id = ? AND action = ?", seed.batch.ID, "batch_retry").Count(&auditsBefore)
	db.DB.Model(&db.TaskBatchRetryIdempotency{}).Where("batch_id = ?", seed.batch.ID).Count(&ledgerBefore)
	routerRuntime().TaskQueue = nil
	second, recorder := batchRetryIdempotentRequest(t, seed.root.ID, seed.batch.ID, "batch-retry-key")
	routerRuntime().TaskQueue = queue
	if recorder.Code != http.StatusOK || !second.Replayed || second.AttemptID != first.AttemptID || second.AttemptNo != first.AttemptNo {
		t.Fatalf("replay=%d response=%+v body=%s", recorder.Code, second, recorder.Body.String())
	}
	var attemptsAfter, auditsAfter, ledgerAfter int64
	db.DB.Model(&db.SubTask{}).Where("batch_id = ?", seed.batch.ID).Count(&attemptsAfter)
	db.DB.Model(&db.TaskAudit{}).Where("batch_id = ? AND action = ?", seed.batch.ID, "batch_retry").Count(&auditsAfter)
	db.DB.Model(&db.TaskBatchRetryIdempotency{}).Where("batch_id = ?", seed.batch.ID).Count(&ledgerAfter)
	if attemptsAfter != attemptsBefore || auditsAfter != auditsBefore || ledgerAfter != ledgerBefore {
		t.Fatalf("replay mutated attempts=%d/%d audits=%d/%d ledger=%d/%d", attemptsAfter, attemptsBefore, auditsAfter, auditsBefore, ledgerAfter, ledgerBefore)
	}
	if err := db.DB.Model(&db.SubTask{}).Where("id = ?", first.AttemptID).Update("status", subTaskStatusDispatching).Error; err != nil {
		t.Fatal(err)
	}
	projected, recorder := batchRetryIdempotentRequest(t, seed.root.ID, seed.batch.ID, "batch-retry-key")
	if recorder.Code != http.StatusOK || !projected.Replayed || projected.DispatchPending != 1 {
		t.Fatalf("replay dispatch projection=%d response=%+v", recorder.Code, projected)
	}
}

func TestTaskBatchRetryIdempotencyRejectsInvalidKeyAndQueueFailureCloses(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	if err := db.DB.AutoMigrate(&db.TaskBatchRetryIdempotency{}); err != nil {
		t.Fatal(err)
	}
	_, invalid := batchRetryIdempotentRequest(t, seed.root.ID, seed.batch.ID, "bad key")
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "invalid_idempotency_key") {
		t.Fatalf("invalid key=%d body=%s", invalid.Code, invalid.Body.String())
	}
	_, unavailable := batchRetryIdempotentRequest(t, seed.root.ID, seed.batch.ID, "batch-queue-key")
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("queue unavailable=%d body=%s", unavailable.Code, unavailable.Body.String())
	}
	var attempts, audits, ledgers int64
	db.DB.Model(&db.SubTask{}).Where("batch_id = ?", seed.batch.ID).Count(&attempts)
	db.DB.Model(&db.TaskAudit{}).Where("batch_id = ? AND action = ?", seed.batch.ID, "batch_retry").Count(&audits)
	db.DB.Model(&db.TaskBatchRetryIdempotency{}).Where("batch_id = ?", seed.batch.ID).Count(&ledgers)
	if attempts != 1 || audits != 0 || ledgers != 0 {
		t.Fatalf("queue failure mutated attempts=%d audits=%d ledgers=%d", attempts, audits, ledgers)
	}
}

func TestTaskBatchRetryIdempotencyDoesNotReplayArchivedScope(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	if err := db.DB.AutoMigrate(&db.TaskBatchRetryIdempotency{}); err != nil {
		t.Fatal(err)
	}
	queue := withBatchTestQueue(t)
	first, recorder := batchRetryIdempotentRequest(t, seed.root.ID, seed.batch.ID, "batch-archive-key")
	if recorder.Code != http.StatusOK || first.Replayed {
		t.Fatalf("initial retry=%d body=%s", recorder.Code, recorder.Body.String())
	}
	now := time.Now().UTC()
	if err := db.DB.Model(&db.TaskBatch{}).Where("id = ?", seed.batch.ID).Update("archived_at", now).Error; err != nil {
		t.Fatal(err)
	}
	replay, recorder := batchRetryIdempotentRequest(t, seed.root.ID, seed.batch.ID, "batch-archive-key")
	if recorder.Code != http.StatusConflict || replay.Replayed {
		t.Fatalf("archived replay=%d response=%+v body=%s", recorder.Code, replay, recorder.Body.String())
	}
	var attempts, audits, ledgers int64
	db.DB.Model(&db.SubTask{}).Where("batch_id = ?", seed.batch.ID).Count(&attempts)
	db.DB.Model(&db.TaskAudit{}).Where("batch_id = ? AND action = ?", seed.batch.ID, "batch_retry").Count(&audits)
	db.DB.Model(&db.TaskBatchRetryIdempotency{}).Where("batch_id = ?", seed.batch.ID).Count(&ledgers)
	if attempts != 2 || audits != 1 || ledgers != 1 {
		t.Fatalf("archived replay mutated attempts=%d audits=%d ledgers=%d", attempts, audits, ledgers)
	}
	queued, _, err := queue.TryPopTask(t.Context(), "archive-retry-agent")
	if err != nil || queued == nil || queued.TaskId != first.AttemptID {
		t.Fatalf("initial dispatch missing task=%+v err=%v", queued, err)
	}
	queued, _, err = queue.TryPopTask(t.Context(), "archive-retry-agent")
	if err != nil || queued != nil {
		t.Fatalf("archived replay dispatched task=%+v err=%v", queued, err)
	}
}

func TestTaskBatchRetryIdempotencyConflictAndAuditFailureRollBack(t *testing.T) {
	seed := seedBatchLifecycle(t, "Failed")
	if err := db.DB.AutoMigrate(&db.TaskBatchRetryIdempotency{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordTaskBatchRetryIdempotencyTx(db.DB, db.TaskBatchRetryIdempotencyDraft{
		TenantID: seed.root.TenantID, ProjectID: seed.root.ProjectID, RootTaskID: seed.root.ID, BatchID: seed.batch.ID, OperatorID: "1", Operation: taskBatchRetryIdempotencyOperation,
		IdempotencyKey: "batch-conflict-key", RequestHash: strings.Repeat("a", 64), AttemptID: seed.attempt.ID, AttemptNo: 1, ConfigVersion: 1, ConfigHash: taskBatchRetryConfigHash(seed.attempt.Config), RuleVersion: seed.attempt.RuleVersion, BeforeStatus: "Failed", AfterStatus: "Dispatching",
	}); err != nil {
		t.Fatal(err)
	}
	withBatchTestQueue(t)
	_, conflict := batchRetryIdempotentRequest(t, seed.root.ID, seed.batch.ID, "batch-conflict-key")
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), "idempotency_conflict") {
		t.Fatalf("conflict=%d body=%s", conflict.Code, conflict.Body.String())
	}
	const callbackName = "test:reject_task_batch_retry_audit"
	if err := db.DB.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "TaskAudit" {
			tx.AddError(errors.New("forced batch retry audit failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	_, failed := batchRetryIdempotentRequest(t, seed.root.ID, seed.batch.ID, "batch-audit-key")
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure=%d body=%s", failed.Code, failed.Body.String())
	}
	if err := db.DB.Callback().Create().Remove(callbackName); err != nil {
		t.Fatal(err)
	}
	var attempts, audits, ledgers int64
	db.DB.Model(&db.SubTask{}).Where("batch_id = ?", seed.batch.ID).Count(&attempts)
	db.DB.Model(&db.TaskAudit{}).Where("batch_id = ? AND action = ?", seed.batch.ID, "batch_retry").Count(&audits)
	db.DB.Model(&db.TaskBatchRetryIdempotency{}).Where("batch_id = ?", seed.batch.ID).Count(&ledgers)
	if attempts != 1 || audits != 0 || ledgers != 1 {
		t.Fatalf("audit rollback mutated attempts=%d audits=%d ledgers=%d", attempts, audits, ledgers)
	}
}

func TestArchiveBatchPreservesResultsAndExcludesProgress(t *testing.T) {
	seed := seedBatchLifecycle(t, "Done")
	withBatchTestQueue(t)
	if err := db.DB.Model(&db.RootTask{}).Where("id = ?", seed.root.ID).
		Updates(map[string]interface{}{"status": "FINISHED", "completed_chunks": 1, "completed_targets": 1}).Error; err != nil {
		t.Fatal(err)
	}
	asset := db.Asset{TenantID: "default", RootTaskID: seed.root.ID, TaskID: seed.attempt.ID, Target: "https://one.test"}
	if err := db.DB.Create(&asset).Error; err != nil {
		t.Fatal(err)
	}

	ctx, recorder := batchMutationContext(http.MethodDelete, seed.root.ID, seed.batch.ID, "archive")
	archiveTaskBatch(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("archive status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := db.DB.First(&seed.batch, "id = ?", seed.batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if seed.batch.ArchivedAt == nil {
		t.Fatal("batch archived_at was not set")
	}
	if err := db.DB.First(&seed.root, "id = ?", seed.root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if seed.root.TotalChunks != 0 || seed.root.TotalTargets != 0 || seed.root.CompletedChunks != 0 || seed.root.CompletedTargets != 0 {
		t.Fatalf("archived batch remained in progress: %+v", seed.root)
	}
	var assetCount int64
	db.DB.Model(&db.Asset{}).Where("root_task_id = ?", seed.root.ID).Count(&assetCount)
	if assetCount != 1 {
		t.Fatalf("archive deleted results: %d", assetCount)
	}

	listCtx, listRecorder := newTenantContextWithRole(http.MethodGet, "/tasks/"+seed.root.ID+"/batches", "viewer", "1")
	listCtx.Params = gin.Params{{Key: "id", Value: seed.root.ID}}
	listTaskBatches(listCtx)
	if listRecorder.Code != http.StatusOK || !strings.Contains(listRecorder.Body.String(), `"items":[]`) {
		t.Fatalf("archived batch appeared in active list: %d %s", listRecorder.Code, listRecorder.Body.String())
	}
	listCtx, listRecorder = newTenantContextWithRole(http.MethodGet, "/tasks/"+seed.root.ID+"/batches?archived=only", "viewer", "1")
	listCtx.Params = gin.Params{{Key: "id", Value: seed.root.ID}}
	listCtx.Request = httptest.NewRequest(http.MethodGet, "/tasks/"+seed.root.ID+"/batches?archived=only", nil)
	listTaskBatches(listCtx)
	var response struct {
		Items []taskBatchSummary `json:"items"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &response); err != nil || len(response.Items) != 1 || response.Items[0].ArchivedAt == nil {
		t.Fatalf("archived batch history missing: err=%v body=%s", err, listRecorder.Body.String())
	}
}

func TestBatchMutationEnforcesProjectOwnership(t *testing.T) {
	seed := seedBatchLifecycle(t, "Pending")
	withBatchTestQueue(t)
	if err := db.DB.Model(&db.Project{}).Where("id = ?", seed.project.ID).Update("owner_user_id", "99").Error; err != nil {
		t.Fatal(err)
	}
	ctx, recorder := batchMutationContext(http.MethodPost, seed.root.ID, seed.batch.ID, "pause")
	pauseTaskBatch(ctx)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("private project batch mutation=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var auditCount int64
	db.DB.Model(&db.TaskAudit{}).Where("batch_id = ?", seed.batch.ID).Count(&auditCount)
	if auditCount != 0 {
		t.Fatalf("rejected batch mutation wrote audit: %d", auditCount)
	}
}
