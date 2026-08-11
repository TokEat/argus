package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
	"gorm.io/gorm"
)

type taskAppendIdempotencyResponse struct {
	Status            string            `json:"status"`
	NewSubTasks       int               `json:"new_subtasks"`
	NewBatches        int               `json:"new_batches"`
	NewTargets        int               `json:"new_targets"`
	DuplicateTargets  int               `json:"duplicate_targets"`
	ConfigVersion     int               `json:"config_version"`
	TotalChunks       int               `json:"total_chunks"`
	TotalTargets      int               `json:"total_targets"`
	ProjectScopeAdded int               `json:"project_scope_added"`
	ProjectSeedsAdded int               `json:"project_seeds_added"`
	Dispatched        int               `json:"dispatched"`
	DispatchPending   int               `json:"dispatch_pending"`
	TargetSummary     taskTargetSummary `json:"target_summary"`
	BatchProfile      batchProfile      `json:"batch_profile"`
	BatchSummary      struct {
		TotalTargets int `json:"total_targets"`
		TotalBatches int `json:"total_batches"`
	} `json:"batch_summary"`
	Replayed bool `json:"replayed"`
}

func appendResponseWithoutReplay(response taskAppendIdempotencyResponse) taskAppendIdempotencyResponse {
	response.Replayed = false
	return response
}

func seedTaskAppendIdempotencyFixture(t *testing.T, store *gorm.DB, suffix, status string) (db.Project, db.RootTask) {
	t.Helper()
	if err := store.AutoMigrate(&db.TaskAppendIdempotency{}); err != nil {
		t.Fatalf("migrate append idempotency: %v", err)
	}
	project := db.Project{ID: "project-append-" + suffix, TenantID: "default", OwnerUserID: "1", Status: "active", Scope: `[]`, SeedTargets: `[]`}
	root := db.RootTask{ID: "task-append-" + suffix, TenantID: "default", ProjectID: project.ID, UserID: "1", Status: status, Config: `{}`, OriginalTargets: `[]`, CurrentConfigVersion: 1}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed append project: %v", err)
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed append task: %v", err)
	}
	revision := db.NewTaskConfigRevision(root, 1, `{}`, `{}`, "1", "initial")
	if err := store.Create(&revision).Error; err != nil {
		t.Fatalf("seed append config revision: %v", err)
	}
	return project, root
}

func appendIdempotentTaskRequest(t *testing.T, taskID, body, key string) (taskAppendIdempotencyResponse, *httptest.ResponseRecorder) {
	t.Helper()
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+taskID+"/append", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: taskID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+taskID+"/append", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	if key != "" {
		ctx.Request.Header.Set("Idempotency-Key", key)
	}
	appendTargets(ctx)
	var response taskAppendIdempotencyResponse
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode append response: %v", err)
		}
	}
	return response, recorder
}

func TestAppendTargetsIdempotencyReplayConflictAndNoKeyCompatibility(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.TaskAppendIdempotency{}); err != nil {
		t.Fatalf("migrate append idempotency: %v", err)
	}
	project := db.Project{ID: "project-append-idempotency", TenantID: "default", OwnerUserID: "1", Status: "active", Scope: `[]`, SeedTargets: `[]`}
	root := db.RootTask{ID: "task-append-idempotency", TenantID: "default", ProjectID: project.ID, UserID: "1", Status: "Finished", Config: `{}`, CurrentConfigVersion: 1}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.TaskConfigRevision{TenantID: "default", ProjectID: project.ID, RootTaskID: root.ID, Version: 1, Config: `{}`, ConfigHash: strings.Repeat("a", 64), Priority: 1, TimeoutSec: 60, AgentSelector: `{}`, AgentSelectorRules: `{}`}).Error; err != nil {
		t.Fatal(err)
	}
	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	first, firstRecorder := appendIdempotentTaskRequest(t, root.ID, `{"targets":["10.10.0.1","https://append.example.test/"]}`, "append-key-1")
	if firstRecorder.Code != http.StatusOK || first.Replayed || first.Status != "appended" {
		t.Fatalf("first append: %d %s", firstRecorder.Code, firstRecorder.Body.String())
	}
	var beforeBatches, beforeAttempts, beforeAudits, beforeLedger int64
	store.Model(&db.TaskBatch{}).Where("root_task_id = ?", root.ID).Count(&beforeBatches)
	store.Model(&db.SubTask{}).Where("root_task_id = ?", root.ID).Count(&beforeAttempts)
	store.Model(&db.TaskAudit{}).Where("root_task_id = ? AND action = ?", root.ID, "batch_append").Count(&beforeAudits)
	store.Model(&db.TaskAppendIdempotency{}).Where("root_task_id = ?", root.ID).Count(&beforeLedger)
	if err := store.Create(&db.TaskConfigRevision{
		TenantID: "default", ProjectID: project.ID, RootTaskID: root.ID, Version: 2,
		Config: `{"Quake":true}`, ConfigHash: strings.Repeat("c", 64), Priority: 1, TimeoutSec: 60,
		AgentSelector: `{}`, AgentSelectorRules: `{}`,
	}).Error; err != nil {
		t.Fatalf("create changed config revision: %v", err)
	}
	if err := store.Model(&db.RootTask{}).Where("id = ?", root.ID).Update("current_config_version", 2).Error; err != nil {
		t.Fatalf("select changed config revision: %v", err)
	}

	routerRuntime().TaskQueue = nil // a replay must not require an available queue.
	replay, replayRecorder := appendIdempotentTaskRequest(t, root.ID, `{"targets":["HTTPS://APPEND.EXAMPLE.TEST","10.10.0.1"]}`, "append-key-1")
	routerRuntime().TaskQueue = queue
	if replayRecorder.Code != http.StatusOK || !replay.Replayed || !reflect.DeepEqual(first, appendResponseWithoutReplay(replay)) {
		t.Fatalf("replay changed result: first=%+v replay=%+v body=%s", first, replay, replayRecorder.Body.String())
	}
	var afterBatches, afterAttempts, afterAudits, afterLedger int64
	store.Model(&db.TaskBatch{}).Where("root_task_id = ?", root.ID).Count(&afterBatches)
	store.Model(&db.SubTask{}).Where("root_task_id = ?", root.ID).Count(&afterAttempts)
	store.Model(&db.TaskAudit{}).Where("root_task_id = ? AND action = ?", root.ID, "batch_append").Count(&afterAudits)
	store.Model(&db.TaskAppendIdempotency{}).Where("root_task_id = ?", root.ID).Count(&afterLedger)
	if beforeBatches != afterBatches || beforeAttempts != afterAttempts || beforeAudits != afterAudits || beforeLedger != afterLedger {
		t.Fatalf("replay mutated state")
	}

	_, conflict := appendIdempotentTaskRequest(t, root.ID, `{"targets":"10.10.0.2"}`, "append-key-1")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("different payload status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	if err := store.Model(&db.RootTask{}).Where("id = ?", root.ID).Update("current_config_version", 1).Error; err != nil {
		t.Fatalf("restore direct config revision: %v", err)
	}
	_, noKey := appendIdempotentTaskRequest(t, root.ID, `{"targets":"10.10.0.3"}`, "")
	if noKey.Code != http.StatusOK {
		t.Fatalf("legacy no-key append failed: %d %s", noKey.Code, noKey.Body.String())
	}
	unchangedFirst, unchangedFirstRecorder := appendIdempotentTaskRequest(t, root.ID, `{"targets":"10.10.0.3"}`, "unchanged-key-1")
	unchangedReplay, unchangedReplayRecorder := appendIdempotentTaskRequest(t, root.ID, `{"targets":"10.10.0.3"}`, "unchanged-key-1")
	if unchangedFirstRecorder.Code != http.StatusOK || unchangedReplayRecorder.Code != http.StatusOK || unchangedFirst.Status != "unchanged" || !unchangedReplay.Replayed {
		t.Fatalf("unchanged replay failed: first=%s replay=%s", unchangedFirstRecorder.Body.String(), unchangedReplayRecorder.Body.String())
	}
	if !reflect.DeepEqual(unchangedFirst, appendResponseWithoutReplay(unchangedReplay)) {
		t.Fatalf("unchanged replay changed response: first=%+v replay=%+v", unchangedFirst, unchangedReplay)
	}
}

func TestAppendTargetsIdempotencyReplayKeepsBusinessResultAndRefreshesDispatchProjection(t *testing.T) {
	store := setupAITestDB(t)
	_, root := seedTaskAppendIdempotencyFixture(t, store, "dispatch-projection", "Finished")
	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	first, firstRecorder := appendIdempotentTaskRequest(t, root.ID, `{"targets":"https://dispatch-projection.example.test"}`, "append-dispatch-key")
	if firstRecorder.Code != http.StatusOK || first.Replayed || first.Status != "appended" || first.Dispatched != 1 || first.DispatchPending != 0 {
		t.Fatalf("first append: status=%d response=%+v body=%s", firstRecorder.Code, first, firstRecorder.Body.String())
	}
	if err := store.Model(&db.SubTask{}).Where("root_task_id = ?", root.ID).Update("status", subTaskStatusDispatching).Error; err != nil {
		t.Fatal(err)
	}

	routerRuntime().TaskQueue = nil // replay reads current evidence and never enqueues again.
	replay, replayRecorder := appendIdempotentTaskRequest(t, root.ID, `{"targets":"HTTPS://DISPATCH-PROJECTION.EXAMPLE.TEST/"}`, "append-dispatch-key")
	routerRuntime().TaskQueue = queue
	if replayRecorder.Code != http.StatusOK || !replay.Replayed || replay.Dispatched != 0 || replay.DispatchPending != 1 {
		t.Fatalf("replay projection: status=%d response=%+v body=%s", replayRecorder.Code, replay, replayRecorder.Body.String())
	}

	first.Dispatched, first.DispatchPending = 0, 0
	replay.Dispatched, replay.DispatchPending, replay.Replayed = 0, 0, false
	if !reflect.DeepEqual(first, replay) {
		t.Fatalf("replay changed frozen business result: first=%+v replay=%+v", first, replay)
	}
}

func TestAppendTargetsRejectsInvalidOrMultipleIdempotencyKeys(t *testing.T) {
	for _, values := range [][]string{{""}, {"one", "two"}} {
		ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/nope/append", "operator", "1")
		ctx.Params = gin.Params{{Key: "id", Value: "nope"}}
		ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/nope/append", strings.NewReader(`{"targets":"10.0.0.1"}`))
		ctx.Request.Header["Idempotency-Key"] = values
		appendTargets(ctx)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("key values=%q status=%d body=%s", values, recorder.Code, recorder.Body.String())
		}
	}
}

func TestAppendTargetsIdempotencyQueueFailureLeavesNoLedgerAndCanRetry(t *testing.T) {
	store := setupAITestDB(t)
	_, root := seedTaskAppendIdempotencyFixture(t, store, "queue-failure", "Finished")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = nil
	t.Cleanup(func() { routerRuntime().TaskQueue = oldQueue })

	_, failed := appendIdempotentTaskRequest(t, root.ID, `{"targets":"https://queue-retry.example.test"}`, "append-queue-key")
	if failed.Code != http.StatusServiceUnavailable {
		t.Fatalf("queue failure status=%d body=%s", failed.Code, failed.Body.String())
	}
	for model, where := range map[interface{}]string{
		&db.TaskAppendIdempotency{}: "root_task_id = ?",
		&db.TaskBatch{}:             "root_task_id = ?",
		&db.SubTask{}:               "root_task_id = ?",
		&db.TaskAudit{}:             "root_task_id = ?",
	} {
		var count int64
		if err := store.Model(model).Where(where, root.ID).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("queue failure persisted %T rows=%d", model, count)
		}
	}

	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close() })
	result, retried := appendIdempotentTaskRequest(t, root.ID, `{"targets":"https://queue-retry.example.test"}`, "append-queue-key")
	if retried.Code != http.StatusOK || result.Status != "appended" || result.Replayed {
		t.Fatalf("same key did not retry after rollback: status=%d response=%+v body=%s", retried.Code, result, retried.Body.String())
	}
}

func TestAppendTargetsIdempotencyAuditFailureRollsBackAndCanRetry(t *testing.T) {
	store := setupAITestDB(t)
	project, root := seedTaskAppendIdempotencyFixture(t, store, "audit-failure", "Finished")
	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	const callbackName = "test:reject_task_append_audit"
	if err := store.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "TaskAudit" {
			tx.AddError(errors.New("forced task append audit failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	_, failed := appendIdempotentTaskRequest(t, root.ID, `{"targets":"https://audit-retry.example.test"}`, "append-audit-key")
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure status=%d body=%s", failed.Code, failed.Body.String())
	}
	if err := store.Callback().Create().Remove(callbackName); err != nil {
		t.Fatal(err)
	}

	var ledgerCount, batchCount, attemptCount, auditCount int64
	store.Model(&db.TaskAppendIdempotency{}).Where("root_task_id = ?", root.ID).Count(&ledgerCount)
	store.Model(&db.TaskBatch{}).Where("root_task_id = ?", root.ID).Count(&batchCount)
	store.Model(&db.SubTask{}).Where("root_task_id = ?", root.ID).Count(&attemptCount)
	store.Model(&db.TaskAudit{}).Where("root_task_id = ?", root.ID).Count(&auditCount)
	if ledgerCount != 0 || batchCount != 0 || attemptCount != 0 || auditCount != 0 {
		t.Fatalf("audit failure persisted ledger=%d batches=%d attempts=%d audits=%d", ledgerCount, batchCount, attemptCount, auditCount)
	}
	var persistedRoot db.RootTask
	var persistedProject db.Project
	if err := store.First(&persistedRoot, "id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.First(&persistedProject, "id = ?", project.ID).Error; err != nil {
		t.Fatal(err)
	}
	if persistedRoot.TotalChunks != 0 || persistedRoot.TotalTargets != 0 || persistedRoot.OriginalTargets != `[]` || persistedProject.Scope != `[]` || persistedProject.SeedTargets != `[]` {
		t.Fatalf("audit rollback changed task/project: task=%+v project=%+v", persistedRoot, persistedProject)
	}

	result, retried := appendIdempotentTaskRequest(t, root.ID, `{"targets":"https://audit-retry.example.test"}`, "append-audit-key")
	if retried.Code != http.StatusOK || result.Status != "appended" || result.Replayed {
		t.Fatalf("same key did not retry after audit rollback: status=%d response=%+v body=%s", retried.Code, result, retried.Body.String())
	}
}

func TestAppendTargetsNormalizesDeduplicatesAndExpandsProjectScope(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{
		ID: "project-append", TenantID: "default", OwnerUserID: "1", Name: "Append project",
		Status: "active", SeedTargets: `[]`, Scope: `[]`,
	}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	root := db.RootTask{
		ID: "task-append", TenantID: "default", ProjectID: project.ID, UserID: "1", Name: "Append task",
		Status: "Finished", OriginalTargets: `["https://existing.example.test"]`, Config: `{"NoPoc":true}`,
		TotalChunks: 1, CompletedChunks: 1, TotalTargets: 1, CompletedTargets: 1, CurrentConfigVersion: 1,
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	revision := db.NewTaskConfigRevision(root, 1, `{}`, `{}`, "1", "initial")
	if err := store.Create(&revision).Error; err != nil {
		t.Fatalf("seed revision: %v", err)
	}
	oldAttempt := db.SubTask{
		ID: "task-append-batch-0-url-attempt-1", TenantID: "default", ProjectID: project.ID,
		RootTaskID: root.ID, BatchID: "task-append-batch-0-url", AttemptNo: 1, Trigger: db.AttemptTriggerInitial,
		ChunkTargets: `["https://existing.example.test"]`, Status: "Finished", ConfigVersion: 1,
	}
	if err := store.Create(&oldAttempt).Error; err != nil {
		t.Fatalf("seed old attempt: %v", err)
	}
	if err := store.Create(&db.TaskBatch{
		ID: oldAttempt.BatchID, TenantID: "default", ProjectID: project.ID, RootTaskID: root.ID,
		Sequence: 0, Kind: "asset_scan", TargetType: "url", Targets: oldAttempt.ChunkTargets,
		TargetCount: 1, Status: "Finished", ConfigVersion: 1, CurrentAttemptNo: 1,
		AttemptCount: 1, LatestAttemptID: oldAttempt.ID,
	}).Error; err != nil {
		t.Fatalf("seed old batch: %v", err)
	}

	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() {
		queue.Close()
		routerRuntime().TaskQueue = oldQueue
	})

	body := `{"targets":["HTTPS://Existing.Example.Test/","https://NEW.example.test/","https://new.example.test#ignored"]}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+root.ID+"/append", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+root.ID+"/append", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	appendTargets(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("append status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Status            string `json:"status"`
		NewBatches        int    `json:"new_batches"`
		NewTargets        int    `json:"new_targets"`
		DuplicateTargets  int    `json:"duplicate_targets"`
		ProjectScopeAdded int    `json:"project_scope_added"`
		ProjectSeedsAdded int    `json:"project_seeds_added"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode append response: %v", err)
	}
	if response.Status != "appended" || response.NewBatches != 1 || response.NewTargets != 1 || response.DuplicateTargets != 1 {
		t.Fatalf("unexpected append response: %+v", response)
	}
	if response.ProjectScopeAdded != 1 || response.ProjectSeedsAdded != 1 {
		t.Fatalf("project scope was not expanded: %+v", response)
	}

	if err := store.First(&root, "id = ?", root.ID).Error; err != nil {
		t.Fatalf("reload root: %v", err)
	}
	if root.Status != "Running" || root.TotalChunks != 2 || root.TotalTargets != 2 {
		t.Fatalf("completed task did not reactivate with one batch: %+v", root)
	}
	if root.OriginalTargets != `["https://existing.example.test","https://new.example.test"]` {
		t.Fatalf("unexpected merged task targets: %s", root.OriginalTargets)
	}
	if err := store.First(&project, "id = ?", project.ID).Error; err != nil {
		t.Fatalf("reload project: %v", err)
	}
	if project.Scope != `["https://new.example.test"]` || project.SeedTargets != `["https://new.example.test"]` {
		t.Fatalf("unexpected project scope: scope=%s seeds=%s", project.Scope, project.SeedTargets)
	}
	var audit db.TaskAudit
	if err := store.First(&audit, "root_task_id = ? AND action = ?", root.ID, "batch_append").Error; err != nil {
		t.Fatalf("load append audit: %v", err)
	}
	if audit.OperatorID != "1" || !strings.Contains(audit.Details, `"scope_added_targets":["https://new.example.test"]`) {
		t.Fatalf("unexpected append audit: %+v", audit)
	}

	ctx, recorder = newTenantContextWithRole(http.MethodPost, "/tasks/"+root.ID+"/append", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+root.ID+"/append", strings.NewReader(`{"targets":"HTTPS://NEW.EXAMPLE.TEST/"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	appendTargets(ctx)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"unchanged"`) {
		t.Fatalf("repeated append should be idempotent, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var batchCount int64
	store.Model(&db.TaskBatch{}).Where("root_task_id = ?", root.ID).Count(&batchCount)
	if batchCount != 2 {
		t.Fatalf("repeated append created another batch, count=%d", batchCount)
	}
	var auditCount int64
	store.Model(&db.TaskAudit{}).Where("root_task_id = ? AND action = ?", root.ID, "batch_append").Count(&auditCount)
	if auditCount != 1 {
		t.Fatalf("no-op append should not add an audit mutation, count=%d", auditCount)
	}
}

func TestAppendTargetsKeepsPausedTaskPaused(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.TaskAppendIdempotency{}); err != nil {
		t.Fatalf("migrate append idempotency: %v", err)
	}
	project := db.Project{ID: "project-paused-append", TenantID: "default", OwnerUserID: "1", Status: "active", SeedTargets: `[]`, Scope: `[]`}
	root := db.RootTask{
		ID: "task-paused-append", TenantID: "default", ProjectID: project.ID, UserID: "1",
		Status: "Paused", Config: `{"NoPoc":true}`, CurrentConfigVersion: 1,
	}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.TaskConfigRevision{
		TenantID: "default", ProjectID: project.ID, RootTaskID: root.ID, Version: 1,
		Config: root.Config, ConfigHash: strings.Repeat("b", 64), Priority: 1, TimeoutSec: 60,
		AgentSelector: `{}`, AgentSelectorRules: `{}`,
	}).Error; err != nil {
		t.Fatal(err)
	}

	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() {
		queue.Close()
		routerRuntime().TaskQueue = oldQueue
	})
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+root.ID+"/append", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+root.ID+"/append", strings.NewReader(`{"targets":"10.0.0.1"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Idempotency-Key", "paused-append-key")
	appendTargets(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("append paused status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if err := store.First(&root, "id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	var attempt db.SubTask
	if err := store.First(&attempt, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if root.Status != "Paused" || attempt.Status != "Paused" {
		t.Fatalf("paused append was dispatched: root=%s attempt=%s", root.Status, attempt.Status)
	}
	queued, _, err := queue.TryPopTask(t.Context(), "agent-paused")
	if err != nil {
		t.Fatal(err)
	}
	if queued != nil {
		t.Fatalf("paused append unexpectedly queued: %+v", queued)
	}
	// A retry remains a replay even while the queue is unavailable, and a
	// paused batch is neither dispatched nor dispatch-pending.
	routerRuntime().TaskQueue = nil
	replay, replayRecorder := appendIdempotentTaskRequest(t, root.ID, `{"targets":"10.0.0.1"}`, "paused-append-key")
	routerRuntime().TaskQueue = queue
	if replayRecorder.Code != http.StatusOK || !replay.Replayed || replay.Status != "appended" {
		t.Fatalf("paused replay status=%d response=%+v body=%s", replayRecorder.Code, replay, replayRecorder.Body.String())
	}
	var replayBody struct {
		Dispatched      int `json:"dispatched"`
		DispatchPending int `json:"dispatch_pending"`
	}
	if err := json.Unmarshal(replayRecorder.Body.Bytes(), &replayBody); err != nil {
		t.Fatal(err)
	}
	if replayBody.Dispatched != 0 || replayBody.DispatchPending != 0 {
		t.Fatalf("paused replay reported dispatch: %+v", replayBody)
	}
}

func TestAppendTargetsEnforcesProjectAndLifecycleBoundaries(t *testing.T) {
	store := setupAITestDB(t)
	projects := []db.Project{
		{ID: "project-private-append", TenantID: "default", OwnerUserID: "99", Status: "active", SeedTargets: `[]`, Scope: `[]`},
		{ID: "project-inactive-append", TenantID: "default", OwnerUserID: "1", Status: "archived", SeedTargets: `[]`, Scope: `[]`},
		{ID: "project-stopping-append", TenantID: "default", OwnerUserID: "1", Status: "active", SeedTargets: `[]`, Scope: `[]`},
	}
	if err := store.Create(&projects).Error; err != nil {
		t.Fatal(err)
	}
	tasks := []db.RootTask{
		{ID: "task-private-append", TenantID: "default", ProjectID: projects[0].ID, Status: "Running"},
		{ID: "task-inactive-append", TenantID: "default", ProjectID: projects[1].ID, Status: "Running"},
		{ID: "task-stopping-append", TenantID: "default", ProjectID: projects[2].ID, Status: "CancelPending"},
	}
	if err := store.Create(&tasks).Error; err != nil {
		t.Fatal(err)
	}

	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() {
		queue.Close()
		routerRuntime().TaskQueue = oldQueue
	})
	for _, testCase := range []struct {
		taskID string
		want   int
	}{
		{taskID: tasks[0].ID, want: http.StatusForbidden},
		{taskID: tasks[1].ID, want: http.StatusConflict},
		{taskID: tasks[2].ID, want: http.StatusConflict},
	} {
		ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+testCase.taskID+"/append", "operator", "1")
		ctx.Params = gin.Params{{Key: "id", Value: testCase.taskID}}
		ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+testCase.taskID+"/append", strings.NewReader(`{"targets":"10.0.0.1"}`))
		ctx.Request.Header.Set("Content-Type", "application/json")
		appendTargets(ctx)
		if recorder.Code != testCase.want {
			t.Fatalf("append %s status=%d want=%d body=%s", testCase.taskID, recorder.Code, testCase.want, recorder.Body.String())
		}
	}
	var batchCount, auditCount int64
	store.Model(&db.TaskBatch{}).Count(&batchCount)
	store.Model(&db.TaskAudit{}).Where("action = ?", "batch_append").Count(&auditCount)
	if batchCount != 0 || auditCount != 0 {
		t.Fatalf("rejected appends mutated state: batches=%d audits=%d", batchCount, auditCount)
	}
}
