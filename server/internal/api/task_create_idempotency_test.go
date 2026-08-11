package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type taskCreateIdempotencyResponse struct {
	TaskID         string            `json:"task_id"`
	ConfigVersion  int               `json:"config_version"`
	TargetSummary  taskTargetSummary `json:"target_summary"`
	BatchProfile   batchProfile      `json:"batch_profile"`
	SkippedTargets []invalidTarget   `json:"skipped_targets"`
	Replayed       bool              `json:"replayed"`
}

type taskCreateCounts struct {
	Roots, Revisions, Batches, Attempts, Audits int64
	Scope, Seeds                                string
}

func withIdempotentTaskCreateQueue(t *testing.T) *scheduler.TaskQueue {
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

func createIdempotentTaskRequest(t *testing.T, tenant, role, operator, body, key string) (taskCreateIdempotencyResponse, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	if key != "" {
		c.Request.Header.Set("Idempotency-Key", key)
	}
	c.Set("tenant", tenant)
	c.Set("role", role)
	c.Set("user_id", operator)
	createTask(c)
	var response taskCreateIdempotencyResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode create response: %v", err)
		}
	}
	return response, w
}

func snapshotTaskCreateCounts(t *testing.T, store *gorm.DB, projectID string) taskCreateCounts {
	t.Helper()
	var result taskCreateCounts
	for _, count := range []struct {
		model interface{}
		out   *int64
		query string
	}{
		{&db.RootTask{}, &result.Roots, "project_id = ?"},
		{&db.TaskConfigRevision{}, &result.Revisions, "project_id = ?"},
		{&db.TaskBatch{}, &result.Batches, "project_id = ?"},
		{&db.SubTask{}, &result.Attempts, "project_id = ?"},
		{&db.TaskAudit{}, &result.Audits, "project_id = ?"},
	} {
		if err := store.Model(count.model).Where(count.query, projectID).Count(count.out).Error; err != nil {
			t.Fatalf("count %T: %v", count.model, err)
		}
	}
	var project db.Project
	if err := store.First(&project, "id = ?", projectID).Error; err != nil {
		t.Fatalf("reload project: %v", err)
	}
	result.Scope, result.Seeds = project.Scope, project.SeedTargets
	return result
}

func TestCreateTaskIdempotencyReplayDoesNotDuplicateTaskOrQueue(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.TaskCreationIdempotency{}); err != nil {
		t.Fatalf("migrate idempotency ledger: %v", err)
	}
	project := db.Project{ID: "project-create-idempotency", TenantID: "default", OwnerUserID: "operator-1", Status: "active", Scope: "[]", SeedTargets: "[]"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	queue := withIdempotentTaskCreateQueue(t)
	body := `{"project_id":"project-create-idempotency","targets":["https://one.example.test","invalid-two","https://two.example.test","invalid-one"],"priority":1,"skip_unsupported":true}`

	first, firstW := createIdempotentTaskRequest(t, "default", "operator", "operator-1", body, "create-key-1")
	if firstW.Code != http.StatusOK || first.TaskID == "" || first.Replayed {
		t.Fatalf("first=%d %+v body=%s", firstW.Code, first, firstW.Body.String())
	}
	// Later task edits must not change the immutable creation response.
	if err := store.Model(&db.RootTask{}).Where("id = ?", first.TaskID).Update("current_config_version", 7).Error; err != nil {
		t.Fatalf("advance task config version: %v", err)
	}
	before := snapshotTaskCreateCounts(t, store, project.ID)
	// Field order and target representation differ, but the normalized request is identical.
	// Omitting the name exercises the deterministic auto-name binding as well.
	replayBody := `{"targets":"invalid-one\nhttps://two.example.test\ninvalid-two\nhttps://one.example.test","skip_unsupported":true,"priority":1,"project_id":"project-create-idempotency"}`
	replay, replayW := createIdempotentTaskRequest(t, "default", "operator", "operator-1", replayBody, "create-key-1")
	if replayW.Code != http.StatusOK || !replay.Replayed || replay.TaskID != first.TaskID || replay.ConfigVersion != 1 {
		t.Fatalf("replay=%d %+v body=%s", replayW.Code, replay, replayW.Body.String())
	}
	if !reflect.DeepEqual(replay.TargetSummary, first.TargetSummary) ||
		!reflect.DeepEqual(replay.BatchProfile, first.BatchProfile) ||
		!reflect.DeepEqual(replay.SkippedTargets, first.SkippedTargets) {
		t.Fatalf("replay summary drifted from first response:\nfirst=%+v\nreplay=%+v", first, replay)
	}
	if after := snapshotTaskCreateCounts(t, store, project.ID); after != before {
		t.Fatalf("replay mutated persisted task state: before=%+v after=%+v", before, after)
	}
	firstQueued, _, err := queue.TryPopTask(context.Background(), "agent-1")
	if err != nil || firstQueued == nil {
		t.Fatalf("first queue entry: task=%v err=%v", firstQueued, err)
	}
	secondQueued, _, err := queue.TryPopTask(context.Background(), "agent-1")
	if err != nil || secondQueued != nil {
		t.Fatalf("replay must not enqueue again: task=%v err=%v", secondQueued, err)
	}
}

func TestCreateTaskIdempotencyRejectsChangedRequestAndKeepsLegacyNoKey(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.TaskCreationIdempotency{}); err != nil {
		t.Fatalf("migrate idempotency ledger: %v", err)
	}
	project := db.Project{ID: "project-create-conflict", TenantID: "default", OwnerUserID: "operator-1", Status: "active", Scope: "[]", SeedTargets: "[]"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	withIdempotentTaskCreateQueue(t)
	body := `{"project_id":"project-create-conflict","targets":"https://one.example.test"}`
	first, w := createIdempotentTaskRequest(t, "default", "operator", "operator-1", body, "conflict-key")
	if w.Code != http.StatusOK || first.TaskID == "" {
		t.Fatalf("first=%d %s", w.Code, w.Body.String())
	}
	before := snapshotTaskCreateCounts(t, store, project.ID)
	_, conflict := createIdempotentTaskRequest(t, "default", "operator", "operator-1", `{"project_id":"project-create-conflict","targets":"https://different.example.test"}`, "conflict-key")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("changed request status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	if after := snapshotTaskCreateCounts(t, store, project.ID); after != before {
		t.Fatalf("conflict mutated state: before=%+v after=%+v", before, after)
	}
	_, noKeyA := createIdempotentTaskRequest(t, "default", "operator", "operator-1", body, "")
	_, noKeyB := createIdempotentTaskRequest(t, "default", "operator", "operator-1", body, "")
	if noKeyA.Code != http.StatusOK || noKeyB.Code != http.StatusOK {
		t.Fatalf("legacy no-key requests must remain compatible: %d/%d", noKeyA.Code, noKeyB.Code)
	}
}

func TestCreateTaskIdempotencyValidatesAndScopesKey(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.TaskCreationIdempotency{}); err != nil {
		t.Fatalf("migrate idempotency ledger: %v", err)
	}
	projects := []db.Project{
		{ID: "project-key-a", TenantID: "default", OwnerUserID: "operator-1", Status: "active", Scope: "[]", SeedTargets: "[]"},
		{ID: "project-key-b", TenantID: "default", OwnerUserID: "operator-1", Status: "active", Scope: "[]", SeedTargets: "[]"},
		{ID: "project-key-tenant-b", TenantID: "tenant-b", OwnerUserID: "operator-1", Status: "active", Scope: "[]", SeedTargets: "[]"},
	}
	if err := store.Create(&projects).Error; err != nil {
		t.Fatalf("create projects: %v", err)
	}
	if err := store.Create(&db.ProjectMember{TenantID: "default", ProjectID: "project-key-a", UserID: "operator-2", Role: "operator"}).Error; err != nil {
		t.Fatalf("create second operator membership: %v", err)
	}
	withIdempotentTaskCreateQueue(t)
	invalid := strings.Repeat("a", 129)
	_, invalidW := createIdempotentTaskRequest(t, "default", "operator", "operator-1", `{"project_id":"project-key-a","targets":"https://one.example.test"}`, invalid)
	if invalidW.Code != http.StatusBadRequest {
		t.Fatalf("invalid key status=%d body=%s", invalidW.Code, invalidW.Body.String())
	}
	_, firstW := createIdempotentTaskRequest(t, "default", "operator", "operator-1", `{"project_id":"project-key-a","targets":"https://one.example.test"}`, "shared-key")
	_, projectW := createIdempotentTaskRequest(t, "default", "operator", "operator-1", `{"project_id":"project-key-b","targets":"https://one.example.test"}`, "shared-key")
	_, operatorW := createIdempotentTaskRequest(t, "default", "operator", "operator-2", `{"project_id":"project-key-a","targets":"https://one.example.test"}`, "shared-key")
	_, tenantW := createIdempotentTaskRequest(t, "tenant-b", "operator", "operator-1", `{"project_id":"project-key-tenant-b","targets":"https://one.example.test"}`, "shared-key")
	if firstW.Code != http.StatusOK || projectW.Code != http.StatusOK || operatorW.Code != http.StatusOK || tenantW.Code != http.StatusOK {
		t.Fatalf("key scope isolation failed: %d/%d/%d/%d", firstW.Code, projectW.Code, operatorW.Code, tenantW.Code)
	}
	_, denied := createIdempotentTaskRequest(t, "default", "viewer", "viewer-1", `{"project_id":"project-key-a","targets":"https://one.example.test"}`, "shared-key")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("inaccessible project must not reveal key outcome: %d %s", denied.Code, denied.Body.String())
	}
}

func TestCreateTaskIdempotencyReplaySurvivesUnavailableQueue(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.TaskCreationIdempotency{}); err != nil {
		t.Fatalf("migrate idempotency ledger: %v", err)
	}
	project := db.Project{ID: "project-create-queue-replay", TenantID: "default", OwnerUserID: "operator-1", Status: "active", Scope: "[]", SeedTargets: "[]"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	withIdempotentTaskCreateQueue(t)
	body := `{"project_id":"project-create-queue-replay","targets":"https://one.example.test"}`
	first, firstW := createIdempotentTaskRequest(t, "default", "operator", "operator-1", body, "queue-replay-key")
	if firstW.Code != http.StatusOK || first.TaskID == "" {
		t.Fatalf("first=%d %s", firstW.Code, firstW.Body.String())
	}
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = nil
	t.Cleanup(func() { routerRuntime().TaskQueue = oldQueue })
	replay, replayW := createIdempotentTaskRequest(t, "default", "operator", "operator-1", body, "queue-replay-key")
	if replayW.Code != http.StatusOK || !replay.Replayed || replay.TaskID != first.TaskID {
		t.Fatalf("replay while queue unavailable=%d %+v %s", replayW.Code, replay, replayW.Body.String())
	}
	_, newW := createIdempotentTaskRequest(t, "default", "operator", "operator-1", `{"project_id":"project-create-queue-replay","targets":"https://two.example.test"}`, "queue-new-key")
	if newW.Code != http.StatusServiceUnavailable {
		t.Fatalf("new request with nil queue=%d body=%s", newW.Code, newW.Body.String())
	}
}

func TestCreateTaskIdempotencyAuditFailureRollsBackAndKeyCanRetry(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.TaskCreationIdempotency{}); err != nil {
		t.Fatalf("migrate idempotency ledger: %v", err)
	}
	project := db.Project{ID: "project-create-audit-rollback", TenantID: "default", OwnerUserID: "operator-1", Status: "active", Scope: "[]", SeedTargets: "[]"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	withIdempotentTaskCreateQueue(t)
	if err := store.Exec(`CREATE TRIGGER fail_task_create_audit BEFORE INSERT ON task_audits BEGIN SELECT RAISE(FAIL, 'forced task audit failure'); END;`).Error; err != nil {
		t.Fatalf("install audit failure trigger: %v", err)
	}
	body := `{"project_id":"project-create-audit-rollback","targets":"https://one.example.test"}`
	_, failed := createIdempotentTaskRequest(t, "default", "operator", "operator-1", body, "audit-retry-key")
	if failed.Code == http.StatusOK {
		t.Fatalf("forced audit failure unexpectedly succeeded: %s", failed.Body.String())
	}
	if counts := snapshotTaskCreateCounts(t, store, project.ID); counts.Roots != 0 || counts.Revisions != 0 || counts.Batches != 0 || counts.Attempts != 0 || counts.Audits != 0 || counts.Scope != "[]" || counts.Seeds != "[]" {
		t.Fatalf("failed transaction leaked state: %+v", counts)
	}
	if err := store.Exec(`DROP TRIGGER fail_task_create_audit`).Error; err != nil {
		t.Fatalf("remove audit failure trigger: %v", err)
	}
	retry, retried := createIdempotentTaskRequest(t, "default", "operator", "operator-1", body, "audit-retry-key")
	if retried.Code != http.StatusOK || retry.TaskID == "" || retry.Replayed {
		t.Fatalf("retry after rollback=%d %+v %s", retried.Code, retry, retried.Body.String())
	}
}
