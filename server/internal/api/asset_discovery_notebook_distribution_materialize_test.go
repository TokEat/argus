package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
	"gorm.io/gorm"
)

func invokeNotebookDistributionMaterialize(t *testing.T, projectID, body, key string) *httptest.ResponseRecorder {
	return invokeNotebookDistributionMaterializeAs(t, projectID, body, key, "default")
}

func invokeNotebookDistributionMaterializeAs(t *testing.T, projectID, body, key, tenantID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/notebook-distributions"
	ctx, recorder := newTenantContextWithRole(http.MethodPost, path, "operator", "9")
	ctx.Set("tenant", tenantID)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Idempotency-Key", key)
	materializeProjectNotebookDistribution(ctx)
	return recorder
}

func assertNotebookDistributionBusinessCounts(t *testing.T, store *gorm.DB, taskID string, wantBatches, wantAttempts, wantAudits, wantIntents, wantResults int64) {
	t.Helper()
	var batches, attempts, audits, intents, results int64
	store.Model(&db.TaskBatch{}).Where("root_task_id = ?", taskID).Count(&batches)
	store.Model(&db.SubTask{}).Where("root_task_id = ?", taskID).Count(&attempts)
	store.Model(&db.TaskAudit{}).Where("root_task_id = ? AND action = ?", taskID, "notebook_distribution_materialize").Count(&audits)
	store.Model(&db.AssetDiscoveryNotebookDistributionIntent{}).Where("root_task_id = ?", taskID).Count(&intents)
	store.Model(&db.AssetDiscoveryNotebookDistributionMaterialization{}).Where("root_task_id = ?", taskID).Count(&results)
	if batches != wantBatches || attempts != wantAttempts || audits != wantAudits || intents != wantIntents || results != wantResults {
		t.Fatalf("business writes batches=%d attempts=%d audits=%d intents=%d results=%d; want %d/%d/%d/%d/%d", batches, attempts, audits, intents, results, wantBatches, wantAttempts, wantAudits, wantIntents, wantResults)
	}
}

func seedNotebookDistributionMaterializeFixture(t *testing.T, store *gorm.DB, suffix, status string) (db.Project, db.RootTask, db.AssetDiscoveryNotebookItem, notebookDistributionPreviewResponse) {
	t.Helper()
	project := seedAssetDiscoveryHistoryProject(t, store, "materialize-"+suffix, "default", "9")
	project.Scope, project.SeedTargets = `[]`, `[]`
	if err := store.Save(&project).Error; err != nil {
		t.Fatal(err)
	}
	item := db.AssetDiscoveryNotebookItem{TenantID: "default", ProjectID: project.ID, NormalizedTarget: "https://" + suffix + ".example.com", TargetHash: "item-" + suffix}
	if err := store.Create(&item).Error; err != nil {
		t.Fatal(err)
	}
	task := db.RootTask{ID: "materialize-task-" + suffix, TenantID: "default", ProjectID: project.ID, UserID: "9", Status: status, OriginalTargets: `[]`, Config: `{}`, CurrentConfigVersion: 1, RuleVersion: "rules-test"}
	if err := store.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	revision := db.NewTaskConfigRevision(task, 1, `{}`, `{}`, "9", "initial")
	if err := store.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}
	preview := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"`+task.ID+`","item_ids":[`+strconv.FormatUint(uint64(item.ID), 10)+`]}`, "default", "operator")
	if preview.Code != http.StatusOK {
		t.Fatalf("preview=%d %s", preview.Code, preview.Body.String())
	}
	var plan notebookDistributionPreviewResponse
	if err := json.Unmarshal(preview.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	return project, task, item, plan
}

func TestNotebookDistributionMaterializeCreatesAndReplaysWithoutDispatchingTwice(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.RootTask{}, &db.TaskBatch{}, &db.SubTask{}, &db.TaskConfigRevision{}, &db.TaskAudit{}, &db.SystemConfig{}, &db.AssetDiscoveryNotebookDistributionIntent{}, &db.AssetDiscoveryNotebookDistributionIntentItem{}, &db.AssetDiscoveryNotebookDistributionMaterialization{}); err != nil {
		t.Fatal(err)
	}
	project := seedAssetDiscoveryHistoryProject(t, store, "materialize-project", "default", "9")
	project.Scope, project.SeedTargets = `[]`, `[]`
	if err := store.Save(&project).Error; err != nil {
		t.Fatal(err)
	}
	item := db.AssetDiscoveryNotebookItem{TenantID: "default", ProjectID: project.ID, NormalizedTarget: "https://new.example.com", TargetHash: "item"}
	if err := store.Create(&item).Error; err != nil {
		t.Fatal(err)
	}
	task := db.RootTask{ID: "materialize-task", TenantID: "default", ProjectID: project.ID, UserID: "9", Status: "Finished", OriginalTargets: `[]`, Config: `{}`, CurrentConfigVersion: 1, RuleVersion: "rules-test"}
	if err := store.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	revision := db.NewTaskConfigRevision(task, 1, `{}`, `{}`, "9", "initial")
	if err := store.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}

	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })
	preview := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"`+task.ID+`","item_ids":[`+strconv.FormatUint(uint64(item.ID), 10)+`]}`, "default", "operator")
	if preview.Code != http.StatusOK {
		t.Fatalf("preview=%d %s", preview.Code, preview.Body.String())
	}
	var plan notebookDistributionPreviewResponse
	if err := json.Unmarshal(preview.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	body := `{"task_id":"` + task.ID + `","item_ids":[` + strconv.FormatUint(uint64(item.ID), 10) + `],"plan_hash":"` + plan.PlanHash + `"}`
	first := invokeNotebookDistributionMaterialize(t, project.ID, body, "idem-materialize-1")
	if first.Code != http.StatusOK {
		t.Fatalf("first=%d %s", first.Code, first.Body.String())
	}
	var firstResult notebookDistributionMaterializeResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResult); err != nil {
		t.Fatal(err)
	}
	if firstResult.SchemaVersion != "argus.asset-discovery-notebook-distribution/v1" || firstResult.Outcome != "materialized" || firstResult.Replayed || firstResult.Counts.Fresh != 1 || len(firstResult.BatchIDs) != 1 || len(firstResult.AttemptIDs) != 1 || firstResult.Task.Status != "Running" {
		t.Fatalf("first result=%+v", firstResult)
	}
	if queued, _, err := queue.TryPopTask(t.Context(), "materialize-agent"); err != nil || queued == nil {
		t.Fatalf("expected initial dispatch, task=%+v err=%v", queued, err)
	}
	routerRuntime().TaskQueue = nil
	second := invokeNotebookDistributionMaterialize(t, project.ID, body, "idem-materialize-1")
	if second.Code != http.StatusOK {
		t.Fatalf("replay=%d %s", second.Code, second.Body.String())
	}
	var replay notebookDistributionMaterializeResponse
	if err := json.Unmarshal(second.Body.Bytes(), &replay); err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.Outcome != "materialized" || replay.IntentID != firstResult.IntentID || strings.Join(replay.BatchIDs, ",") != strings.Join(firstResult.BatchIDs, ",") || strings.Join(replay.AttemptIDs, ",") != strings.Join(firstResult.AttemptIDs, ",") || replay.Dispatch.Dispatched != 1 || replay.Dispatch.Pending != 0 {
		t.Fatalf("replay=%+v first=%+v", replay, firstResult)
	}
	conflict := invokeNotebookDistributionMaterialize(t, project.ID, strings.Replace(body, plan.PlanHash, strings.Repeat("0", 64), 1), "idem-materialize-1")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("idempotency conflict=%d %s", conflict.Code, conflict.Body.String())
	}
	duplicatePreview := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"`+task.ID+`","item_ids":[`+strconv.FormatUint(uint64(item.ID), 10)+`]}`, "default", "operator")
	var duplicatePlan notebookDistributionPreviewResponse
	_ = json.Unmarshal(duplicatePreview.Body.Bytes(), &duplicatePlan)
	unchanged := invokeNotebookDistributionMaterialize(t, project.ID, `{"task_id":"`+task.ID+`","item_ids":[`+strconv.FormatUint(uint64(item.ID), 10)+`],"plan_hash":"`+duplicatePlan.PlanHash+`"}`, "idem-unchanged-1")
	if unchanged.Code != http.StatusOK {
		t.Fatalf("unchanged=%d %s", unchanged.Code, unchanged.Body.String())
	}
	var unchangedResult notebookDistributionMaterializeResponse
	_ = json.Unmarshal(unchanged.Body.Bytes(), &unchangedResult)
	if unchangedResult.Outcome != "unchanged" || unchangedResult.Counts.Fresh != 0 || len(unchangedResult.BatchIDs) != 0 || len(unchangedResult.AttemptIDs) != 0 {
		t.Fatalf("unchanged=%+v", unchangedResult)
	}
	var batches, attempts, intents, results, audits int64
	store.Model(&db.TaskBatch{}).Where("root_task_id = ?", task.ID).Count(&batches)
	store.Model(&db.SubTask{}).Where("root_task_id = ?", task.ID).Count(&attempts)
	store.Model(&db.AssetDiscoveryNotebookDistributionIntent{}).Count(&intents)
	store.Model(&db.AssetDiscoveryNotebookDistributionMaterialization{}).Count(&results)
	store.Model(&db.TaskAudit{}).Where("action = ?", "notebook_distribution_materialize").Count(&audits)
	if batches != 1 || attempts != 1 || intents != 2 || results != 2 || audits != 1 {
		t.Fatalf("writes batches=%d attempts=%d intents=%d results=%d audits=%d", batches, attempts, intents, results, audits)
	}
	if queued, _, err := queue.TryPopTask(t.Context(), "materialize-agent"); err != nil || queued != nil {
		t.Fatalf("replay queued task=%+v err=%v", queued, err)
	}
}

func TestNotebookDistributionMaterializeRejectsStalePlanWithoutWrites(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.RootTask{}, &db.TaskBatch{}, &db.SubTask{}, &db.TaskConfigRevision{}, &db.TaskAudit{}, &db.SystemConfig{}, &db.AssetDiscoveryNotebookDistributionIntent{}, &db.AssetDiscoveryNotebookDistributionIntentItem{}, &db.AssetDiscoveryNotebookDistributionMaterialization{}); err != nil {
		t.Fatal(err)
	}
	project := seedAssetDiscoveryHistoryProject(t, store, "materialize-stale", "default", "9")
	item := db.AssetDiscoveryNotebookItem{TenantID: "default", ProjectID: project.ID, NormalizedTarget: "https://stale.example.com", TargetHash: "item"}
	if err := store.Create(&item).Error; err != nil {
		t.Fatal(err)
	}
	task := db.RootTask{ID: "materialize-stale-task", TenantID: "default", ProjectID: project.ID, UserID: "9", Status: "Running", Config: `{}`, CurrentConfigVersion: 1}
	if err := store.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	revision := db.NewTaskConfigRevision(task, 1, `{}`, `{}`, "9", "initial")
	if err := store.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = scheduler.NewTaskQueue("")
	t.Cleanup(func() { routerRuntime().TaskQueue.Close(); routerRuntime().TaskQueue = oldQueue })
	preview := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"`+task.ID+`","item_ids":[`+strconv.FormatUint(uint64(item.ID), 10)+`]}`, "default", "operator")
	var plan notebookDistributionPreviewResponse
	_ = json.Unmarshal(preview.Body.Bytes(), &plan)
	if err := store.Model(&db.Project{}).Where("id = ?", project.ID).Update("scope", `["https://changed.example"]`).Error; err != nil {
		t.Fatal(err)
	}
	r := invokeNotebookDistributionMaterialize(t, project.ID, `{"task_id":"`+task.ID+`","item_ids":[`+strconv.FormatUint(uint64(item.ID), 10)+`],"plan_hash":"`+plan.PlanHash+`"}`, "idem-stale-1")
	if r.Code != http.StatusConflict {
		t.Fatalf("stale=%d %s", r.Code, r.Body.String())
	}
	var count int64
	store.Model(&db.AssetDiscoveryNotebookDistributionIntent{}).Count(&count)
	if count != 0 {
		t.Fatalf("stale confirmation wrote intent=%d", count)
	}
}

func TestNotebookDistributionMaterializeQueueUnavailableCommitsForRecovery(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.RootTask{}, &db.TaskBatch{}, &db.SubTask{}, &db.TaskConfigRevision{}, &db.TaskAudit{}, &db.SystemConfig{}, &db.AssetDiscoveryNotebookDistributionIntent{}, &db.AssetDiscoveryNotebookDistributionIntentItem{}, &db.AssetDiscoveryNotebookDistributionMaterialization{}); err != nil {
		t.Fatal(err)
	}
	project, task, item, plan := seedNotebookDistributionMaterializeFixture(t, store, "queue-unavailable", "Finished")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = nil
	t.Cleanup(func() { routerRuntime().TaskQueue = oldQueue })

	body := `{"task_id":"` + task.ID + `","item_ids":[` + strconv.FormatUint(uint64(item.ID), 10) + `],"plan_hash":"` + plan.PlanHash + `"}`
	r := invokeNotebookDistributionMaterialize(t, project.ID, body, "idem-queue-unavailable")
	if r.Code != http.StatusOK {
		t.Fatalf("queue unavailable=%d %s", r.Code, r.Body.String())
	}
	var result notebookDistributionMaterializeResponse
	if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Dispatch.Dispatched != 0 || result.Dispatch.Pending != 1 || result.Replayed || len(result.AttemptIDs) != 1 {
		t.Fatalf("queue unavailable result=%+v", result)
	}
	assertNotebookDistributionBusinessCounts(t, store, task.ID, 1, 1, 1, 1, 1)
	var reloadedProject db.Project
	var reloadedTask db.RootTask
	var attempt db.SubTask
	if err := store.First(&reloadedProject, "id = ?", project.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.First(&reloadedTask, "id = ?", task.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.First(&attempt, "id = ?", result.AttemptIDs[0]).Error; err != nil {
		t.Fatal(err)
	}
	if reloadedProject.Scope == `[]` || reloadedProject.SeedTargets == `[]` || reloadedTask.OriginalTargets == `[]` || reloadedTask.Status != "Running" || attempt.Status != subTaskStatusDispatching {
		t.Fatalf("queue failure did not preserve recoverable work: project=%+v task=%+v attempt=%+v", reloadedProject, reloadedTask, attempt)
	}

	replay := invokeNotebookDistributionMaterialize(t, project.ID, body, "idem-queue-unavailable")
	if replay.Code != http.StatusOK {
		t.Fatalf("queue unavailable replay=%d %s", replay.Code, replay.Body.String())
	}
	var replayResult notebookDistributionMaterializeResponse
	if err := json.Unmarshal(replay.Body.Bytes(), &replayResult); err != nil {
		t.Fatal(err)
	}
	if !replayResult.Replayed || replayResult.IntentID != result.IntentID || replayResult.Dispatch.Dispatched != 0 || replayResult.Dispatch.Pending != 1 {
		t.Fatalf("queue unavailable replay result=%+v", replayResult)
	}
	assertNotebookDistributionBusinessCounts(t, store, task.ID, 1, 1, 1, 1, 1)
}

func TestNotebookDistributionMaterializePausedTaskPersistsWithoutDispatch(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.RootTask{}, &db.TaskBatch{}, &db.SubTask{}, &db.TaskConfigRevision{}, &db.TaskAudit{}, &db.SystemConfig{}, &db.AssetDiscoveryNotebookDistributionIntent{}, &db.AssetDiscoveryNotebookDistributionIntentItem{}, &db.AssetDiscoveryNotebookDistributionMaterialization{}); err != nil {
		t.Fatal(err)
	}
	project, task, item, plan := seedNotebookDistributionMaterializeFixture(t, store, "paused", "Paused")
	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	body := `{"task_id":"` + task.ID + `","item_ids":[` + strconv.FormatUint(uint64(item.ID), 10) + `],"plan_hash":"` + plan.PlanHash + `"}`
	r := invokeNotebookDistributionMaterialize(t, project.ID, body, "idem-paused")
	if r.Code != http.StatusOK {
		t.Fatalf("paused materialize=%d %s", r.Code, r.Body.String())
	}
	var result notebookDistributionMaterializeResponse
	if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Task.Status != "Paused" || result.Dispatch.Dispatched != 0 || result.Dispatch.Pending != 0 || len(result.BatchIDs) != 1 || len(result.AttemptIDs) != 1 {
		t.Fatalf("paused result=%+v", result)
	}
	var batch db.TaskBatch
	var attempt db.SubTask
	if err := store.First(&batch, "id = ?", result.BatchIDs[0]).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.First(&attempt, "id = ?", result.AttemptIDs[0]).Error; err != nil {
		t.Fatal(err)
	}
	if batch.Status != "Paused" || attempt.Status != "Paused" {
		t.Fatalf("paused execution batch=%+v attempt=%+v", batch, attempt)
	}
	if queued, _, err := queue.TryPopTask(t.Context(), "paused-agent"); err != nil || queued != nil {
		t.Fatalf("paused task unexpectedly queued: task=%+v err=%v", queued, err)
	}
}

func TestNotebookDistributionMaterializeRejectsCrossProjectAndTenantObjectsWithoutWrites(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.RootTask{}, &db.TaskBatch{}, &db.SubTask{}, &db.TaskConfigRevision{}, &db.TaskAudit{}, &db.SystemConfig{}, &db.AssetDiscoveryNotebookDistributionIntent{}, &db.AssetDiscoveryNotebookDistributionIntentItem{}, &db.AssetDiscoveryNotebookDistributionMaterialization{}); err != nil {
		t.Fatal(err)
	}
	project, task, _, _ := seedNotebookDistributionMaterializeFixture(t, store, "boundary", "Finished")
	otherProject := seedAssetDiscoveryHistoryProject(t, store, "materialize-boundary-other", "default", "9")
	otherItem := db.AssetDiscoveryNotebookItem{TenantID: "default", ProjectID: otherProject.ID, NormalizedTarget: "https://cross-project.example.invalid", TargetHash: "cross-project"}
	if err := store.Create(&otherItem).Error; err != nil {
		t.Fatal(err)
	}
	foreignTask := db.RootTask{ID: "materialize-foreign-task", TenantID: "other-tenant", ProjectID: project.ID, UserID: "9", Status: "Finished", Config: `{}`, CurrentConfigVersion: 1}
	if err := store.Create(&foreignTask).Error; err != nil {
		t.Fatal(err)
	}
	foreignItem := db.AssetDiscoveryNotebookItem{TenantID: "other-tenant", ProjectID: project.ID, NormalizedTarget: "https://cross-tenant.example.invalid", TargetHash: "cross-tenant"}
	if err := store.Create(&foreignItem).Error; err != nil {
		t.Fatal(err)
	}

	validHash := strings.Repeat("a", 64)
	cases := []struct {
		name string
		body string
	}{
		{name: "cross project item", body: `{"task_id":"` + task.ID + `","item_ids":[` + strconv.FormatUint(uint64(otherItem.ID), 10) + `],"plan_hash":"` + validHash + `"}`},
		{name: "cross tenant task", body: `{"task_id":"` + foreignTask.ID + `","item_ids":[` + strconv.FormatUint(uint64(foreignItem.ID), 10) + `],"plan_hash":"` + validHash + `"}`},
		{name: "cross tenant item", body: `{"task_id":"` + task.ID + `","item_ids":[` + strconv.FormatUint(uint64(foreignItem.ID), 10) + `],"plan_hash":"` + validHash + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := invokeNotebookDistributionMaterialize(t, project.ID, tc.body, "idem-boundary-"+strings.ReplaceAll(tc.name, " ", "-"))
			if r.Code != http.StatusNotFound {
				t.Fatalf("boundary=%d %s", r.Code, r.Body.String())
			}
			assertNotebookDistributionBusinessCounts(t, store, task.ID, 0, 0, 0, 0, 0)
		})
	}
}

func TestNotebookDistributionMaterializeRollsBackWhenTaskAuditFails(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.RootTask{}, &db.TaskBatch{}, &db.SubTask{}, &db.TaskConfigRevision{}, &db.TaskAudit{}, &db.SystemConfig{}, &db.AssetDiscoveryNotebookDistributionIntent{}, &db.AssetDiscoveryNotebookDistributionIntentItem{}, &db.AssetDiscoveryNotebookDistributionMaterialization{}); err != nil {
		t.Fatal(err)
	}
	project, task, item, plan := seedNotebookDistributionMaterializeFixture(t, store, "audit-rollback", "Finished")
	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })
	const callbackName = "test:fail_notebook_distribution_task_audit"
	if err := store.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table == "task_audits" {
			tx.AddError(errors.New("injected task audit failure"))
		}
	}); err != nil {
		t.Fatalf("register audit failure callback: %v", err)
	}
	t.Cleanup(func() { _ = store.Callback().Create().Remove(callbackName) })

	body := `{"task_id":"` + task.ID + `","item_ids":[` + strconv.FormatUint(uint64(item.ID), 10) + `],"plan_hash":"` + plan.PlanHash + `"}`
	r := invokeNotebookDistributionMaterialize(t, project.ID, body, "idem-audit-rollback")
	if r.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure=%d %s", r.Code, r.Body.String())
	}
	assertNotebookDistributionBusinessCounts(t, store, task.ID, 0, 0, 0, 0, 0)
	var reloadedProject db.Project
	var reloadedTask db.RootTask
	if err := store.First(&reloadedProject, "id = ?", project.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.First(&reloadedTask, "id = ?", task.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reloadedProject.Scope != `[]` || reloadedProject.SeedTargets != `[]` || reloadedTask.OriginalTargets != `[]` || reloadedTask.Status != "Finished" {
		t.Fatalf("audit failure mutated project/task: project=%+v task=%+v", reloadedProject, reloadedTask)
	}
	if queued, _, err := queue.TryPopTask(t.Context(), "audit-failure-agent"); err != nil || queued != nil {
		t.Fatalf("rolled back task unexpectedly queued: task=%+v err=%v", queued, err)
	}
}

func TestNotebookDistributionMaterializeRouteRequiresOperator(t *testing.T) {
	if got := matchPermission(http.MethodPost, "/api/v1/projects/p/asset-discovery/notebook-distributions"); got != "operator" {
		t.Fatalf("permission=%q", got)
	}
}

func TestNotebookDistributionMaterializeRouteAndCORSContract(t *testing.T) {
	router := NewRouter(RouterDependencies{})
	found := false
	for _, route := range router.Routes() {
		if route.Method == http.MethodPost && route.Path == "/api/v1/projects/:id/asset-discovery/notebook-distributions" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("materialize route is not registered")
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodOptions, "/api/v1/projects/p/asset-discovery/notebook-distributions", nil))
	if recorder.Code != http.StatusNoContent || !strings.Contains(recorder.Header().Get("Access-Control-Allow-Headers"), "Idempotency-Key") {
		t.Fatalf("CORS=%d headers=%q", recorder.Code, recorder.Header().Get("Access-Control-Allow-Headers"))
	}
}
