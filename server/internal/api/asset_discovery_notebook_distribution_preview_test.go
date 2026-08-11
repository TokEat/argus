package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

func invokeNotebookDistributionPreview(t *testing.T, projectID, body, tenant, role string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/notebook-distributions/preview"
	ctx, recorder := newTenantContextWithRole(http.MethodPost, path, role, "9")
	ctx.Set("tenant", tenant)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	previewProjectNotebookDistribution(ctx)
	return recorder
}

func TestNotebookDistributionPreviewIsReadOnlyAndVersionBound(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.RootTask{}, &db.TaskBatch{}, &db.TaskConfigRevision{}, &db.TaskAudit{}, &db.SystemConfig{}); err != nil {
		t.Fatal(err)
	}
	project := seedAssetDiscoveryHistoryProject(t, store, "distribution-preview", "default", "9")
	project.Scope, project.SeedTargets = `["https://scope.example.invalid"]`, `[]`
	if err := store.Save(&project).Error; err != nil {
		t.Fatal(err)
	}
	items := []db.AssetDiscoveryNotebookItem{{TenantID: "default", ProjectID: project.ID, NormalizedTarget: "https://existing.example.com", TargetHash: "existing"}, {TenantID: "default", ProjectID: project.ID, NormalizedTarget: "https://new.example.com", TargetHash: "new"}}
	if err := store.Create(&items).Error; err != nil {
		t.Fatal(err)
	}
	task := db.RootTask{ID: "preview-task", TenantID: "default", ProjectID: project.ID, Name: "Preview", Status: "Finished", OriginalTargets: `["https://existing.example.com"]`, Config: `{}`, CurrentConfigVersion: 1, RuleVersion: "rules-a"}
	if err := store.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	revision := db.NewTaskConfigRevision(task, 1, `{}`, `{}`, "9", "test")
	if err := store.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.TaskBatch{ID: "existing-batch", TenantID: "default", ProjectID: project.ID, RootTaskID: task.ID, Sequence: 0, Targets: `["https://existing.example.com"]`, TargetType: "url"}).Error; err != nil {
		t.Fatal(err)
	}
	// SQLite assigns IDs deterministically here, but use the created values to keep the test backend-neutral.
	request := `{"task_id":"preview-task","item_ids":[` + strconv.FormatUint(uint64(items[0].ID), 10) + `,` + strconv.FormatUint(uint64(items[1].ID), 10) + `]}`
	r := invokeNotebookDistributionPreview(t, project.ID, request, "default", "operator")
	if r.Code != http.StatusOK {
		t.Fatalf("preview=%d %s", r.Code, r.Body.String())
	}
	if r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache header=%q", r.Header().Get("Cache-Control"))
	}
	var response notebookDistributionPreviewResponse
	if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Counts.Selected != 2 || response.Counts.Fresh != 1 || response.Counts.Duplicates != 1 || response.Counts.ProjectScopeAdded != 1 || response.Counts.ProjectSeedTargetsAdded != 1 || response.BatchProfile.TotalBatches != 1 {
		t.Fatalf("response=%+v", response)
	}
	var batches, audits, roots int64
	store.Model(&db.TaskBatch{}).Count(&batches)
	store.Model(&db.TaskAudit{}).Count(&audits)
	store.Model(&db.RootTask{}).Count(&roots)
	if batches != 1 || audits != 0 || roots != 1 {
		t.Fatalf("preview mutated database: batches=%d audits=%d roots=%d", batches, audits, roots)
	}
	firstHash := response.PlanHash
	reversed := `{"task_id":"preview-task","item_ids":[` + strconv.FormatUint(uint64(items[1].ID), 10) + `,` + strconv.FormatUint(uint64(items[0].ID), 10) + `]}`
	r = invokeNotebookDistributionPreview(t, project.ID, reversed, "default", "operator")
	var reordered notebookDistributionPreviewResponse
	_ = json.Unmarshal(r.Body.Bytes(), &reordered)
	if r.Code != http.StatusOK || reordered.PlanHash != firstHash {
		t.Fatal("same selected targets in a different order changed hash")
	}
	task.RuleVersion = "rules-b"
	if err := store.Save(&task).Error; err != nil {
		t.Fatal(err)
	}
	r = invokeNotebookDistributionPreview(t, project.ID, request, "default", "operator")
	var changed notebookDistributionPreviewResponse
	_ = json.Unmarshal(r.Body.Bytes(), &changed)
	if r.Code != http.StatusOK || changed.PlanHash == firstHash {
		t.Fatalf("task version did not affect hash: %d %+v", r.Code, changed)
	}
	if err := store.Model(&db.TaskConfigRevision{}).Where("root_task_id = ?", task.ID).Update("config_hash", "changed-config").Error; err != nil {
		t.Fatal(err)
	}
	r = invokeNotebookDistributionPreview(t, project.ID, request, "default", "operator")
	var configChanged notebookDistributionPreviewResponse
	_ = json.Unmarshal(r.Body.Bytes(), &configChanged)
	if configChanged.PlanHash == changed.PlanHash {
		t.Fatal("config did not affect hash")
	}
	task.OriginalTargets = `["https://existing.example.com","https://another.example.com"]`
	if err := store.Save(&task).Error; err != nil {
		t.Fatal(err)
	}
	r = invokeNotebookDistributionPreview(t, project.ID, request, "default", "operator")
	var targetsChanged notebookDistributionPreviewResponse
	_ = json.Unmarshal(r.Body.Bytes(), &targetsChanged)
	if targetsChanged.PlanHash == configChanged.PlanHash {
		t.Fatal("existing targets did not affect hash")
	}
	project.Scope = `["https://scope-changed.example.com"]`
	if err := store.Save(&project).Error; err != nil {
		t.Fatal(err)
	}
	r = invokeNotebookDistributionPreview(t, project.ID, request, "default", "operator")
	var scopeChanged notebookDistributionPreviewResponse
	_ = json.Unmarshal(r.Body.Bytes(), &scopeChanged)
	if scopeChanged.PlanHash == targetsChanged.PlanHash {
		t.Fatal("project scope did not affect hash")
	}
	task.Status = "Paused"
	if err := store.Save(&task).Error; err != nil {
		t.Fatal(err)
	}
	r = invokeNotebookDistributionPreview(t, project.ID, request, "default", "operator")
	var statusChanged notebookDistributionPreviewResponse
	_ = json.Unmarshal(r.Body.Bytes(), &statusChanged)
	if statusChanged.PlanHash == scopeChanged.PlanHash {
		t.Fatal("task status did not affect hash")
	}
	if r := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"preview-task","item_ids":[`+strconv.FormatUint(uint64(items[0].ID), 10)+`,`+strconv.FormatUint(uint64(items[0].ID), 10)+`]}`, "default", "operator"); r.Code != http.StatusBadRequest {
		t.Fatalf("duplicate ids=%d", r.Code)
	}
	callback := "test:notebook-distribution-rule-context"
	requestContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := store.Callback().Query().Before("gorm:query").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table == "system_configs" {
			cancel()
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer store.Callback().Query().Remove(callback)
	path := "/projects/" + project.ID + "/asset-discovery/notebook-distributions/preview"
	ctx, recorder := newTenantContextWithRole(http.MethodPost, path, "operator", "9")
	ctx.Set("tenant", "default")
	ctx.Params = gin.Params{{Key: "id", Value: project.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(request)).WithContext(requestContext)
	previewProjectNotebookDistribution(ctx)
	if recorder.Code != http.StatusGatewayTimeout || recorder.Body.Len() == 0 {
		t.Fatalf("cancelled rule lookup=%d %s", recorder.Code, recorder.Body.String())
	}
}

func TestNotebookDistributionPreviewRouteRBACAndBoundaries(t *testing.T) {
	if got := matchPermission(http.MethodPost, "/api/v1/projects/p/asset-discovery/notebook-distributions/preview"); got != "operator" {
		t.Fatalf("permission=%q", got)
	}
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.RootTask{}, &db.TaskConfigRevision{}); err != nil {
		t.Fatal(err)
	}
	project := seedAssetDiscoveryHistoryProject(t, store, "distribution-boundary", "default", "9")
	if r := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"missing","item_ids":[1]}`, "default", "operator"); r.Code != http.StatusNotFound {
		t.Fatalf("missing task=%d", r.Code)
	}
	if r := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"missing","item_ids":[1],"extra":true}`, "default", "operator"); r.Code != http.StatusBadRequest {
		t.Fatalf("strict body=%d", r.Code)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"tenant_id": "default", "role": "viewer", "user_id": "9", "exp": time.Now().Add(time.Hour).Unix()})
	signed, err := token.SignedString(currentJWTSecret())
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(RouterDependencies{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/"+project.ID+"/asset-discovery/notebook-distributions/preview", strings.NewReader(`{"task_id":"missing","item_ids":[1]}`))
	request.Header.Set("Authorization", "Bearer "+signed)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("viewer status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestNotebookDistributionPreviewRejectsLifecycleAndScopedItemsWithoutWrites(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.RootTask{}, &db.TaskBatch{}, &db.TaskConfigRevision{}, &db.TaskAudit{}, &db.SystemConfig{}); err != nil {
		t.Fatal(err)
	}
	project := seedAssetDiscoveryHistoryProject(t, store, "distribution-lifecycle", "default", "9")
	item := db.AssetDiscoveryNotebookItem{TenantID: "default", ProjectID: project.ID, NormalizedTarget: "https://item.example.com", TargetHash: "item"}
	if err := store.Create(&item).Error; err != nil {
		t.Fatal(err)
	}
	task := db.RootTask{ID: "lifecycle-task", TenantID: "default", ProjectID: project.ID, Status: "Running", Config: `{}`, CurrentConfigVersion: 1}
	if err := store.Create(&task).Error; err != nil {
		t.Fatal(err)
	}
	revision := db.NewTaskConfigRevision(task, 1, `{}`, `{}`, "9", "test")
	if err := store.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}
	valid := `{"task_id":"lifecycle-task","item_ids":[` + strconv.FormatUint(uint64(item.ID), 10) + `]}`
	for _, status := range []string{"CancelPending"} {
		task.Status = status
		if err := store.Save(&task).Error; err != nil {
			t.Fatal(err)
		}
		if r := invokeNotebookDistributionPreview(t, project.ID, valid, "default", "operator"); r.Code != http.StatusConflict {
			t.Fatalf("status %s=%d", status, r.Code)
		}
	}
	now := time.Now()
	task.Status = "Running"
	task.ArchivedAt = &now
	if err := store.Save(&task).Error; err != nil {
		t.Fatal(err)
	}
	if r := invokeNotebookDistributionPreview(t, project.ID, valid, "default", "operator"); r.Code != http.StatusConflict {
		t.Fatalf("archived task=%d", r.Code)
	}
	task.ArchivedAt = nil
	if err := store.Save(&task).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Model(&db.TaskConfigRevision{}).Where("root_task_id = ?", task.ID).Update("config", `{"Hunter":true}`).Error; err != nil {
		t.Fatal(err)
	}
	if r := invokeNotebookDistributionPreview(t, project.ID, valid, "default", "operator"); r.Code != http.StatusConflict {
		t.Fatalf("non-direct=%d", r.Code)
	}
	if err := store.Model(&db.TaskConfigRevision{}).Where("root_task_id = ?", task.ID).Update("config", `{"NoPoc":false}`).Error; err != nil {
		t.Fatal(err)
	}
	if r := invokeNotebookDistributionPreview(t, project.ID, valid, "default", "operator"); r.Code != http.StatusConflict {
		t.Fatalf("unsafe config=%d", r.Code)
	}
	if err := store.Model(&db.TaskConfigRevision{}).Where("root_task_id = ?", task.ID).Update("config", `{}`).Error; err != nil {
		t.Fatal(err)
	}
	if r := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"lifecycle-task","item_ids":[999999]}`, "default", "operator"); r.Code != http.StatusNotFound {
		t.Fatalf("missing item=%d", r.Code)
	}
	foreignProject := db.Project{ID: "distribution-foreign-project", TenantID: "default", OwnerUserID: "9", Status: "active"}
	foreignTenantProject := db.Project{ID: "distribution-foreign-tenant", TenantID: "tenant-b", OwnerUserID: "9", Status: "active"}
	if err := store.Create(&foreignProject).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&foreignTenantProject).Error; err != nil {
		t.Fatal(err)
	}
	foreignItem := db.AssetDiscoveryNotebookItem{TenantID: "default", ProjectID: foreignProject.ID, NormalizedTarget: "https://foreign-project.example.com", TargetHash: "foreign-project"}
	foreignTenantItem := db.AssetDiscoveryNotebookItem{TenantID: "tenant-b", ProjectID: foreignTenantProject.ID, NormalizedTarget: "https://foreign-tenant.example.com", TargetHash: "foreign-tenant"}
	if err := store.Create(&foreignItem).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&foreignTenantItem).Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint{foreignItem.ID, foreignTenantItem.ID} {
		if r := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"lifecycle-task","item_ids":[`+strconv.FormatUint(uint64(id), 10)+`]}`, "default", "operator"); r.Code != http.StatusNotFound {
			t.Fatalf("foreign item %d=%d", id, r.Code)
		}
	}
	ids := strings.TrimRight(strings.Repeat("1,", 101), ",")
	if r := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"lifecycle-task","item_ids":[`+ids+`]}`, "default", "operator"); r.Code != http.StatusBadRequest {
		t.Fatalf("101 ids=%d", r.Code)
	}
	if r := invokeNotebookDistributionPreview(t, project.ID, `{"task_id":"lifecycle-task","item_ids":[1],"pad":"`+strings.Repeat("a", int(assetDiscoveryRequestLimit))+`"}`, "default", "operator"); r.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized=%d", r.Code)
	}
	project.Status = "archived"
	if err := store.Save(&project).Error; err != nil {
		t.Fatal(err)
	}
	if r := invokeNotebookDistributionPreview(t, project.ID, valid, "default", "operator"); r.Code != http.StatusConflict {
		t.Fatalf("archived project=%d", r.Code)
	}
	var batches, audits, items int64
	store.Model(&db.TaskBatch{}).Count(&batches)
	store.Model(&db.TaskAudit{}).Count(&audits)
	store.Model(&db.AssetDiscoveryNotebookItem{}).Count(&items)
	if batches != 0 || audits != 0 || items != 3 {
		t.Fatalf("preview writes: batches=%d audits=%d items=%d", batches, audits, items)
	}
}
