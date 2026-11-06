package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// purgeAPITestChildTables 镜像 db.purgeChildTables 中除 task_audits 外的任务级联表，
// 供 api 层测试建最小 schema（生产表集合见 db.task_purge.go）。
var purgeAPITestChildTables = []string{
	"asset_discovery_notebook_distribution_intents",
	"asset_discovery_notebook_distribution_materializations",
	"risk_validation_execution_idempotencies",
	"scan_timing_events",
	"task_append_idempotencies",
	"task_batch_retry_idempotencies",
	"task_creation_idempotencies",
	"task_retry_idempotencies",
	"task_config_revisions",
	"scan_observations",
	"scan_stage_derivations",
	"scan_policy_intents",
	"task_coverage_links",
	"assets",
	"fingerprint_hits",
	"vulnerabilities",
	"sensitive_findings",
	"crawl_site_candidates",
	"credential_bundles",
	"credential_finding_secrets",
	"subdomain_passive_jobs",
	"egress_ban_events",
	"ai_finding_reviews",
	"task_batches",
	"sub_tasks",
}

func setupPurgeAPITestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.Project{}, &db.ProjectMember{}, &db.RootTask{}, &db.TaskAudit{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	for _, tbl := range purgeAPITestChildTables {
		if err := store.Exec("CREATE TABLE " + tbl + " (tenant_id TEXT, project_id TEXT, root_task_id TEXT)").Error; err != nil {
			t.Fatalf("create %s: %v", tbl, err)
		}
	}
	if err := store.Exec("CREATE TABLE scan_coverages (tenant_id TEXT, project_id TEXT, source_task_id TEXT)").Error; err != nil {
		t.Fatalf("create scan_coverages: %v", err)
	}
	old := db.DB
	db.DB = store
	t.Cleanup(func() { db.DB = old })
	return store
}

func purgeTaskRequest(t *testing.T, taskID, body, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+taskID+"/purge", role, userID)
	ctx.Params = gin.Params{{Key: "id", Value: taskID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+taskID+"/purge", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	purgeTask(ctx)
	return recorder
}

func TestPurgeTaskEndpointSuccessForOwner(t *testing.T) {
	store := setupPurgeAPITestDB(t)
	project := db.Project{ID: "project-purge-api", TenantID: "default", OwnerUserID: "1", Status: "active", Scope: `[]`, SeedTargets: `[]`}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	root := db.RootTask{ID: "task-purge-api", TenantID: "default", ProjectID: project.ID, UserID: "1", Status: "Finished"}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	for _, tbl := range purgeAPITestChildTables {
		if err := store.Exec("INSERT INTO "+tbl+" (tenant_id, project_id, root_task_id) VALUES (?,?,?)", "default", project.ID, root.ID).Error; err != nil {
			t.Fatalf("insert %s: %v", tbl, err)
		}
	}
	if err := store.Exec("INSERT INTO scan_coverages (tenant_id, project_id, source_task_id) VALUES (?,?,?)", "default", project.ID, root.ID).Error; err != nil {
		t.Fatal(err)
	}

	recorder := purgeTaskRequest(t, root.ID, `{"confirm":true}`, "operator", "1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("purge status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"purged"`) {
		t.Errorf("unexpected body: %s", recorder.Body.String())
	}
	var rootCount, assetCount int64
	store.Model(&db.RootTask{}).Where("id = ?", root.ID).Count(&rootCount)
	store.Table("assets").Where("root_task_id = ?", root.ID).Count(&assetCount)
	if rootCount != 0 || assetCount != 0 {
		t.Errorf("task data should be purged: root=%d assets=%d", rootCount, assetCount)
	}
	var audits []db.TaskAudit
	if err := store.Where("root_task_id = ?", root.ID).Find(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 || audits[0].Action != "hard_delete" || audits[0].OperatorID != "1" {
		t.Errorf("expected one hard_delete audit by owner, got %+v", audits)
	}
}

func TestPurgeTaskEndpointGuardRails(t *testing.T) {
	store := setupPurgeAPITestDB(t)
	projects := []db.Project{
		{ID: "project-purge-foreign", TenantID: "default", OwnerUserID: "99", Status: "active", Scope: `[]`, SeedTargets: `[]`},
		{ID: "project-purge-running", TenantID: "default", OwnerUserID: "1", Status: "active", Scope: `[]`, SeedTargets: `[]`},
		{ID: "project-purge-terminal", TenantID: "default", OwnerUserID: "1", Status: "active", Scope: `[]`, SeedTargets: `[]`},
	}
	if err := store.Create(&projects).Error; err != nil {
		t.Fatal(err)
	}
	tasks := []db.RootTask{
		{ID: "task-purge-foreign", TenantID: "default", ProjectID: projects[0].ID, Status: "Finished"},
		{ID: "task-purge-running", TenantID: "default", ProjectID: projects[1].ID, Status: "Running"},
		{ID: "task-purge-terminal", TenantID: "default", ProjectID: projects[2].ID, Status: "Finished"},
	}
	if err := store.Create(&tasks).Error; err != nil {
		t.Fatal(err)
	}

	// 缺失任务 → 404
	if recorder := purgeTaskRequest(t, "task-does-not-exist", `{"confirm":true}`, "admin", "1"); recorder.Code != http.StatusNotFound {
		t.Errorf("missing task: status=%d want 404", recorder.Code)
	}
	// 非 owner / 非 admin → 403
	if recorder := purgeTaskRequest(t, "task-purge-foreign", `{"confirm":true}`, "operator", "1"); recorder.Code != http.StatusForbidden {
		t.Errorf("foreign project: status=%d want 403 body=%s", recorder.Code, recorder.Body.String())
	}
	// 非终态 → 409（owner 本人）
	if recorder := purgeTaskRequest(t, "task-purge-running", `{"confirm":true}`, "operator", "1"); recorder.Code != http.StatusConflict {
		t.Errorf("running task: status=%d want 409 body=%s", recorder.Code, recorder.Body.String())
	}
	// 终态但缺确认 → 400
	if recorder := purgeTaskRequest(t, "task-purge-terminal", `{}`, "operator", "1"); recorder.Code != http.StatusBadRequest {
		t.Errorf("missing confirm: status=%d want 400 body=%s", recorder.Code, recorder.Body.String())
	}

	// 守卫全部拦截：任何任务都不应被删、不应产生 hard_delete 审计。
	var rootCount int64
	store.Model(&db.RootTask{}).Count(&rootCount)
	if rootCount != int64(len(tasks)) {
		t.Errorf("guard rails should not delete tasks, root count=%d", rootCount)
	}
	var auditCount int64
	store.Model(&db.TaskAudit{}).Where("action = ?", "hard_delete").Count(&auditCount)
	if auditCount != 0 {
		t.Errorf("guard rails should not write hard_delete audits, count=%d", auditCount)
	}
}
