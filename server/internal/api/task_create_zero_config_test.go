package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
)

func withTaskCreateQueue(t *testing.T) {
	t.Helper()
	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() {
		queue.Close()
		routerRuntime().TaskQueue = oldQueue
	})
}

func TestCreateTaskUsesProjectScopeAndSafeDefaults(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{
		ID: "project-zero-config", TenantID: "default", OwnerUserID: "1", Status: "active",
		SeedTargets: `["https://seed.example.test"]`, Scope: `["https://scope.example.test"]`,
	}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	withTaskCreateQueue(t)

	c, w := newTenantContextWithRole(http.MethodPost, "/tasks", "operator", "1")
	c.Request = httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(`{"project_id":"project-zero-config"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	createTask(c)

	if w.Code != http.StatusOK {
		t.Fatalf("create task status = %d, body=%s", w.Code, w.Body.String())
	}
	var response struct {
		TaskID       string `json:"task_id"`
		Profile      string `json:"profile"`
		TargetSource string `json:"target_source"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.TaskID == "" || response.Profile != "external-map" || response.TargetSource != "project_scope" {
		t.Fatalf("unexpected response: %+v", response)
	}

	var root db.RootTask
	if err := store.First(&root, "id = ?", response.TaskID).Error; err != nil {
		t.Fatalf("load root task: %v", err)
	}
	if root.Name != "https://seed.example.test" || root.Priority != 1 || root.TimeoutSec != 3600 || root.TotalTargets != 2 {
		t.Fatalf("unexpected zero-config root: %+v", root)
	}
	var cfg taskScanConfig
	if err := json.Unmarshal([]byte(root.Config), &cfg); err != nil {
		t.Fatalf("decode task config: %v", err)
	}
	if !cfg.NoPoc || cfg.GolangPoc || !cfg.DisableGeneralPoc || !cfg.Subdomain || !cfg.NoSubdomainBruteForce || cfg.NoSubFinder {
		t.Fatalf("unexpected safe defaults: %+v", cfg)
	}

	var audit db.TaskAudit
	if err := store.Where("root_task_id = ? AND action = ?", root.ID, "create").First(&audit).Error; err != nil {
		t.Fatalf("load create audit: %v", err)
	}
	if audit.OperatorID != "1" || !strings.Contains(audit.Details, `"target_source":"project_scope"`) || !strings.Contains(audit.Details, `"poc_enabled":false`) {
		t.Fatalf("unexpected create audit: %+v", audit)
	}
}

func TestCreateTaskExpandsProjectScopeAndPreservesExplicitPriority(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{
		ID: "project-explicit-zero", TenantID: "default", OwnerUserID: "1", Status: "active",
		SeedTargets: `[]`, Scope: `[]`,
	}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	withTaskCreateQueue(t)

	c, w := newTenantContextWithRole(http.MethodPost, "/tasks", "operator", "1")
	c.Request = httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(`{
		"project_id":"project-explicit-zero",
		"targets":"https://new.example.test",
		"priority":0,
		"timeout_sec":0
	}`))
	c.Request.Header.Set("Content-Type", "application/json")
	createTask(c)

	if w.Code != http.StatusOK {
		t.Fatalf("create task status = %d, body=%s", w.Code, w.Body.String())
	}
	var response struct {
		TaskID            string `json:"task_id"`
		ProjectScopeAdded int    `json:"project_scope_added"`
		ProjectSeedsAdded int    `json:"project_seeds_added"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var root db.RootTask
	if err := store.First(&root, "id = ?", response.TaskID).Error; err != nil {
		t.Fatalf("load root task: %v", err)
	}
	if root.Priority != 0 || root.TimeoutSec != 0 {
		t.Fatalf("explicit zero values were not preserved: priority=%d timeout=%d", root.Priority, root.TimeoutSec)
	}
	if response.ProjectScopeAdded != 1 || response.ProjectSeedsAdded != 1 {
		t.Fatalf("expected project scope expansion, got %+v", response)
	}
	if err := store.First(&project, "id = ?", project.ID).Error; err != nil {
		t.Fatalf("reload project: %v", err)
	}
	if project.Scope != `["https://new.example.test"]` || project.SeedTargets != `["https://new.example.test"]` {
		t.Fatalf("unexpected project targets: scope=%s seeds=%s", project.Scope, project.SeedTargets)
	}
}
