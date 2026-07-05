package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	aipkg "github.com/user/dddd-server/internal/ai"
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
)

func ptrTime(v time.Time) *time.Time {
	return &v
}

func TestShouldAgentReloadRules(t *testing.T) {
	tests := []struct {
		name             string
		agentRuleVersion string
		ruleVersion      string
		want             bool
	}{
		{name: "unknown current version", agentRuleVersion: "v1", ruleVersion: "unknown", want: false},
		{name: "empty current version", agentRuleVersion: "v1", ruleVersion: "", want: false},
		{name: "up to date", agentRuleVersion: "v2", ruleVersion: "v2", want: false},
		{name: "agent missing version", agentRuleVersion: "", ruleVersion: "v2", want: true},
		{name: "agent outdated", agentRuleVersion: "v1", ruleVersion: "v2", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldAgentReloadRules(tt.agentRuleVersion, tt.ruleVersion); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestAIPermissions(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{method: "POST", path: "/api/v1/ai/arsenal/analyze", want: "operator"},
		{method: "POST", path: "/api/v1/ai/arsenal/analyze/stream", want: "operator"},
		{method: "POST", path: "/api/v1/ai/chat", want: "operator"},
		{method: "POST", path: "/api/v1/ai/actions/confirm", want: "operator"},
		{method: "GET", path: "/api/v1/ai/copilot/prompts", want: "operator"},
		{method: "GET", path: "/api/v1/ai/tool-invocations", want: "operator"},
		{method: "GET", path: "/api/v1/ai/config", want: "admin"},
		{method: "PUT", path: "/api/v1/ai/config", want: "admin"},
		{method: "GET", path: "/api/v1/ai/models", want: "admin"},
		{method: "POST", path: "/api/v1/ai/test", want: "admin"},
	}
	for _, tt := range tests {
		if got := matchPermission(tt.method, tt.path); got != tt.want {
			t.Fatalf("%s %s expected %s, got %s", tt.method, tt.path, tt.want, got)
		}
	}
}

func TestTenantRolePermissionMatrix(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{method: "GET", path: "/api/v1/projects", want: "viewer"},
		{method: "GET", path: "/api/v1/tasks/task-1", want: "viewer"},
		{method: "GET", path: "/api/v1/reports/export/vulns", want: "viewer"},
		{method: "POST", path: "/api/v1/projects", want: "operator"},
		{method: "GET", path: "/api/v1/projects/proj-1/members", want: "operator"},
		{method: "PUT", path: "/api/v1/projects/proj-1/members", want: "operator"},
		{method: "POST", path: "/api/v1/tasks", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/preview-selector", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/cancel", want: "operator"},
		{method: "DELETE", path: "/api/v1/nodes/agent-1", want: "operator"},
		{method: "POST", path: "/api/v1/dictionaries/workflow", want: "operator"},
		{method: "PUT", path: "/api/v1/dictionaries/workflow/product", want: "operator"},
		{method: "POST", path: "/api/v1/arsenals/poc/demo.yaml", want: "operator"},
		{method: "POST", path: "/api/v1/arsenals/poc/demo.yaml/approve", want: "admin"},
		{method: "POST", path: "/api/v1/arsenals/poc/demo.yaml/rollback", want: "admin"},
		{method: "GET", path: "/api/v1/arsenals/seed-db", want: "admin"},
		{method: "GET", path: "/api/v1/exploits", want: "viewer"},
		{method: "POST", path: "/api/v1/exploits/source/validate", want: "operator"},
		{method: "POST", path: "/api/v1/exploits/source/dry-run", want: "operator"},
		{method: "POST", path: "/api/v1/exploits/source/debug", want: "operator"},
		{method: "POST", path: "/api/v1/exploits/12/dry-run", want: "operator"},
		{method: "POST", path: "/api/v1/exploits/12/approve", want: "admin"},
		{method: "POST", path: "/api/v1/exploits/12/risk-waiver", want: "admin"},
		{method: "POST", path: "/api/v1/exploit-runs", want: "operator"},
		{method: "GET", path: "/api/v1/agents/agent-1/pyenv", want: "operator"},
		{method: "POST", path: "/api/v1/agents/agent-1/pyenv/install", want: "admin"},
		{method: "GET", path: "/api/v1/agents/agent-1/pyenv/jobs/job-1", want: "operator"},
		{method: "GET", path: "/api/v1/mcp/resources/pyexp/spec", want: "operator"},
		{method: "POST", path: "/api/v1/mcp/tools/poc/debug", want: "operator"},
		{method: "POST", path: "/api/v1/mcp/tools/agent/python-run", want: "admin"},
		{method: "POST", path: "/api/v1/mcp/tools/rule/context", want: "operator"},
		{method: "POST", path: "/api/v1/mcp/tools/rule/debug", want: "operator"},
		{method: "POST", path: "/api/v1/mcp/tools/rule/save", want: "operator"},
		{method: "POST", path: "/api/v1/mcp/tools/rule/apply", want: "admin"},
		{method: "GET", path: "/api/v1/users", want: "operator"},
		{method: "GET", path: "/api/v1/roles", want: "admin"},
		{method: "POST", path: "/api/v1/roles", want: "admin"},
		{method: "PUT", path: "/api/v1/roles/security-reviewer", want: "admin"},
		{method: "DELETE", path: "/api/v1/roles/security-reviewer", want: "admin"},
		{method: "GET", path: "/api/v1/cloud/accounts", want: "operator"},
		{method: "POST", path: "/api/v1/cloud/accounts/ca-1/oss/upload", want: "operator"},
		{method: "POST", path: "/api/v1/build/client", want: "admin"},
		{method: "POST", path: "/api/v1/build/jobs/1/cancel", want: "admin"},
		{method: "POST", path: "/api/v1/build/jobs/1/retry", want: "admin"},
		{method: "GET", path: "/api/v1/undocumented", want: "admin"},
	}
	for _, tt := range tests {
		if got := matchPermission(tt.method, tt.path); got != tt.want {
			t.Fatalf("%s %s expected %s, got %s", tt.method, tt.path, tt.want, got)
		}
	}
}

func TestExportVulnsRecordsReportObject(t *testing.T) {
	store := setupAITestDB(t)
	oldRoot := objectStorageRoot
	objectStorageRoot = t.TempDir()
	t.Cleanup(func() {
		objectStorageRoot = oldRoot
	})
	if err := store.Create(&db.Vulnerability{
		TenantID:  "default",
		ProjectID: "p1",
		TaskID:    "task-1",
		Target:    "https://example.com",
		Plugin:    "poc-demo",
		Severity:  "high",
	}).Error; err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/reports/export/vulns", "admin", "7")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/reports/export/vulns", nil)
	exportVulns(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected export 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "poc-demo") {
		t.Fatalf("expected CSV body to contain vulnerability row, got %s", recorder.Body.String())
	}
	var report db.Report
	if err := store.Where("type = ? AND format = ?", "vulnerabilities", "csv").First(&report).Error; err != nil {
		t.Fatalf("expected report metadata: %v", err)
	}
	key := strings.TrimPrefix(report.FileURL, "local://")
	if key == report.FileURL || key == "" {
		t.Fatalf("unexpected report file url: %s", report.FileURL)
	}
	if _, err := os.Stat(filepath.Join(objectStorageRoot, filepath.FromSlash(key))); err != nil {
		t.Fatalf("expected report object file: %v", err)
	}
}

func TestCustomRoleResolvesToBaseRole(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.CustomRole{
		TenantID: "tenant-a",
		Name:     "task-runner",
		Label:    "任务执行员",
		BaseRole: "operator",
	}).Error; err != nil {
		t.Fatalf("create custom role: %v", err)
	}
	if got := roleLevelForTenant("tenant-a", "task-runner"); got != roleHierarchy["operator"] {
		t.Fatalf("expected operator level, got %d", got)
	}
	if got := roleLevelForTenant("tenant-b", "task-runner"); got != roleHierarchy["viewer"] {
		t.Fatalf("expected unknown tenant custom role to fall back to viewer, got %d", got)
	}
	if role, ok := normalizeUserRoleForTenant("tenant-a", "task-runner"); !ok || role != "task-runner" {
		t.Fatalf("expected tenant custom role to be accepted, role=%q ok=%v", role, ok)
	}
	if _, ok := normalizeUserRoleForTenant("tenant-b", "task-runner"); ok {
		t.Fatalf("expected custom role from another tenant to be rejected")
	}
}

func TestRoleHandlersProtectBuiltinsAndAssignedRoles(t *testing.T) {
	store := setupAITestDB(t)
	ctx, recorder := newTenantContext(http.MethodPost, "/roles")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/roles", strings.NewReader(`{
		"name":"security-reviewer",
		"label":"安全观察员",
		"base_role":"viewer",
		"description":"review only"
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	createRole(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected create role ok, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	if role, ok := normalizeUserRoleForTenant("default", "security-reviewer"); !ok || role != "security-reviewer" {
		t.Fatalf("expected created custom role to be accepted, role=%q ok=%v", role, ok)
	}

	if err := store.Create(&db.User{TenantID: "default", Username: "reviewer", Role: "security-reviewer", Status: "active"}).Error; err != nil {
		t.Fatalf("assign role to user: %v", err)
	}

	ctx, recorder = newTenantContext(http.MethodDelete, "/roles/security-reviewer")
	ctx.Params = gin.Params{{Key: "name", Value: "security-reviewer"}}
	deleteRole(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected assigned role delete to conflict, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = newTenantContext(http.MethodDelete, "/roles/admin")
	ctx.Params = gin.Params{{Key: "name", Value: "admin"}}
	deleteRole(ctx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected built-in delete to fail, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestCreateTaskRejectsTenantQuotaExceeded(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-quota", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.TenantQuota{TenantID: "default", MaxConcurrentTasks: 1, DailyTaskLimit: 10}).Error; err != nil {
		t.Fatalf("seed quota: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "active-task", TenantID: "default", ProjectID: "project-quota", Status: "Running", CreatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("seed active task: %v", err)
	}

	oldQueue := taskQueue
	taskQueue = scheduler.NewTaskQueue("")
	t.Cleanup(func() { taskQueue = oldQueue })

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks", "operator", "1")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(`{
		"project_id":"project-quota",
		"name":"quota blocked",
		"targets":"https://example.com",
		"config":{},
		"priority":1
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	createTask(ctx)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected quota rejection 429, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var rootCount int64
	store.Model(&db.RootTask{}).Where("tenant_id = ?", "default").Count(&rootCount)
	if rootCount != 1 {
		t.Fatalf("expected no new root task after quota rejection, got %d", rootCount)
	}
}

func TestListPocRulesFiltersMetadata(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.PocRule{
		TenantID:            "default",
		SourceFile:          "demo.yaml",
		Name:                "demo-poc",
		TargetProduct:       "DemoProduct",
		CVE:                 "CVE-2026-0003",
		CompatibilityStatus: "indexed",
		Severity:            "high",
		Enabled:             true,
	}).Error; err != nil {
		t.Fatalf("seed poc rule: %v", err)
	}
	if err := store.Create(&db.PocRule{
		TenantID:            "default",
		SourceFile:          "other.yaml",
		Name:                "other-poc",
		TargetProduct:       "OtherProduct",
		CVE:                 "CVE-2026-9999",
		CompatibilityStatus: "unknown",
		Severity:            "low",
		Enabled:             true,
	}).Error; err != nil {
		t.Fatalf("seed other poc rule: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/poc-rules?product=demo&cve=2026-0003&compatibility_status=indexed", "viewer", "1")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/poc-rules?product=demo&cve=2026-0003&compatibility_status=indexed", nil)
	listPocRules(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp []pocRuleResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp) != 1 || resp[0].Name != "demo-poc" || resp[0].CVE != "CVE-2026-0003" {
		t.Fatalf("unexpected filtered poc rules: %+v", resp)
	}
}

func TestRBACRequiresUserEXPAuthorization(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.User{
		ID:            1,
		TenantID:      "tenant-a",
		Username:      "authorized",
		Role:          "operator",
		Status:        "active",
		ExpAuthorized: true,
	}).Error; err != nil {
		t.Fatalf("create authorized user: %v", err)
	}
	if err := store.Create(&db.User{
		ID:            2,
		TenantID:      "tenant-a",
		Username:      "plain",
		Role:          "operator",
		Status:        "active",
		ExpAuthorized: false,
	}).Error; err != nil {
		t.Fatalf("create plain user: %v", err)
	}

	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name   string
		userID string
		want   int
	}{
		{name: "authorized user can view exp", userID: "1", want: http.StatusOK},
		{name: "unauthorized user is blocked", userID: "2", want: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("tenant", "tenant-a")
				c.Set("role", "operator")
				c.Set("user_id", tt.userID)
				c.Next()
			})
			r.Use(RBACMiddleware())
			r.GET("/api/v1/exploits", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/exploits", nil)
			r.ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Fatalf("expected status %d, got %d body=%s", tt.want, w.Code, w.Body.String())
			}
		})
	}
}

func TestNormalizeUserRoleAndStatus(t *testing.T) {
	if got, ok := normalizeUserRole(""); !ok || got != "viewer" {
		t.Fatalf("empty role should default to viewer, got %q ok=%v", got, ok)
	}
	if got, ok := normalizeUserRole("operator"); !ok || got != "operator" {
		t.Fatalf("operator role should be accepted, got %q ok=%v", got, ok)
	}
	if _, ok := normalizeUserRole("owner"); ok {
		t.Fatalf("unknown role should be rejected")
	}
	if got, ok := normalizeUserStatus("disabled"); !ok || got != "disabled" {
		t.Fatalf("disabled status should be accepted, got %q ok=%v", got, ok)
	}
	if _, ok := normalizeUserStatus("locked"); ok {
		t.Fatalf("unknown status should be rejected")
	}
}

func TestValidateAgentSessionBindsTenantAndRejectsMismatch(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Node{
		TenantID:       "tenant-a",
		AgentID:        "agent-a",
		Token:          "session-token",
		Status:         "Alive",
		TokenExpiresAt: ptrTime(time.Now().Add(time.Hour)),
	}).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-a/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "session-token")

	if !validateAgentSession(c) {
		t.Fatalf("expected valid agent session")
	}
	if got := c.GetString("tenant"); got != "tenant-a" {
		t.Fatalf("expected tenant-a, got %q", got)
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-b/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "session-token")

	if validateAgentSession(c) {
		t.Fatalf("expected mismatched path agent id to be rejected")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent mismatch, got %d", w.Code)
	}

	if err := store.Model(&db.Node{}).Where("agent_id = ?", "agent-a").Updates(map[string]interface{}{
		"status": "Offline",
		"token":  "session-token",
	}).Error; err != nil {
		t.Fatalf("mark node offline: %v", err)
	}
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-a/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "session-token")
	if validateAgentSession(c) {
		t.Fatalf("expected offline agent session to be rejected")
	}

	if err := store.Model(&db.Node{}).Where("agent_id = ?", "agent-a").Updates(map[string]interface{}{
		"status":           "Alive",
		"token":            "expired-token",
		"token_expires_at": time.Now().Add(-time.Minute),
		"token_revoked_at": nil,
	}).Error; err != nil {
		t.Fatalf("expire token: %v", err)
	}
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-a/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "expired-token")
	if ok := validateAgentSession(c); ok {
		t.Fatalf("expected expired agent session to be rejected")
	}

	if err := store.Model(&db.Node{}).Where("agent_id = ?", "agent-a").Updates(map[string]interface{}{
		"token":            "revoked-token",
		"token_expires_at": time.Now().Add(time.Hour),
		"token_revoked_at": time.Now(),
	}).Error; err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-a/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "revoked-token")
	if ok := validateAgentSession(c); ok {
		t.Fatalf("expected revoked agent session to be rejected")
	}
}

func TestParseAgentSelectorRejectsNestedValues(t *testing.T) {
	if _, err := parseAgentSelector(json.RawMessage(`{"cloud":"aliyun","region":"cn-hangzhou"}`)); err != nil {
		t.Fatalf("expected flat selector to pass: %v", err)
	}
	if _, err := parseAgentSelector(json.RawMessage(`{"cloud":{"provider":"aliyun"}}`)); err == nil {
		t.Fatalf("expected nested selector to fail")
	}
}

func TestPreviewTaskSelectorUsesEffectiveTargetType(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-1", TenantID: "tenant-a", Status: "active"}).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := store.Create(&db.Node{
		TenantID:     "tenant-a",
		AgentID:      "agent-url",
		Status:       "Alive",
		Tags:         `{"cloud":"aliyun","target_type":"url"}`,
		Capacity:     3,
		RunningTasks: 1,
	}).Error; err != nil {
		t.Fatalf("create matching node: %v", err)
	}
	if err := store.Create(&db.Node{
		TenantID: "tenant-a",
		AgentID:  "agent-ip",
		Status:   "Alive",
		Tags:     `{"cloud":"aliyun","target_type":"ip"}`,
		Capacity: 3,
	}).Error; err != nil {
		t.Fatalf("create mismatching node: %v", err)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("tenant", "tenant-a")
	c.Set("role", "admin")
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/tasks/preview-selector", strings.NewReader(`{
		"project_id":"project-1",
		"targets":"https://example.com",
		"config":{},
		"agent_selector":{"cloud":"aliyun"}
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	previewTaskSelector(c)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		MatchedNodes   int                 `json:"matched_nodes"`
		AvailableSlots int                 `json:"available_slots"`
		Selectors      []map[string]string `json:"effective_selectors"`
		Groups         []struct {
			TargetType     string            `json:"target_type"`
			TargetCount    int               `json:"target_count"`
			MatchedNodes   int               `json:"matched_nodes"`
			AvailableSlots int               `json:"available_slots"`
			Selector       map[string]string `json:"selector"`
			Reasons        []string          `json:"reasons"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode preview response: %v", err)
	}
	if resp.MatchedNodes != 1 || resp.AvailableSlots != 2 {
		t.Fatalf("expected one URL-capable node with two free slots, got %+v", resp)
	}
	if len(resp.Selectors) != 1 || resp.Selectors[0]["target_type"] != "url" || resp.Selectors[0]["cloud"] != "aliyun" {
		t.Fatalf("expected effective selector to include user selector and target_type=url, got %+v", resp.Selectors)
	}
	if len(resp.Groups) != 1 || resp.Groups[0].TargetType != "url" || resp.Groups[0].MatchedNodes != 1 || resp.Groups[0].AvailableSlots != 2 {
		t.Fatalf("expected grouped url preview with one node and two slots, got %+v", resp.Groups)
	}

	if err := store.Create(&db.Node{
		TenantID: "tenant-a",
		AgentID:  "agent-region",
		Status:   "Alive",
		Tags:     `{"cloud":"aliyun","target_type":"url","region":"cn-hangzhou"}`,
		Capacity: 1,
	}).Error; err != nil {
		t.Fatalf("create rules matching node: %v", err)
	}
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Set("tenant", "tenant-a")
	c.Set("role", "admin")
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/tasks/preview-selector", strings.NewReader(`{
		"project_id":"project-1",
		"targets":"https://example.com",
		"config":{},
		"agent_selector":{"cloud":"aliyun"},
		"agent_selector_rules":{"match":{"region":["cn-hangzhou","cn-shanghai"]},"not_match":{"cloud":"tencent"}}
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	previewTaskSelector(c)
	if w.Code != http.StatusOK {
		t.Fatalf("expected rules preview status 200, got %d body=%s", w.Code, w.Body.String())
	}
	resp = struct {
		MatchedNodes   int                 `json:"matched_nodes"`
		AvailableSlots int                 `json:"available_slots"`
		Selectors      []map[string]string `json:"effective_selectors"`
		Groups         []struct {
			TargetType     string            `json:"target_type"`
			TargetCount    int               `json:"target_count"`
			MatchedNodes   int               `json:"matched_nodes"`
			AvailableSlots int               `json:"available_slots"`
			Selector       map[string]string `json:"selector"`
			Reasons        []string          `json:"reasons"`
		} `json:"groups"`
	}{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode rules preview response: %v", err)
	}
	if resp.MatchedNodes != 1 || resp.AvailableSlots != 1 {
		t.Fatalf("expected selector rules to narrow matching nodes to one free slot, got %+v", resp)
	}
}

func TestTaskDetailIncludesReasonStats(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-1", TenantID: "default", Status: "active"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	root := db.RootTask{
		ID:              "task-reasons",
		TenantID:        "default",
		ProjectID:       "project-1",
		Name:            "reason stats",
		Status:          "PartialDone",
		OriginalTargets: `["https://a","https://b","https://c"]`,
		Config:          `{}`,
		TotalChunks:     3,
		TotalTargets:    3,
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	subTasks := []db.SubTask{
		{ID: "sub-failed", TenantID: "default", ProjectID: "project-1", RootTaskID: root.ID, Status: "Failed", ChunkTargets: `["https://a"]`, TimeoutSec: 60},
		{ID: "sub-timeout", TenantID: "default", ProjectID: "project-1", RootTaskID: root.ID, Status: "Timeout", ChunkTargets: `["https://b","https://c"]`, TimeoutSec: 60},
	}
	if err := store.Create(&subTasks).Error; err != nil {
		t.Fatalf("seed subtasks: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/tasks/"+root.ID)
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	getTaskDetail(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected detail response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		ReasonStats []struct {
			Status      string `json:"status"`
			Reason      string `json:"reason"`
			Count       int    `json:"count"`
			TargetCount int    `json:"target_count"`
		} `json:"reason_stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode task detail: %v", err)
	}
	if len(resp.ReasonStats) != 2 {
		t.Fatalf("expected failed and timeout reason stats, got %+v", resp.ReasonStats)
	}
	if resp.ReasonStats[0].Count == 0 || resp.ReasonStats[1].TargetCount == 0 {
		t.Fatalf("expected reason stats to include batch and target counts, got %+v", resp.ReasonStats)
	}
}

func TestBuildJobHelpers(t *testing.T) {
	if !isSupportedBuildTarget("linux", "arm64") || isSupportedBuildTarget("linux", "386") {
		t.Fatalf("unexpected linux build target validation")
	}
	if got := expectedBuildArtifact("windows", "amd64"); got != "dddd-agent-windows-amd64.exe" {
		t.Fatalf("unexpected windows artifact name: %s", got)
	}
	if got := truncateBuildLog("abcdef", 3); got != "def" {
		t.Fatalf("unexpected truncated log: %s", got)
	}
	components, err := normalizeBuildComponents([]string{"server-ui", "dddd-server", "dddd-server"})
	if err != nil {
		t.Fatalf("normalize components: %v", err)
	}
	if strings.Join(components, ",") != "server-ui,dddd-server" {
		t.Fatalf("unexpected normalized components: %+v", components)
	}
	artifacts := expectedBuildArtifacts([]string{"dddd-agent", "server-ui"}, "linux", "amd64")
	if strings.Join(artifacts, ",") != "dddd-agent-linux-amd64,server-ui-dist.tar.gz" {
		t.Fatalf("unexpected multi-component artifacts: %+v", artifacts)
	}
}

func TestCreateBuildJobIfIdleRejectsQueuedJob(t *testing.T) {
	setupAITestDB(t)

	first, err := createBuildJobIfIdle("linux", "amd64", false)
	if err != nil {
		t.Fatalf("first build job should be queued: %v", err)
	}
	if first.Status != "queued" {
		t.Fatalf("expected first job to be queued, got %q", first.Status)
	}

	if _, err := createBuildJobIfIdle("linux", "arm64", false); !errors.Is(err, errBuildAlreadyQueued) {
		t.Fatalf("expected duplicate queued job to be rejected, got %v", err)
	}
}

func TestCreateBuildJobIfIdleAllowsOnlyOneConcurrentJob(t *testing.T) {
	setupAITestDB(t)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := createBuildJobIfIdle("linux", "amd64", false)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	successes := 0
	conflicts := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		if errors.Is(err, errBuildAlreadyQueued) {
			conflicts++
			continue
		}
		t.Fatalf("unexpected create error: %v", err)
	}
	if successes != 1 || conflicts != 7 {
		t.Fatalf("expected 1 success and 7 conflicts, got %d success %d conflicts", successes, conflicts)
	}
}

func TestBuildJobLogsReturnsFullLog(t *testing.T) {
	setupAITestDB(t)
	job := db.BuildJob{Platform: "linux", Arch: "amd64", Status: "failed", LogTail: "tail", LogText: "full log"}
	if err := db.DB.Create(&job).Error; err != nil {
		t.Fatalf("seed build job: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/build/jobs/1/logs")
	ctx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(job.ID))}}
	getBuildJobLogs(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected logs response, got %d", recorder.Code)
	}
	if recorder.Body.String() != "full log" {
		t.Fatalf("expected full log, got %q", recorder.Body.String())
	}
}

func TestCancelBuildJobMarksQueuedJobCanceled(t *testing.T) {
	setupAITestDB(t)
	job, err := createBuildJobIfIdle("linux", "amd64", false)
	if err != nil {
		t.Fatalf("seed queued job: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/build/jobs/1/cancel")
	ctx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(job.ID))}}
	cancelBuildJob(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected cancel response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var updated db.BuildJob
	if err := db.DB.First(&updated, job.ID).Error; err != nil {
		t.Fatalf("load updated job: %v", err)
	}
	if updated.Status != "canceled" || updated.Error == "" || updated.FinishedAt == nil {
		t.Fatalf("expected canceled job with finished metadata, got %+v", updated)
	}
}

func TestRetryBuildJobCreatesNewQueuedJob(t *testing.T) {
	setupAITestDB(t)
	t.Chdir(t.TempDir())
	if err := os.WriteFile("build.sh", []byte("#!/bin/sh\nmkdir -p release\ntouch release/dddd-agent-linux-amd64\n"), 0o755); err != nil {
		t.Fatalf("write build script: %v", err)
	}
	oldRunner := buildJobRunner
	buildJobRunner = func(uint) {}
	t.Cleanup(func() { buildJobRunner = oldRunner })
	oldJob := db.BuildJob{Platform: "linux", Arch: "amd64", Status: "failed", Error: "boom"}
	if err := db.DB.Create(&oldJob).Error; err != nil {
		t.Fatalf("seed failed build job: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/build/jobs/1/retry")
	ctx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(oldJob.ID))}}
	retryBuildJob(ctx)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected retry response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var count int64
	if err := db.DB.Model(&db.BuildJob{}).Count(&count).Error; err != nil {
		t.Fatalf("count build jobs: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected retry to create a second build job, got %d", count)
	}
}

func TestRunBuildJobStoresFullLogAndArtifact(t *testing.T) {
	setupAITestDB(t)
	t.Chdir(t.TempDir())
	if err := os.WriteFile("build.sh", []byte("#!/bin/sh\necho full-build-log\nmkdir -p release\ntouch release/dddd-agent-linux-amd64\n"), 0o755); err != nil {
		t.Fatalf("write build script: %v", err)
	}
	job, err := createBuildJobIfIdle("linux", "amd64", false)
	if err != nil {
		t.Fatalf("seed queued job: %v", err)
	}

	runBuildJob(job.ID)

	var updated db.BuildJob
	if err := db.DB.First(&updated, job.ID).Error; err != nil {
		t.Fatalf("load updated job: %v", err)
	}
	if updated.Status != "success" || updated.Artifact != "dddd-agent-linux-amd64" {
		t.Fatalf("expected successful build artifact, got %+v", updated)
	}
	if !strings.Contains(updated.LogText, "full-build-log") || !strings.Contains(updated.LogTail, "full-build-log") {
		t.Fatalf("expected full and tail logs to include build output, got log_text=%q log_tail=%q", updated.LogText, updated.LogTail)
	}
}

func TestAgentLogSummaryAndRetentionCleanup(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AgentLog{}); err != nil {
		t.Fatalf("migrate agent logs: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed tenant node: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "other", AgentID: "agent-2", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed other tenant node: %v", err)
	}
	oldTime := time.Now().AddDate(0, 0, -30)
	nowMs := time.Now().UnixMilli()
	logs := []db.AgentLog{
		{AgentID: "agent-1", Level: "ERROR", Message: "expired", Timestamp: oldTime.UnixMilli(), CreatedAt: oldTime},
		{AgentID: "agent-1", Level: "ERROR", Message: "recent", Timestamp: nowMs, CreatedAt: time.Now()},
		{AgentID: "agent-2", Level: "ERROR", Message: "other tenant", Timestamp: nowMs, CreatedAt: time.Now()},
	}
	if err := store.Create(&logs).Error; err != nil {
		t.Fatalf("seed logs: %v", err)
	}

	deleted, err := cleanupAgentLogsOnce(7)
	if err != nil {
		t.Fatalf("cleanup logs: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected one expired log to be deleted, got %d", deleted)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/agent-logs/summary?agent_id=agent-1")
	getAgentLogSummary(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected summary response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		LevelCounts []agentLogLevelCount `json:"level_counts"`
		RecentErrs  []db.AgentLog        `json:"recent_errors"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(resp.LevelCounts) != 1 || resp.LevelCounts[0].Level != "ERROR" || resp.LevelCounts[0].Count != 1 {
		t.Fatalf("expected tenant scoped ERROR count, got %+v", resp.LevelCounts)
	}
	if len(resp.RecentErrs) != 1 || resp.RecentErrs[0].AgentID != "agent-1" {
		t.Fatalf("expected tenant scoped recent errors, got %+v", resp.RecentErrs)
	}
}

func TestGetAgentLogsUsesAgentIDPrimaryKeyAndTenantScope(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AgentLog{}); err != nil {
		t.Fatalf("migrate agent logs: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed default node: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "other", AgentID: "agent-2", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed other tenant node: %v", err)
	}
	nowMs := time.Now().UnixMilli()
	if err := store.Create(&[]db.AgentLog{
		{AgentID: "agent-1", Level: "INFO", Message: "default tenant log", Timestamp: nowMs, CreatedAt: time.Now()},
		{AgentID: "agent-2", Level: "INFO", Message: "other tenant log", Timestamp: nowMs, CreatedAt: time.Now()},
	}).Error; err != nil {
		t.Fatalf("seed logs: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/agents/agent-1/logs?limit=10")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-1"}}
	getAgentLogs(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected logs response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var logs []db.AgentLog
	if err := json.Unmarshal(recorder.Body.Bytes(), &logs); err != nil {
		t.Fatalf("decode logs: %v", err)
	}
	if len(logs) != 1 || logs[0].AgentID != "agent-1" || logs[0].Message != "default tenant log" {
		t.Fatalf("expected default tenant agent log, got %+v", logs)
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/agents/missing/logs")
	ctx.Params = gin.Params{{Key: "id", Value: "missing"}}
	getAgentLogs(ctx)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected missing agent 404, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/agents/agent-2/logs")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-2"}}
	getAgentLogs(ctx)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected cross-tenant agent 404, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestAgentLogSummaryReturnsEmptyArraysForNodeWithoutLogs(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AgentLog{}); err != nil {
		t.Fatalf("migrate agent logs: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-empty", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/agent-logs/summary?agent_id=agent-empty")
	getAgentLogSummary(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected summary response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, `"level_counts":null`) || strings.Contains(body, `"recent_errors":null`) {
		t.Fatalf("expected empty arrays instead of null arrays, got %s", body)
	}
	var resp struct {
		LevelCounts []agentLogLevelCount `json:"level_counts"`
		RecentErrs  []db.AgentLog        `json:"recent_errors"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(resp.LevelCounts) != 0 || len(resp.RecentErrs) != 0 {
		t.Fatalf("expected empty summary arrays, got %+v", resp)
	}
}

func TestResultEndpointsPaginateAndRespectTaskProjectTenantScope(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	if err := store.Create(&[]db.Project{
		{ID: "project-1", TenantID: "default", Name: "Project 1", Status: "active"},
		{ID: "project-2", TenantID: "default", Name: "Project 2", Status: "active"},
		{ID: "project-other", TenantID: "other", Name: "Other", Status: "active"},
	}).Error; err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-1", TenantID: "default", ProjectID: "project-1", Name: "root", Status: "Running"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "sub-1", TenantID: "default", ProjectID: "project-1", RootTaskID: "root-1", Status: "Done"}).Error; err != nil {
		t.Fatalf("seed sub task: %v", err)
	}
	for i := 0; i < 3; i++ {
		createdAt := now.Add(time.Duration(i) * time.Minute)
		if err := store.Create(&db.Vulnerability{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://target-" + strconv.Itoa(i) + ".example", Plugin: "poc-" + strconv.Itoa(i),
			Severity: "high", CreatedAt: createdAt, UpdatedAt: createdAt,
		}).Error; err != nil {
			t.Fatalf("seed vuln %d: %v", i, err)
		}
		if err := store.Create(&db.Asset{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "10.0.0." + strconv.Itoa(i+1), Protocol: "Web", Port: 80 + i,
			CreatedAt: createdAt, UpdatedAt: createdAt,
		}).Error; err != nil {
			t.Fatalf("seed asset %d: %v", i, err)
		}
		if err := store.Create(&db.FingerprintHit{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://fp-" + strconv.Itoa(i) + ".example", ProductName: "product-" + strconv.Itoa(i),
			RuleName: "rule-" + strconv.Itoa(i), CreatedAt: createdAt, UpdatedAt: createdAt,
		}).Error; err != nil {
			t.Fatalf("seed fingerprint %d: %v", i, err)
		}
	}
	if err := store.Create(&db.Vulnerability{
		TenantID: "default", ProjectID: "project-2", TaskID: "other-default",
		Target: "https://project-2.example", Plugin: "poc-project-2", CreatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed other project vuln: %v", err)
	}
	if err := store.Create(&db.Vulnerability{
		TenantID: "other", ProjectID: "project-other", TaskID: "other-tenant",
		Target: "https://other-tenant.example", Plugin: "poc-other", CreatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed other tenant vuln: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/vulns?project_id=project-1&task_id=root-1&page=2&page_size=2")
	getVulns(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged vulns, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var vulnResp struct {
		Items    []db.Vulnerability `json:"items"`
		Total    int64              `json:"total"`
		Page     int                `json:"page"`
		PageSize int                `json:"page_size"`
		HasMore  bool               `json:"has_more"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &vulnResp); err != nil {
		t.Fatalf("decode vuln response: %v", err)
	}
	if vulnResp.Total != 3 || vulnResp.Page != 2 || vulnResp.PageSize != 2 || vulnResp.HasMore || len(vulnResp.Items) != 1 {
		t.Fatalf("unexpected vuln pagination: %+v", vulnResp)
	}
	if vulnResp.Items[0].ProjectID != "project-1" || vulnResp.Items[0].TaskID != "sub-1" || vulnResp.Items[0].TenantID != "default" {
		t.Fatalf("unexpected scoped vuln item: %+v", vulnResp.Items[0])
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/assets?project_id=project-1&task_id=root-1&page=1&page_size=2")
	getAssets(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged assets, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var assetResp struct {
		Items    []db.Asset `json:"items"`
		Total    int64      `json:"total"`
		Page     int        `json:"page"`
		PageSize int        `json:"page_size"`
		HasMore  bool       `json:"has_more"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &assetResp); err != nil {
		t.Fatalf("decode asset response: %v", err)
	}
	if assetResp.Total != 3 || assetResp.Page != 1 || assetResp.PageSize != 2 || !assetResp.HasMore || len(assetResp.Items) != 2 {
		t.Fatalf("unexpected asset pagination: %+v", assetResp)
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/fingerprints?project_id=project-1&task_id=root-1&page=1&page_size=2000")
	getFingerprints(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged fingerprints, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var fpResp struct {
		Items    []db.FingerprintHit `json:"items"`
		Total    int64               `json:"total"`
		Page     int                 `json:"page"`
		PageSize int                 `json:"page_size"`
		HasMore  bool                `json:"has_more"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &fpResp); err != nil {
		t.Fatalf("decode fingerprint response: %v", err)
	}
	if fpResp.Total != 3 || fpResp.Page != 1 || fpResp.PageSize != 200 || fpResp.HasMore || len(fpResp.Items) != 3 {
		t.Fatalf("unexpected fingerprint pagination: %+v", fpResp)
	}
}

func TestCopilotProfileAndContextCompaction(t *testing.T) {
	profile := resolveCopilotProfile("poc_inline")
	if profile.MaxTurns <= 4 || len(profile.Tools) != 4 {
		t.Fatalf("expected poc profile to enable 4 focused tools (incl node_capacity), got %+v", profile)
	}
	if !strings.Contains(profile.SystemPrompt, "POC 编辑模式") {
		t.Fatalf("expected poc profile to load prompt section from registry, got %s", profile.SystemPrompt)
	}
	expBuilderProfile := resolveCopilotProfile("exp_builder")
	if expBuilderProfile.MaxTurns <= 4 {
		t.Fatalf("expected exp_builder profile to allow extended turns, got %+v", expBuilderProfile)
	}
	if !strings.Contains(expBuilderProfile.SystemPrompt, "EXP Python 生成模式") || !strings.Contains(expBuilderProfile.SystemPrompt, "fenced python") || !strings.Contains(expBuilderProfile.SystemPrompt, "ARGUS_EXP") {
		t.Fatalf("expected exp_builder prompt to enforce complete Python output, got %s", expBuilderProfile.SystemPrompt)
	}

	compact := compactPageContext(map[string]interface{}{
		"module":    "poc_inline",
		"api_key":   "secret",
		"raw_data":  map[string]interface{}{"authorization": "Bearer token"},
		"long_text": strings.Repeat("x", 7000),
	})
	if compact["api_key"] != "[redacted]" {
		t.Fatalf("expected api_key redaction, got %+v", compact["api_key"])
	}
	raw, ok := compact["raw_data"].(map[string]interface{})
	if !ok || raw["authorization"] != "[redacted]" {
		t.Fatalf("expected nested authorization redaction, got %+v", compact["raw_data"])
	}
	if got, ok := compact["long_text"].(string); !ok || len(got) >= 7000 {
		t.Fatalf("expected long text truncation")
	}
}

func TestCopilotPromptRegistryEndpoint(t *testing.T) {
	registry, err := loadCopilotPromptRegistry()
	if err != nil {
		t.Fatalf("load copilot prompt registry: %v", err)
	}
	if registry.Version == 0 || registry.Base == "" {
		t.Fatalf("expected embedded copilot prompt registry to include version and base prompt")
	}
	if registry.aliasByID["poc_inline"] != "poc_list" {
		t.Fatalf("expected poc_inline alias to resolve to poc_list, got %q", registry.aliasByID["poc_inline"])
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/ai/copilot/prompts", nil)

	getCopilotPromptProfiles(c)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}

	var resp copilotPromptRegistryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode copilot prompt registry response: %v", err)
	}
	if resp.Source != "server/internal/api/prompts/copilot_profiles.yaml" {
		t.Fatalf("expected registry source to be exposed, got %q", resp.Source)
	}
	if len(resp.Profiles) == 0 || resp.Default.SystemPrompt == "" {
		t.Fatalf("expected prompt registry response to include profiles and default prompt: %+v", resp)
	}
	foundExpBuilder := false
	for _, profile := range resp.Profiles {
		if profile.Module == "exp_builder" {
			foundExpBuilder = true
			break
		}
	}
	if !foundExpBuilder {
		t.Fatalf("expected prompt registry response to include exp_builder profile: %+v", resp.Profiles)
	}
	foundExpAction := false
	for _, action := range resp.Actions {
		if action.ActionType == "create_exp_draft" {
			foundExpAction = action.RiskLevel == "low" && action.RequiredRole == "operator" && len(action.Params) == 2
			break
		}
	}
	if !foundExpAction {
		t.Fatalf("expected prompt registry response to include create_exp_draft action, got %+v", resp.Actions)
	}
}

func TestCopilotLayeredContextCompactionAndInjection(t *testing.T) {
	pageContext := map[string]interface{}{
		"_identity": map[string]interface{}{
			"tenant_id": "t1",
			"username":  "alice",
			"api_key":   "should-not-leak",
		},
		"_focus": map[string]interface{}{
			"module":         "task_results",
			"route":          "/tasks/t1/results",
			"entity_type":    "vuln",
			"entity_summary": "high nuclei hit",
		},
		"data": map[string]interface{}{
			"selected_vuln": map[string]interface{}{
				"plugin":   "test-poc",
				"response": strings.Repeat("x", 7000),
			},
			"authorization": "Bearer should-not-leak",
		},
		"_ambient": map[string]interface{}{
			"queue": map[string]interface{}{"total_depth": 3},
		},
	}

	compact := compactPageContext(pageContext)
	if got := resolveCopilotModule(compact); got != "task_results" {
		t.Fatalf("expected layered _focus module, got %q", got)
	}
	identity, ok := compact["_identity"].(map[string]interface{})
	if !ok || identity["api_key"] != "[redacted]" {
		t.Fatalf("expected identity secrets to be redacted, got %+v", compact["_identity"])
	}
	data, ok := compact["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected compacted data layer, got %+v", compact["data"])
	}
	if data["authorization"] != "[redacted]" {
		t.Fatalf("expected data authorization to be redacted, got %+v", data["authorization"])
	}
	selected, ok := data["selected_vuln"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected selected_vuln map, got %+v", data["selected_vuln"])
	}
	if got, ok := selected["response"].(string); !ok || len(got) >= 7000 {
		t.Fatalf("expected nested response truncation, got len=%d", len(got))
	}

	messages := []aipkg.ChatMessage{}
	injectCopilotContext(&messages, compact)
	if len(messages) != 4 {
		t.Fatalf("expected identity/focus/data/ambient system messages, got %d", len(messages))
	}
	joined := messages[0].Content + messages[1].Content + messages[2].Content + messages[3].Content
	for _, want := range []string{"【用户身份】", "【页面焦点】", "【页面数据】", "【全局态势】", "test-poc"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected injected context to contain %q, got %s", want, joined)
		}
	}
	if strings.Contains(joined, "should-not-leak") {
		t.Fatalf("sensitive context leaked into injected messages: %s", joined)
	}
}

func TestCopilotProfileNodeCapacityGlobal(t *testing.T) {
	// node_capacity should be available in ALL profiles
	modules := []string{"global", "poc_list", "poc_inline", "exp_list", "exploit_list", "exp_builder", "task_list", "task_results", "node_list", "asset_list", "workflow_list", "fingerprint_list", "dir_list", "dict_list", "dashboard", "unknown_module"}
	for _, mod := range modules {
		profile := resolveCopilotProfile(mod)
		found := false
		for _, tool := range profile.Tools {
			if tool == "node_capacity" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("module %q should include node_capacity tool, got tools: %v", mod, profile.Tools)
		}
	}
}

func TestIsAgentInternalEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{name: "agent commands is internal", method: "GET", path: "/api/v1/agents/a1/commands", want: true},
		{name: "manifest is internal", method: "GET", path: "/api/v1/arsenals/manifest", want: true},
		{name: "arsenal db is internal", method: "GET", path: "/api/v1/arsenals/db", want: true},
		{name: "arsenal db hash is internal", method: "GET", path: "/api/v1/arsenals/db/hash", want: true},
		{name: "arsenal db stats is internal", method: "GET", path: "/api/v1/arsenals/db/stats", want: true},
		{name: "workflow page arsenal list is NOT internal", method: "GET", path: "/api/v1/arsenals/poc", want: false},
		{name: "non GET should not be internal", method: "POST", path: "/api/v1/arsenals/db", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(tt.method, tt.path, nil)
			if got := isAgentInternalEndpoint(c); got != tt.want {
				t.Fatalf("%s %s expected %v, got %v", tt.method, tt.path, tt.want, got)
			}
		})
	}
}
