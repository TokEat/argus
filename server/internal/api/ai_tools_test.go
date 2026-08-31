package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aipkg "github.com/P0lar1ght/argus/server/internal/ai"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/expworkspace"
	"github.com/P0lar1ght/argus/server/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupAITestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(
		&db.SystemConfig{},
		&db.Project{},
		&db.ProjectMember{},
		&db.Report{},
		&db.Arsenal{},
		&db.ArsenalEvent{},
		&db.RuleCatalogBootstrap{},
		&db.Asset{},
		&db.Credential{},
		&db.RootTask{},
		&db.SubTask{},
		&db.TaskBatch{},
		&db.TaskConfigRevision{},
		&db.TaskAudit{},
		&db.AssetDiscoveryAudit{},
		&db.Node{},
		&db.FingerprintHit{},
		&db.Vulnerability{},
		&db.FingerprintRule{},
		&db.PocRule{},
		&db.ActiveFingerprintRule{},
		&db.WorkflowRule{},
		&db.DirRule{},
		&db.Exp{},
		&db.ExpRevision{},
		&db.ExpDependency{},
		&db.ExpAsset{},
		&db.ExpAssetRef{},
		&db.ExpTestCase{},
		&db.ExpRun{},
		&db.ExpAudit{},
		&db.ExpRiskWaiver{},
		&db.OAuthClient{},
		&db.OAuthAuthorizationCode{},
		&db.OAuthRefreshToken{},
		&db.TenantMCPSettings{},
		&db.OAuthTenantClientBlock{},
		&db.MCPAdminEvent{},
		&db.BuildJob{},
		&db.AgentSessionAudit{},
		&db.WSEventLog{},
		&db.AgentLogAlertRule{},
		&db.AgentLogAlertEvent{},
		&db.AgentLogArchive{},
		&db.User{},
		&db.CustomRole{},
		&db.TenantQuota{},
		&db.ScanObservation{},
		&db.ScanCoverage{},
		&db.ScanWorkClaim{},
		&db.TaskCoverageLink{},
		&db.ScanTimingEvent{},
		&db.ScanPolicyIntent{},
		&db.ScanStageDerivation{},
		&db.CredentialDictionary{},
		&db.CredentialDictionaryRevision{},
		&db.SubdomainDictionary{},
		&db.SubdomainDictionaryRevision{},
		&db.CredentialBundle{},
		&db.CredentialFindingSecret{},
		&db.CredentialRevealAudit{},
		&db.MCPToolInvocation{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := db.DB
	db.DB = store
	t.Cleanup(func() {
		db.DB = old
	})
	return store
}

const testYakshaExpContent = `target = cli.String("target", cli.setRequired(true), cli.setHelp("authorized target"))
cli.check()
yaksha.result({"target": target})
`

func TestExtractPendingActionsNormalizesAllowedSchemas(t *testing.T) {
	actions := extractPendingActions("请确认：\n```pending_action\n{\"action_type\":\"create_poc_draft\",\"params\":{\"file_name\":\"demo.yaml\",\"content\":\"id: demo\\ninfo:\\n  name: demo\"}}\n```")
	if len(actions) != 1 {
		t.Fatalf("expected one pending action, got %+v", actions)
	}
	if actions[0].ConfirmLabel != "保存草稿" || actions[0].RequiredRole != "operator" {
		t.Fatalf("expected normalized defaults, got %+v", actions[0])
	}

	expActions := extractPendingActions(fmt.Sprintf("```pending_action\n{\"action_type\":\"create_exp_draft\",\"params\":{\"name\":\"exp-demo\",\"content\":%q}}\n```", testYakshaExpContent))
	if len(expActions) != 1 || expActions[0].RiskLevel != "low" || expActions[0].ConfirmLabel != "保存草稿" {
		t.Fatalf("expected create_exp_draft to normalize as low-risk draft action, got %+v", expActions)
	}
}

func TestConfirmCopilotActionCreatesPOCDraft(t *testing.T) {
	store := setupAITestDB(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/ai/actions/confirm", func(c *gin.Context) {
		c.Set("tenant", "default")
		c.Set("user_id", "u1")
		c.Set("role", "operator")
		confirmCopilotAction(c)
	})

	payload := `{
		"action":{
			"action_type":"create_poc_draft",
			"required_role":"operator",
			"params":{
				"file_name":"demo.yaml",
				"content":"id: demo\ninfo:\n  name: Demo\n  severity: low\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
			}
		},
		"page_context":{"module":"poc_inline"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/actions/confirm", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var arsenal db.Arsenal
	if err := store.Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "poc", "demo.yaml").First(&arsenal).Error; err != nil {
		t.Fatalf("expected draft arsenal: %v", err)
	}
	if arsenal.State != "Draft" || !strings.Contains(arsenal.Content, "id: demo") {
		t.Fatalf("unexpected arsenal %+v", arsenal)
	}
}

func TestConfirmCopilotActionPreparesUnsavedExpDraft(t *testing.T) {
	store := setupAITestDB(t)
	objects, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := expworkspace.NewService(store, objects, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldWorkspace := routerRuntime().EXPWorkspace
	routerRuntime().EXPWorkspace = service
	t.Cleanup(func() { routerRuntime().EXPWorkspace = oldWorkspace })
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/ai/actions/confirm", func(c *gin.Context) {
		c.Set("tenant", "default")
		c.Set("user_id", "u1")
		c.Set("role", "operator")
		c.Set("exp_authorized", true)
		confirmCopilotAction(c)
	})

	payload := map[string]interface{}{
		"action": map[string]interface{}{
			"action_type":   "create_exp_draft",
			"required_role": "operator",
			"params": map[string]interface{}{
				"name":    "exp-demo",
				"content": testYakshaExpContent,
			},
		},
		"page_context": map[string]interface{}{"_focus": map[string]interface{}{"module": "exp_builder", "route": "/config/exploit"}},
	}
	payloadBytes, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/actions/confirm", bytes.NewReader(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var item db.Exp
	if err := store.Where("tenant_id = ? AND name = ?", "default", "exp-demo").First(&item).Error; err != nil {
		t.Fatalf("expected Yaksha EXP: %v", err)
	}
	var revisionCount int64
	if err := store.Model(&db.ExpRevision{}).Where("tenant_id = ? AND exp_id = ?", "default", item.ID).Count(&revisionCount).Error; err != nil {
		t.Fatal(err)
	}
	if revisionCount != 0 {
		t.Fatalf("AI-generated source must remain unsaved until Fixture acceptance, revisions=%d", revisionCount)
	}
	if !strings.Contains(rec.Body.String(), `"state":"in_memory"`) || !strings.Contains(rec.Body.String(), `"source_sha256"`) {
		t.Fatalf("expected in-memory draft response, got %s", rec.Body.String())
	}
}

func TestConfirmCopilotActionUpsertsWorkflowDraftWithoutPublishing(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "workflow", "workflow.yaml"),
		TenantID: "default",
		Type:     "workflow",
		FileName: "workflow.yaml",
		Content:  "old-product:\n  type: [root]\n  pocs: [old-poc]\n",
		Hash:     "old",
		Version:  1,
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed workflow: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/ai/actions/confirm", func(c *gin.Context) {
		c.Set("tenant", "default")
		c.Set("user_id", "u1")
		c.Set("role", "operator")
		confirmCopilotAction(c)
	})
	payload := `{
		"action":{
			"action_type":"upsert_workflow_draft",
			"required_role":"operator",
			"params":{"product":"nginx","type":["root","base"],"pocs":["nginx-poc"]}
		},
		"page_context":{"module":"workflow_list"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/actions/confirm", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var arsenal db.Arsenal
	if err := store.Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "workflow", "workflow.yaml").First(&arsenal).Error; err != nil {
		t.Fatalf("expected workflow arsenal: %v", err)
	}
	if arsenal.State != "Draft" || !strings.Contains(arsenal.Content, "nginx:") || arsenal.PreviousHash != "old" {
		t.Fatalf("unexpected workflow draft %+v", arsenal)
	}
}

func TestConfirmCopilotActionCreatesTaskDraftWithoutDispatch(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "proj-1", TenantID: "default", OwnerUserID: "u1", Name: "Default", Status: "active"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/ai/actions/confirm", func(c *gin.Context) {
		c.Set("tenant", "default")
		c.Set("user_id", "u1")
		c.Set("role", "operator")
		confirmCopilotAction(c)
	})
	payload := `{
		"action":{
			"action_type":"create_task_draft",
			"required_role":"operator",
			"params":{"project_id":"proj-1","name":"AI draft","targets":["example.com"],"priority":1,"policy":{"schema_version":"argus.scan-policy/v1","preset":"quick","port_profile":"common-100","scan_method":"tcp","intensity":"low","capabilities":{"subdomain_discovery":true},"credentials":{"pair_limit":50000},"authorization":{"validation_confirmed":false}}}
		},
		"page_context":{"module":"task_list"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/actions/confirm", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var root db.RootTask
	if err := store.Where("tenant_id = ? AND project_id = ? AND status = ?", "default", "proj-1", "Draft").First(&root).Error; err != nil {
		t.Fatalf("expected draft task: %v", err)
	}
	var subtasks int64
	store.Model(&db.SubTask{}).Where("root_task_id = ?", root.ID).Count(&subtasks)
	if subtasks != 0 || root.TotalTargets != 1 {
		t.Fatalf("expected draft without dispatch, root=%+v subtasks=%d", root, subtasks)
	}
	var revision db.TaskConfigRevision
	if err := store.First(&revision, "root_task_id = ? AND version = ?", root.ID, 1).Error; err != nil {
		t.Fatalf("expected initial draft config revision: %v", err)
	}
	if root.CurrentConfigVersion != 1 || revision.ConfigHash == "" || revision.CreatedBy != "u1" {
		t.Fatalf("unexpected draft config version: root=%+v revision=%+v", root, revision)
	}
	var intent db.ScanPolicyIntent
	if err := store.First(&intent, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatalf("expected Server-compiled scan policy intent: %v", err)
	}
	if intent.SchemaVersion != "argus.scan-policy/v1" || intent.PolicyHash == "" || intent.PlanHash == "" {
		t.Fatalf("unexpected semantic scan policy intent: %+v", intent)
	}
}

func TestConfirmCopilotActionUpsertsDirDraft(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "dir", "dir.yaml"),
		TenantID: "default",
		Type:     "dir",
		FileName: "dir.yaml",
		Content:  "old-product:\n  - /old\n",
		Hash:     "old",
		Version:  1,
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed dir: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/ai/actions/confirm", func(c *gin.Context) {
		c.Set("tenant", "default")
		c.Set("user_id", "u1")
		c.Set("role", "operator")
		confirmCopilotAction(c)
	})
	payload := `{
		"action":{
			"action_type":"upsert_dir_draft",
			"required_role":"operator",
			"params":{"product":"nginx","paths":["/admin","/login"]}
		},
		"page_context":{"module":"dir_list"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/actions/confirm", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var arsenal db.Arsenal
	if err := store.Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "dir", "dir.yaml").First(&arsenal).Error; err != nil {
		t.Fatalf("expected dir arsenal: %v", err)
	}
	if arsenal.State != "Draft" || !strings.Contains(arsenal.Content, "nginx:") || arsenal.PreviousHash != "old" {
		t.Fatalf("unexpected dir draft %+v", arsenal)
	}
}

func TestCopilotBusinessToolsAreTenantScoped(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Asset{TenantID: "default", Target: "example.com", Protocol: "https", Port: 443, URL: "https://example.com", Title: "Example", Service: "nginx", Status: "alive"}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := store.Create(&db.Asset{TenantID: "other", Target: "secret.example", Protocol: "https", Port: 443, Status: "alive"}).Error; err != nil {
		t.Fatalf("seed other asset: %v", err)
	}

	result, err := (&SearchAssetsTool{TenantID: "default"}).Execute(context.Background(), []byte(`{"query":"example","limit":10}`))
	if err != nil {
		t.Fatalf("search assets: %v", err)
	}
	payload := result.(map[string]interface{})
	items := payload["items"].([]map[string]interface{})
	if len(items) != 1 || items[0]["target"] != "example.com" {
		t.Fatalf("expected tenant scoped asset result, got %+v", items)
	}
}

func TestCopilotTaskInsightAndWorkflowRecommendation(t *testing.T) {
	store := setupAITestDB(t)
	task := db.RootTask{ID: "task-1", TenantID: "default", Name: "Weekly Scan", Status: "completed", TotalTargets: 2, CompletedTargets: 2, CreatedAt: time.Now()}
	if err := store.Create(&task).Error; err != nil {
		t.Fatalf("seed task: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "sub-1", TenantID: "default", RootTaskID: "task-1", Status: "completed"}).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}
	if err := store.Create(&db.Vulnerability{TenantID: "default", RootTaskID: "task-1", Target: "https://example.com", Plugin: "poc-test", Severity: "high"}).Error; err != nil {
		t.Fatalf("seed vuln: %v", err)
	}
	if err := store.Create(&db.PocRule{TenantID: "default", Name: "nginx-exposure", SourceFile: "nginx.yaml", Severity: "medium", Enabled: true}).Error; err != nil {
		t.Fatalf("seed poc: %v", err)
	}
	if err := store.Create(&db.FingerprintHit{TenantID: "default", ProductName: "nginx", Target: "https://example.com"}).Error; err != nil {
		t.Fatalf("seed fingerprint: %v", err)
	}

	insight, err := (&GetTaskInsightTool{TenantID: "default"}).Execute(context.Background(), []byte(`{"task_id":"task-1"}`))
	if err != nil {
		t.Fatalf("task insight: %v", err)
	}
	counts := insight.(map[string]interface{})["result_counts"].(map[string]int64)
	if counts["vulnerabilities"] != 1 {
		t.Fatalf("expected vulnerability count, got %+v", counts)
	}

	recommend, err := (&RecommendWorkflowRulesTool{TenantID: "default"}).Execute(context.Background(), []byte(`{"product_name":"nginx","limit":5}`))
	if err != nil {
		t.Fatalf("workflow recommend: %v", err)
	}
	recommendations := recommend.(map[string]interface{})["recommendations"].([]string)
	if len(recommendations) == 0 || !strings.Contains(recommendations[0], "nginx") {
		t.Fatalf("expected nginx workflow recommendation, got %+v", recommendations)
	}
}

func TestCopilotP2ToolsAreReadOnlyAndSummarized(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive", Version: "2.0.0", Capacity: 2, RunningTasks: 2, CPUUsage: 91, MemUsage: 70, LastBeat: now.Add(-30 * time.Second).UnixMilli()}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if err := store.Create(&db.Vulnerability{
		TenantID:    "default",
		RootTaskID:  "task-1",
		Target:      "https://example.com",
		Plugin:      "nginx-exposure",
		Severity:    "high",
		Status:      "open",
		Request:     strings.Repeat("GET /admin HTTP/1.1\n", 80),
		Response:    strings.Repeat("HTTP/1.1 200 OK\n", 80),
		Description: "Nginx 管理入口暴露",
		MatchedAt:   "https://example.com/admin",
		CreatedAt:   now,
	}).Error; err != nil {
		t.Fatalf("seed vuln: %v", err)
	}
	if err := store.Create(&db.Asset{TenantID: "default", Target: "example.com", Protocol: "https", Port: 443, Title: "Nginx Admin", Service: "nginx", Status: "alive"}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := store.Create(&db.FingerprintHit{TenantID: "default", Target: "https://example.com", ProductName: "nginx"}).Error; err != nil {
		t.Fatalf("seed fp hit: %v", err)
	}
	if err := store.Create(&db.FingerprintRule{TenantID: "default", ProductName: "nginx", RuleExpr: "title=nginx", Enabled: true}).Error; err != nil {
		t.Fatalf("seed fp rule: %v", err)
	}
	if err := store.Create(&db.DirRule{TenantID: "default", ProductName: "nginx", Path: "/admin", SourceFile: "nginx.yaml", Enabled: true}).Error; err != nil {
		t.Fatalf("seed dir rule: %v", err)
	}
	if err := store.Create(&db.PocRule{TenantID: "default", Name: "nginx-exposure", SourceFile: "nginx-poc.yaml", Severity: "high", Enabled: true}).Error; err != nil {
		t.Fatalf("seed poc: %v", err)
	}

	vulnResult, err := (&ExplainVulnerabilityTool{TenantID: "default"}).Execute(context.Background(), []byte(`{"target":"example","limit":1}`))
	if err != nil {
		t.Fatalf("explain vuln: %v", err)
	}
	vulnItems := vulnResult.(map[string]interface{})["items"].([]map[string]interface{})
	if len(vulnItems) != 1 || len(vulnItems[0]["request"].(string)) > 920 {
		t.Fatalf("expected summarized vulnerability evidence, got %+v", vulnItems)
	}

	nodeResult, err := (&AnalyzeNodeCapacityTool{TenantID: "default"}).Execute(context.Background(), []byte(`{"agent_id":"agent-1"}`))
	if err != nil {
		t.Fatalf("node capacity: %v", err)
	}
	nodes := nodeResult.(map[string]interface{})["nodes"].([]map[string]interface{})
	if len(nodes) != 1 || len(nodes[0]["warnings"].([]string)) == 0 {
		t.Fatalf("expected node warnings, got %+v", nodes)
	}

	dictResult, err := (&SuggestDictionaryStrategyTool{TenantID: "default"}).Execute(context.Background(), []byte(`{"product_name":"nginx"}`))
	if err != nil {
		t.Fatalf("dict strategy: %v", err)
	}
	if len(dictResult.(map[string]interface{})["suggestions"].([]string)) == 0 {
		t.Fatalf("expected dictionary suggestions, got %+v", dictResult)
	}
}

func TestDetectWorkflowConflicts(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.PocRule{TenantID: "default", Name: "disabled-poc", SourceFile: "disabled.yaml", Enabled: false}).Error; err != nil {
		t.Fatalf("seed disabled poc: %v", err)
	}
	rules := []db.WorkflowRule{
		{TenantID: "default", ProductName: "ghost", PocName: "missing-poc", MatchType: "product", Enabled: true},
		{TenantID: "default", ProductName: "nginx", PocName: "disabled-poc", MatchType: "product", Enabled: true},
		{TenantID: "default", ProductName: "nginx", PocName: "disabled-poc", MatchType: "finger", Enabled: true},
		{TenantID: "default", ProductName: "General-Poc-HTTP", PocName: "disabled-poc", MatchType: "root", Enabled: true},
	}
	if err := store.Create(&rules).Error; err != nil {
		t.Fatalf("seed workflows: %v", err)
	}

	result, err := (&DetectWorkflowConflictsTool{TenantID: "default"}).Execute(context.Background(), []byte(`{"limit":10}`))
	if err != nil {
		t.Fatalf("detect conflicts: %v", err)
	}
	conflicts := result.(map[string]interface{})["conflicts"].([]map[string]interface{})
	if len(conflicts) < 3 {
		t.Fatalf("expected workflow conflicts, got %+v", conflicts)
	}
	for _, conflict := range conflicts {
		if conflict["product_name"] == "General-Poc-HTTP" && conflict["type"] == "missing_fingerprint" {
			t.Fatalf("general POC workflow should not require a same-name fingerprint: %+v", conflicts)
		}
	}
}

func TestGlobalAIChatMissingConfig(t *testing.T) {
	setupAITestDB(t)
	body := postGlobalAIChat(t, `{"messages":[{"role":"user","content":"hi"}],"page_context":{"module":"dashboard"}}`)
	if !strings.Contains(body, "event: error") {
		t.Fatalf("expected SSE error event, got %s", body)
	}
}

func TestGlobalAIChatNormalAnswer(t *testing.T) {
	store := setupAITestDB(t)
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		writeSSEData(t, w, map[string]interface{}{
			"choices": []map[string]interface{}{{"delta": map[string]interface{}{"content": "总览正常。"}}},
		})
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer llm.Close()
	if err := aipkg.SaveConfig(store, aipkg.Config{BaseURL: llm.URL, APIKey: "test", Model: "model"}); err != nil {
		t.Fatalf("save config: %v", err)
	}

	body := postGlobalAIChat(t, `{"messages":[{"role":"user","content":"看总览"}],"page_context":{"module":"dashboard"}}`)
	if !strings.Contains(body, "event: token") || !strings.Contains(body, "总览正常") {
		t.Fatalf("expected normal token SSE, got %s", body)
	}
}

func TestGlobalAIChatNormalAndToolPaths(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Asset{TenantID: "default", Target: "example.com", Protocol: "https", Port: 443, Status: "alive"}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	var calls int32
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		call := atomic.AddInt32(&calls, 1)
		if call == 1 {
			writeSSEData(t, w, map[string]interface{}{
				"choices": []map[string]interface{}{{
					"delta": map[string]interface{}{
						"tool_calls": []map[string]interface{}{{
							"index": 0,
							"id":    "call-asset",
							"type":  "function",
							"function": map[string]interface{}{
								"name":      "SearchAssets",
								"arguments": `{"query":"example"}`,
							},
						}},
					},
				}},
			})
		} else {
			writeSSEData(t, w, map[string]interface{}{
				"choices": []map[string]interface{}{{"delta": map[string]interface{}{"content": "找到 example.com 资产。"}}},
			})
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer llm.Close()
	if err := aipkg.SaveConfig(store, aipkg.Config{BaseURL: llm.URL, APIKey: "test", Model: "model"}); err != nil {
		t.Fatalf("save config: %v", err)
	}

	body := postGlobalAIChat(t, `{"messages":[{"role":"user","content":"查资产"}],"page_context":{"module":"asset_list"}}`)
	if !strings.Contains(body, "event: tool_start") || !strings.Contains(body, "SearchAssets") || !strings.Contains(body, "找到 example.com") {
		t.Fatalf("expected tool path SSE, got %s", body)
	}
}

func TestGlobalAIChatLayeredContextEnablesAssetToolsAndRedactsData(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Asset{TenantID: "default", Target: "layered.example", Protocol: "https", Port: 443, Status: "alive"}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	var calls int32
	var mu sync.Mutex
	var requestBodies []string
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read llm request: %v", err)
		}
		mu.Lock()
		requestBodies = append(requestBodies, string(body))
		mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		call := atomic.AddInt32(&calls, 1)
		if call == 1 {
			writeSSEData(t, w, map[string]interface{}{
				"choices": []map[string]interface{}{{
					"delta": map[string]interface{}{
						"tool_calls": []map[string]interface{}{{
							"index": 0,
							"id":    "call-layered-asset",
							"type":  "function",
							"function": map[string]interface{}{
								"name":      "SearchAssets",
								"arguments": `{"query":"layered"}`,
							},
						}},
					},
				}},
			})
		} else {
			writeSSEData(t, w, map[string]interface{}{
				"choices": []map[string]interface{}{{"delta": map[string]interface{}{"content": "找到 layered.example 资产。"}}},
			})
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer llm.Close()
	if err := aipkg.SaveConfig(store, aipkg.Config{BaseURL: llm.URL, APIKey: "test", Model: "model"}); err != nil {
		t.Fatalf("save config: %v", err)
	}

	body := postGlobalAIChat(t, `{
		"messages":[{"role":"user","content":"查当前资产"}],
		"page_context":{
			"_identity":{"tenant_id":"default","username":"operator"},
			"_focus":{"module":"asset_list","route":"/assets"},
			"data":{"authorization":"Bearer should-not-leak","assets_summary":[{"target":"layered.example"}]},
			"_ambient":{"queue":{"total_depth":0}}
		}
	}`)
	if !strings.Contains(body, "event: tool_start") || !strings.Contains(body, "SearchAssets") || !strings.Contains(body, "找到 layered.example") {
		t.Fatalf("expected layered context to enable SearchAssets tool path, got %s", body)
	}

	mu.Lock()
	joinedRequests := strings.Join(requestBodies, "\n")
	mu.Unlock()
	if !strings.Contains(joinedRequests, "SearchAssets") {
		t.Fatalf("expected SearchAssets tool definition in LLM request, got %s", joinedRequests)
	}
	if strings.Contains(joinedRequests, "should-not-leak") || strings.Contains(joinedRequests, "Bearer should-not-leak") {
		t.Fatalf("sensitive data authorization leaked to LLM request: %s", joinedRequests)
	}
}

func TestGlobalAIChatToolErrorPath(t *testing.T) {
	store := setupAITestDB(t)
	var calls int32
	llm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		call := atomic.AddInt32(&calls, 1)
		if call == 1 {
			writeSSEData(t, w, map[string]interface{}{
				"choices": []map[string]interface{}{{
					"delta": map[string]interface{}{
						"tool_calls": []map[string]interface{}{{
							"index": 0,
							"id":    "call-task",
							"type":  "function",
							"function": map[string]interface{}{
								"name":      "GetTaskInsight",
								"arguments": `{"task_id":"missing"}`,
							},
						}},
					},
				}},
			})
		} else {
			writeSSEData(t, w, map[string]interface{}{
				"choices": []map[string]interface{}{{"delta": map[string]interface{}{"content": "任务不存在。"}}},
			})
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer llm.Close()
	if err := aipkg.SaveConfig(store, aipkg.Config{BaseURL: llm.URL, APIKey: "test", Model: "model"}); err != nil {
		t.Fatalf("save config: %v", err)
	}

	body := postGlobalAIChat(t, `{"messages":[{"role":"user","content":"解释任务"}],"page_context":{"module":"task_list"}}`)
	if !strings.Contains(body, `"status":"error"`) || !strings.Contains(body, "task not found") {
		t.Fatalf("expected tool error SSE, got %s", body)
	}
}

func postGlobalAIChat(t *testing.T, payload string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/ai/chat", globalAIChat)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/chat", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func writeSSEData(t *testing.T, w http.ResponseWriter, data interface{}) {
	t.Helper()
	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal SSE: %v", err)
	}
	fmt.Fprintf(w, "data: %s\n\n", payload)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}
