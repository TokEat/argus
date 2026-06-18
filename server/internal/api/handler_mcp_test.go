package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/db"
	grpcpkg "github.com/user/dddd-server/internal/grpc"
)

const testMCPPythonExpContent = `ARGUS_EXP = {
    "id": "exp-mcp-demo",
    "name": "MCP Demo",
    "risk_level": "medium",
    "policy": {
        "capabilities": ["http.request", "result.write"],
        "dry_run_supported": True,
        "timeout_sec": 30,
    },
    "params": {
        "marker": {"type": "string", "required": True, "default": "argus"}
    },
    "requirements": [],
}

def run(ctx):
    return ctx.result.success("ok", marker=ctx.params.get("marker"))
`

func TestMCPPyexpValidateSourceReturnsMetadata(t *testing.T) {
	setupAITestDB(t)
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/pyexp/validate", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/pyexp/validate", strings.NewReader(`{"source":`+strconvQuote(testMCPPythonExpContent)+`}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpPyexpValidate(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["valid"] != true || resp["id"] != "exp-mcp-demo" || resp["requirements_hash"] != "" {
		t.Fatalf("unexpected validate response: %#v", resp)
	}
}

func TestMCPPyexpDryRunSourceNormalizesParams(t *testing.T) {
	setupAITestDB(t)
	body := `{"source":` + strconvQuote(testMCPPythonExpContent) + `,"target":"https://example.com","params":{}}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/pyexp/dry-run", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/pyexp/dry-run", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpPyexpDryRun(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp dryRunExploitResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.ParamsValid || resp.NormalizedParams["marker"] != "argus" || resp.ExploitID != "exp-mcp-demo" {
		t.Fatalf("unexpected dry-run response: %#v", resp)
	}
}

func TestMCPRuleDebugPyexpSourceDryRunDoesNotPersist(t *testing.T) {
	store := setupAITestDB(t)
	body := `{"rule_type":"pyexp","action":"dry_run","source":` + strconvQuote(testMCPPythonExpContent) + `,"target_url":"https://example.com","params":{}}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/debug", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/debug", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpRuleDebug(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"source_level":true`) || !strings.Contains(recorder.Body.String(), `"dry_run":true`) {
		t.Fatalf("unexpected dry-run response: %s", recorder.Body.String())
	}
	var count int64
	if err := store.Model(&db.Arsenal{}).Where("tenant_id = ? AND type = ?", "default", "exp").Count(&count).Error; err != nil {
		t.Fatalf("count arsenals: %v", err)
	}
	if count != 0 {
		t.Fatalf("source dry-run should not persist EXP artifacts, got %d", count)
	}
}

func TestMCPRuleDebugPyexpSourceDispatchesWithoutSavedRule(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive", Version: "v2.3.0", Tags: `{"python_exp":"true","pyexp_python":"/usr/bin/python3"}`}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	oldHub := notifyHub
	hub := grpcpkg.NewNotifyHub()
	stream := &fakeSubscribeStream{sentCh: make(chan *pb.TaskNotify, 1)}
	notifyHub = hub
	oldWSHub := Hub
	Hub = &WebSocketHub{clients: make(map[*websocket.Conn]string), broadcast: make(chan wsEnvelope, 16)}
	t.Cleanup(func() {
		notifyHub = oldHub
		Hub = oldWSHub
	})
	hub.Register("agent-1", stream, 1, nil)

	body := `{"rule_type":"pyexp","action":"run","agent_id":"agent-1","target_url":"https://example.com","source":` + strconvQuote(testMCPPythonExpContent) + `,"params":{},"timeout_sec":1}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/debug", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/debug", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	done := make(chan struct{})
	go func() {
		mcpRuleDebug(ctx)
		close(done)
	}()
	var cmd *pb.DebugCommand
	select {
	case notify := <-stream.sentCh:
		cmd = notify.DebugCommand
	case <-done:
		t.Fatalf("EXP source debug returned before dispatch: status=%d body=%s", recorder.Code, recorder.Body.String())
	case <-time.After(2 * time.Second):
		t.Fatalf("EXP source debug command was not dispatched")
	}
	if cmd.Action != "start_exp_debug" || !strings.Contains(cmd.PocContent, `"id": "exp-mcp-demo"`) {
		t.Fatalf("unexpected EXP debug command: %#v", cmd)
	}
	if got := cmd.Params; !strings.Contains(got, `"marker":"argus"`) {
		t.Fatalf("expected normalized default params, got %q", got)
	}
	handleAgentDebugEvent(&pb.DebugEvent{AgentId: "agent-1", TenantId: "default", SessionId: cmd.SessionId, Type: "debug_result", Matched: true, Message: `{"status":"Succeeded"}`})
	handleAgentDebugEvent(&pb.DebugEvent{AgentId: "agent-1", TenantId: "default", SessionId: cmd.SessionId, Type: "debug_complete", Matched: true})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("source pyexp debug did not return after debug_complete")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"source_level":true`) || strings.Contains(recorder.Body.String(), `"artifact_id"`) {
		t.Fatalf("unexpected source debug response: %s", recorder.Body.String())
	}
}

func TestMCPPyexpSaveDraftReturnsRuleIDAndRequirementsHash(t *testing.T) {
	store := setupAITestDB(t)
	body := `{"file_name":"mcp-demo.py","content":` + strconvQuote(testMCPPythonExpContent) + `}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/pyexp/save-draft", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/pyexp/save-draft", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpPyexpSaveDraft(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["artifact_id"] != db.BuildTenantArsenalID("default", "exp", "mcp-demo.py") || resp["requirements_hash"] != "" {
		t.Fatalf("unexpected save response: %#v", resp)
	}
	if _, ok := resp["exploit_rule_id"].(float64); !ok {
		t.Fatalf("expected exploit_rule_id in response, got %#v", resp)
	}
	var rule db.ExploitRule
	if err := store.Where("tenant_id = ? AND rule_id = ?", "default", "exp-mcp-demo").First(&rule).Error; err != nil {
		t.Fatalf("expected synced exploit rule: %v", err)
	}
}

func TestMCPAgentPythonRunRejectsUnknownCommandBeforeDispatch(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive", Version: "v2.3.0", Tags: `{"python_exp":"true","pyexp_python":"/usr/bin/python3"}`}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	oldHub := notifyHub
	hub := grpcpkg.NewNotifyHub()
	notifyHub = hub
	t.Cleanup(func() { notifyHub = oldHub })

	body := `{"agent_id":"agent-1","command":"shell","params":{"argv":["sh","-c","id"]}}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/agent/python-run", "admin", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/agent/python-run", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpAgentPythonRun(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "dispatched") {
		t.Fatalf("unknown command should not dispatch: %s", recorder.Body.String())
	}
}

func TestMCPRuleSaveFingerprintDraftDoesNotPublish(t *testing.T) {
	store := setupAITestDB(t)
	oldContent := "ExistingProduct:\n    - body=\"old\"\n"
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "finger", "finger.yaml"),
		TenantID: "default",
		Type:     "finger",
		FileName: "finger.yaml",
		Content:  oldContent,
		Hash:     "old-hash",
		Version:  1,
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed finger arsenal: %v", err)
	}

	body := `{"rule_type":"fingerprint","product_name":"ArgusMCP","rules":["body=\"ArgusMCPFingerprint\""]}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/save", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/save", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpRuleSave(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["rule_type"] != "fingerprint" || resp["file_name"] != "finger.yaml" || resp["state"] != "Draft" {
		t.Fatalf("unexpected save response: %#v", resp)
	}
	if resp["hash"] == "" || int(resp["version"].(float64)) != 2 {
		t.Fatalf("expected hash and incremented version, got %#v", resp)
	}
	var arsenal db.Arsenal
	if err := store.Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "finger", "finger.yaml").First(&arsenal).Error; err != nil {
		t.Fatalf("load finger arsenal: %v", err)
	}
	if arsenal.State != "Draft" || arsenal.PreviousHash != "old-hash" || !strings.Contains(arsenal.Content, "ArgusMCP") {
		t.Fatalf("unexpected finger arsenal: %+v", arsenal)
	}
	var rule db.FingerprintRule
	if err := store.Where("tenant_id = ? AND product_name = ?", "default", "ArgusMCP").First(&rule).Error; err != nil {
		t.Fatalf("expected synced draft fingerprint rule: %v", err)
	}
	if rule.Enabled || rule.State != "Draft" {
		t.Fatalf("draft fingerprint rule should not be enabled: %+v", rule)
	}
}

func TestMCPContextSelfDescribingResourcesAndQuickstart(t *testing.T) {
	setupAITestDB(t)
	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{
			name: "resources",
			body: `{"action":"resources"}`,
			want: []string{"argus://argus-mcp/quickstart", "argus://fingerprint/spec", "argus://workflow/spec", "recommended_reading_order"},
		},
		{
			name: "quickstart",
			body: `{"action":"quickstart"}`,
			want: []string{"debug", "save", "publish", "workflow_links"},
		},
		{
			name: "lifecycle",
			body: `{"action":"lifecycle_policy"}`,
			want: []string{"test_only", "production_candidate", "approved_reusable", "cleanup is situational"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/context", "operator", "9")
			ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/context", strings.NewReader(tc.body))
			ctx.Request.Header.Set("Content-Type", "application/json")

			mcpRuleContext(ctx)

			if recorder.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(recorder.Body.String(), want) {
					t.Fatalf("context response missing %q: %s", want, recorder.Body.String())
				}
			}
		})
	}
}

func TestMCPResourceEndpointsReturnSelfDescribingDocs(t *testing.T) {
	setupAITestDB(t)
	for _, tc := range []struct {
		name    string
		handler func(*gin.Context)
		wantURI string
		want    []string
	}{
		{name: "quickstart", handler: mcpArgusMCPQuickstart, wantURI: "argus://argus-mcp/quickstart", want: []string{"argus_rule_debug", "argus_rule_save", "argus_rule_apply"}},
		{name: "fingerprint spec", handler: mcpFingerprintSpec, wantURI: "argus://fingerprint/spec", want: []string{"body=", "product_name"}},
		{name: "poc spec", handler: mcpPOCSpec, wantURI: "argus://poc/spec", want: []string{"id:", "requests:", "matchers:"}},
		{name: "workflow spec", handler: mcpWorkflowSpec, wantURI: "argus://workflow/spec", want: []string{"root", "workflow_pocs"}},
		{name: "full chain example", handler: mcpFullChainExample, wantURI: "argus://examples/fingerprint-poc-workflow", want: []string{"fingerprint", "workflow_links", "test_only"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, recorder := newTenantContextWithRole(http.MethodGet, "/mcp/resources", "operator", "9")
			ctx.Request = httptest.NewRequest(http.MethodGet, "/mcp/resources", nil)

			tc.handler(ctx)

			if recorder.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.wantURI) {
				t.Fatalf("resource response missing URI %q: %s", tc.wantURI, recorder.Body.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(recorder.Body.String(), want) {
					t.Fatalf("resource response missing %q: %s", want, recorder.Body.String())
				}
			}
		})
	}
}

func TestMCPRuleSaveTestOnlyReturnsGuidance(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "finger", "finger.yaml"),
		TenantID: "default",
		Type:     "finger",
		FileName: "finger.yaml",
		Content:  "ExistingProduct:\n    - body=\"old\"\n",
		Hash:     "old-hash",
		Version:  1,
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed finger arsenal: %v", err)
	}

	body := `{"rule_type":"fingerprint","intent":"test_only","product_name":"ArgusMCP","rules":["body=\"ArgusMCPFingerprint\""]}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/save", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/save", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpRuleSave(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	guidance, ok := resp["mcp_guidance"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected mcp_guidance, got %#v", resp)
	}
	if guidance["lifecycle_hint"] != "test_only" || !strings.Contains(fmt.Sprint(guidance["cleanup_hint"]), "situational") {
		t.Fatalf("unexpected guidance: %#v", guidance)
	}
}

func TestMCPRuleApplyPublishRequiresFreshHashAndVersion(t *testing.T) {
	store := setupAITestDB(t)
	content := "id: mcp-publish-poc\ninfo:\n  name: Publish POC\n  severity: info\nrequests: []\n"
	arsenal := db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "poc", "mcp-publish.yaml"),
		TenantID: "default",
		Type:     "poc",
		FileName: "mcp-publish.yaml",
		Content:  content,
		Hash:     "fresh-hash",
		Version:  3,
		State:    "Draft",
	}
	if err := store.Create(&arsenal).Error; err != nil {
		t.Fatalf("seed poc arsenal: %v", err)
	}

	staleBody := `{"action":"publish","rule_type":"poc","file_name":"mcp-publish.yaml","hash":"old-hash","version":3}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/apply", "admin", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/apply", strings.NewReader(staleBody))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpRuleApply(ctx)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected stale publish 409, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	freshBody := `{"action":"publish","rule_type":"poc","file_name":"mcp-publish.yaml","hash":"fresh-hash","version":3}`
	ctx, recorder = newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/apply", "admin", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/apply", strings.NewReader(freshBody))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpRuleApply(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected publish 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var saved db.Arsenal
	if err := store.Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "poc", "mcp-publish.yaml").First(&saved).Error; err != nil {
		t.Fatalf("load published poc: %v", err)
	}
	if saved.State != "Approved" {
		t.Fatalf("expected Approved state, got %+v", saved)
	}
}

func TestMCPRuleApplyRejectsNonAdmin(t *testing.T) {
	setupAITestDB(t)
	body := `{"action":"publish","rule_type":"poc","file_name":"mcp-publish.yaml","hash":"fresh-hash","version":3}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/apply", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/apply", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpRuleApply(ctx)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestMCPRuleContextWorkflowLinks(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.FingerprintRule{TenantID: "default", ProductName: "ArgusMCP", RuleExpr: `body="ArgusMCPFingerprint"`, SourceFile: "finger.yaml", State: "Approved", Enabled: true}).Error; err != nil {
		t.Fatalf("seed fingerprint rule: %v", err)
	}
	if err := store.Create(&db.PocRule{TenantID: "default", Name: "argus-mcp-poc", SourceFile: "argus-mcp-poc.yaml", State: "Approved", Enabled: true}).Error; err != nil {
		t.Fatalf("seed poc rule: %v", err)
	}
	if err := store.Create(&db.WorkflowRule{TenantID: "default", ProductName: "ArgusMCP", PocName: "argus-mcp-poc", MatchType: "root", SourceFile: "workflow.yaml", State: "Approved", Enabled: true}).Error; err != nil {
		t.Fatalf("seed workflow rule: %v", err)
	}
	if err := store.Create(&db.FingerprintHit{TenantID: "default", Target: "http://target.local", ProductName: "ArgusMCP"}).Error; err != nil {
		t.Fatalf("seed fingerprint hit: %v", err)
	}

	body := `{"action":"workflow_links","product_name":"ArgusMCP","poc_name":"argus-mcp-poc","limit":5}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/context", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/context", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	mcpRuleContext(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	for _, want := range []string{"ArgusMCP", "argus-mcp-poc", "root", "http://target.local"} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Fatalf("context response missing %q: %s", want, recorder.Body.String())
		}
	}
}

func TestMCPRuleDebugFingerprintDispatchesPayloadAndCollectsResult(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive", Version: "v2.3.0"}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	oldHub := notifyHub
	hub := grpcpkg.NewNotifyHub()
	stream := &fakeSubscribeStream{}
	notifyHub = hub
	oldWSHub := Hub
	Hub = &WebSocketHub{clients: make(map[*websocket.Conn]string), broadcast: make(chan wsEnvelope, 16)}
	t.Cleanup(func() {
		notifyHub = oldHub
		Hub = oldWSHub
	})
	hub.Register("agent-1", stream, 1, nil)

	body := `{"rule_type":"fingerprint","agent_id":"agent-1","target_url":"http://target.local","product_name":"ArgusMCP","rule":"body=\"ArgusMCPFingerprint\"","include_poc":true,"workflow_product":"ArgusMCP","workflow_types":["root"],"workflow_pocs":["argus-mcp-poc"],"poc_content":"id: argus-mcp-poc\ninfo:\n  name: Argus MCP\n  severity: info\nrequests: []\n","timeout_sec":1}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/debug", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/debug", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	done := make(chan struct{})
	go func() {
		mcpRuleDebug(ctx)
		close(done)
	}()
	var cmd *pb.DebugCommand
	deadline := time.After(2 * time.Second)
	for cmd == nil {
		select {
		case <-deadline:
			t.Fatalf("debug command was not dispatched")
		default:
			if len(stream.sent) > 0 {
				cmd = stream.sent[0].DebugCommand
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if cmd.Action != "start_fingerprint_debug" {
		t.Fatalf("unexpected debug action: %#v", cmd)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(cmd.PocContent), &payload); err != nil {
		t.Fatalf("decode fingerprint debug payload: %v", err)
	}
	if payload["custom_product"] != "ArgusMCP" || payload["custom_wf_pocs"] != "argus-mcp-poc" {
		t.Fatalf("unexpected fingerprint payload: %#v", payload)
	}
	handleAgentDebugEvent(&pb.DebugEvent{AgentId: "agent-1", TenantId: "default", SessionId: cmd.SessionId, Type: "debug_result", TemplateId: "Finger", Matched: true, Extracted: []string{"[custom]ArgusMCP"}})
	handleAgentDebugEvent(&pb.DebugEvent{AgentId: "agent-1", TenantId: "default", SessionId: cmd.SessionId, Type: "debug_complete", Matched: true})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("mcpRuleDebug did not return after debug_complete")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"ArgusMCP"`) {
		t.Fatalf("expected matched product in response: %s", recorder.Body.String())
	}
}

func TestDeleteFingerprintDictReturnsCatalogSyncError(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "finger", "finger.yaml"),
		TenantID: "default",
		Type:     "finger",
		FileName: "finger.yaml",
		Content:  "ArgusMCPDeleteError:\n  - body=\"delete-error\"\n",
		Hash:     "old",
		Version:  1,
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed finger arsenal: %v", err)
	}
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "exp", "broken.py"),
		TenantID: "default",
		Type:     "exp",
		FileName: "broken.py",
		Content:  "ARGUS_EXP = {",
		Hash:     "broken",
		Version:  1,
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed invalid exp arsenal: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodDelete, "/dictionaries/fingerprint/ArgusMCPDeleteError", "operator", "9")
	ctx.Params = gin.Params{{Key: "product", Value: "ArgusMCPDeleteError"}}
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/dictionaries/fingerprint/ArgusMCPDeleteError", nil)

	deleteFingerprintDict(ctx)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "rule catalog materialized") || !strings.Contains(recorder.Body.String(), "broken.py") {
		t.Fatalf("expected raw catalog sync error, got %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "failed to save to database") {
		t.Fatalf("generic database error hides root cause: %s", recorder.Body.String())
	}
	var arsenal db.Arsenal
	if err := store.Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "finger", "finger.yaml").First(&arsenal).Error; err != nil {
		t.Fatalf("reload finger arsenal: %v", err)
	}
	if !strings.Contains(arsenal.Content, "ArgusMCPDeleteError") {
		t.Fatalf("fingerprint source changed even though catalog sync failed: %q", arsenal.Content)
	}
}

func TestDeletePOCArsenalRejectsWorkflowReferences(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "poc", "referenced.yaml"),
		TenantID: "default",
		Type:     "poc",
		FileName: "referenced.yaml",
		Content:  "id: referenced\ninfo:\n  name: referenced\n  severity: info\nrequests: []\n",
		Hash:     "poc-hash",
		Version:  1,
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed poc arsenal: %v", err)
	}
	if err := store.Create(&db.PocRule{
		TenantID:   "default",
		ArtifactID: db.BuildTenantArsenalID("default", "poc", "referenced.yaml"),
		SourceFile: "referenced.yaml",
		Name:       "referenced",
		State:      "Approved",
		Enabled:    true,
	}).Error; err != nil {
		t.Fatalf("seed poc rule: %v", err)
	}
	if err := store.Create(&db.WorkflowRule{
		TenantID:    "default",
		ProductName: "ReferencedProduct",
		PocName:     "referenced",
		MatchType:   "root",
		SourceFile:  "workflow.yaml",
		State:       "Approved",
		Enabled:     true,
	}).Error; err != nil {
		t.Fatalf("seed workflow rule: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodDelete, "/arsenals/poc/referenced.yaml", "operator", "9")
	ctx.Params = gin.Params{{Key: "type", Value: "poc"}, {Key: "filename", Value: "referenced.yaml"}}
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/arsenals/poc/referenced.yaml", nil)

	deleteArsenal(ctx)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "ReferencedProduct") || !strings.Contains(recorder.Body.String(), "referenced") {
		t.Fatalf("expected workflow reference detail, got %s", recorder.Body.String())
	}
	var count int64
	store.Model(&db.Arsenal{}).Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "poc", "referenced.yaml").Count(&count)
	if count != 1 {
		t.Fatalf("referenced POC should not be deleted, count=%d", count)
	}
}

func TestMCPDebugResultWaitReturnsCompleteEvent(t *testing.T) {
	resultChan := make(chan map[string]interface{}, 2)
	resultChan <- map[string]interface{}{
		"type":       "debug_result",
		"severity":   "Succeeded",
		"matched":    true,
		"matched_at": "http://target.local/",
		"request":    "GET / HTTP/1.1\r\n\r\n",
		"response":   "HTTP/1.1 200 OK\r\n\r\nok",
		"message":    `{"status":"Succeeded","message":"verified","evidence":{"status_code":200}}`,
	}
	resultChan <- map[string]interface{}{"type": "debug_complete", "matched": true}

	result, err := waitMCPDebugResult(resultChan, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("wait result: %v", err)
	}
	if result.Status != "completed" || !result.Matched || result.Result["severity"] != "Succeeded" || result.Complete["matched"] != true {
		t.Fatalf("unexpected wait result: %#v", result)
	}
	execResult := result.ExecutionResult
	if execResult["success"] != true || execResult["matched"] != true || execResult["message"] != "verified" {
		t.Fatalf("unexpected execution_result: %#v", execResult)
	}
	if execResult["has_request_response"] != true || !strings.Contains(fmt.Sprint(execResult["request"]), "GET /") || !strings.Contains(fmt.Sprint(execResult["response"]), "200 OK") {
		t.Fatalf("expected request/response in execution_result: %#v", execResult)
	}
	evidence, ok := execResult["evidence"].(map[string]interface{})
	if !ok || fmt.Sprint(evidence["status_code"]) != "200" {
		t.Fatalf("expected parsed evidence in execution_result: %#v", execResult)
	}
}

func TestMCPDebugResultWaitMarksTemplateLoadFailure(t *testing.T) {
	resultChan := make(chan map[string]interface{}, 3)
	resultChan <- map[string]interface{}{
		"type":    "debug_log",
		"level":   "INFO",
		"message": "\x1b[33mWRN\x1b[0m Could not load template /var/folders/vs/example/T/argus-poc-debug-123/debug-poc.yaml: mandatory 'author' field is missing",
	}
	resultChan <- map[string]interface{}{
		"type":    "debug_log",
		"level":   "ERROR",
		"message": "\x1b[31mWRN\x1b[0m Found 1 templates with syntax error",
	}
	resultChan <- map[string]interface{}{"type": "debug_complete", "matched": false}

	result, err := waitMCPDebugResult(resultChan, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("wait result: %v", err)
	}
	if result.Status != "failed" {
		t.Fatalf("expected failed status, got %#v", result)
	}
	if !strings.Contains(result.Error, "mandatory 'author' field is missing") {
		t.Fatalf("expected author error in response, got %#v", result)
	}
	if strings.Contains(result.Error, "\x1b") || strings.Contains(result.Error, "/var/folders") || !strings.Contains(result.Error, "debug-poc.yaml") {
		t.Fatalf("expected sanitized error, got %q", result.Error)
	}
	if result.ExecutionResult["success"] != false || result.ExecutionResult["matched"] != false || !strings.Contains(fmt.Sprint(result.ExecutionResult["error"]), "mandatory 'author' field is missing") {
		t.Fatalf("unexpected failure execution_result: %#v", result.ExecutionResult)
	}
	if len(result.Logs) != 2 {
		t.Fatalf("expected debug logs to be returned, got %#v", result.Logs)
	}
}

func TestMCPDebugResultWaitUsesResultMatchedOverComplete(t *testing.T) {
	resultChan := make(chan map[string]interface{}, 2)
	resultChan <- map[string]interface{}{"type": "debug_result", "matched": true, "template_id": "poc-demo", "matched_at": "http://target.local/"}
	resultChan <- map[string]interface{}{"type": "debug_complete", "matched": false}

	result, err := waitMCPDebugResult(resultChan, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("wait result: %v", err)
	}
	if !result.Matched || result.ExecutionResult["matched"] != true || result.ExecutionResult["success"] != true {
		t.Fatalf("expected result.matched to win over complete.matched: %#v", result)
	}
	warnings, ok := result.ExecutionResult["warnings"].([]string)
	if !ok || len(warnings) == 0 || !strings.Contains(warnings[0], "complete.matched differed") {
		t.Fatalf("expected mismatch warning, got %#v", result.ExecutionResult)
	}
}

func strconvQuote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}
