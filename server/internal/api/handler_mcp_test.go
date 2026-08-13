package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	grpcpkg "github.com/P0lar1ght/argus/server/internal/grpc"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc/metadata"
)

type fakeSubscribeStream struct {
	sent   []*pb.TaskNotify
	sentCh chan *pb.TaskNotify
}

func (s *fakeSubscribeStream) Recv() (*pb.AgentSignal, error) { return nil, io.EOF }
func (s *fakeSubscribeStream) Send(msg *pb.TaskNotify) error {
	if s.sentCh != nil {
		s.sentCh <- msg
	} else {
		s.sent = append(s.sent, msg)
	}
	return nil
}
func (s *fakeSubscribeStream) SetHeader(metadata.MD) error  { return nil }
func (s *fakeSubscribeStream) SendHeader(metadata.MD) error { return nil }
func (s *fakeSubscribeStream) SetTrailer(metadata.MD)       {}
func (s *fakeSubscribeStream) Context() context.Context     { return context.Background() }
func (s *fakeSubscribeStream) SendMsg(interface{}) error    { return nil }
func (s *fakeSubscribeStream) RecvMsg(interface{}) error    { return io.EOF }

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
		{name: "workflow spec", handler: mcpWorkflowSpec, wantURI: "argus://workflow/spec", want: []string{"root", "workflow_pocs", "General-Poc-*", "general POC workflow"}},
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
	oldHub := routerRuntime().NotifyHub
	hub := grpcpkg.NewNotifyHub()
	stream := &fakeSubscribeStream{sentCh: make(chan *pb.TaskNotify, 1)}
	routerRuntime().NotifyHub = hub
	oldWSHub := Hub
	Hub = &WebSocketHub{clients: make(map[*websocket.Conn]string), broadcast: make(chan wsEnvelope, 16)}
	t.Cleanup(func() {
		routerRuntime().NotifyHub = oldHub
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
	select {
	case notify := <-stream.sentCh:
		cmd = notify.DebugCommand
	case <-time.After(2 * time.Second):
		t.Fatalf("debug command was not dispatched")
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
	if payload["custom_only"] != true || payload["custom_rule"] != `body="ArgusMCPFingerprint"` {
		t.Fatalf("expected custom-only fingerprint payload: %#v", payload)
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

func TestMCPRuleDebugFingerprintRuleOnlyDispatchesCustomOnly(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive", Version: "v2.3.0"}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	oldHub := routerRuntime().NotifyHub
	hub := grpcpkg.NewNotifyHub()
	stream := &fakeSubscribeStream{sentCh: make(chan *pb.TaskNotify, 1)}
	routerRuntime().NotifyHub = hub
	oldWSHub := Hub
	Hub = &WebSocketHub{clients: make(map[*websocket.Conn]string), broadcast: make(chan wsEnvelope, 16)}
	t.Cleanup(func() {
		routerRuntime().NotifyHub = oldHub
		Hub = oldWSHub
	})
	hub.Register("agent-1", stream, 1, nil)

	body := `{"rule_type":"fingerprint","agent_id":"agent-1","target_url":"http://target.local","rule":"body=\"ArgusMCPFingerprint\"","timeout_sec":1}`
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
	case <-time.After(2 * time.Second):
		t.Fatalf("debug command was not dispatched")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(cmd.PocContent), &payload); err != nil {
		t.Fatalf("decode fingerprint debug payload: %v", err)
	}
	if payload["custom_only"] != true || payload["custom_rule"] != `body="ArgusMCPFingerprint"` {
		t.Fatalf("expected rule-only custom payload: %#v", payload)
	}
	if _, ok := payload["custom_product"]; ok {
		t.Fatalf("rule-only debug should not require custom_product: %#v", payload)
	}
	handleAgentDebugEvent(&pb.DebugEvent{AgentId: "agent-1", TenantId: "default", SessionId: cmd.SessionId, Type: "debug_result", TemplateId: "Finger", Matched: true, Extracted: []string{"[custom]DebugFingerprint"}})
	handleAgentDebugEvent(&pb.DebugEvent{AgentId: "agent-1", TenantId: "default", SessionId: cmd.SessionId, Type: "debug_complete", Matched: true})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("mcpRuleDebug did not return after debug_complete")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"DebugFingerprint"`) {
		t.Fatalf("expected debug fingerprint in response: %s", recorder.Body.String())
	}
}

func TestDebugFingerprintDispatchesCustomRules(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive", Version: "v2.3.0"}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	oldHub := routerRuntime().NotifyHub
	hub := grpcpkg.NewNotifyHub()
	stream := &fakeSubscribeStream{}
	routerRuntime().NotifyHub = hub
	oldWSHub := Hub
	Hub = &WebSocketHub{clients: make(map[*websocket.Conn]string), broadcast: make(chan wsEnvelope, 16)}
	oldSessions := pocDebugSessions
	pocDebugSessions = &debugSessionManager{
		sessions:     make(map[string]*debugSession),
		activeTenant: make(map[string]string),
	}
	t.Cleanup(func() {
		routerRuntime().NotifyHub = oldHub
		Hub = oldWSHub
		pocDebugSessions = oldSessions
	})
	hub.Register("agent-1", stream, 1, nil)

	body := `{"agent_id":"agent-1","target_url":"http://target.local","custom_only":true,"custom_product":"OnlyOne","custom_rules":["body=\"only-one\"","title=\"OnlyOne\""],"timeout_sec":1}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/arsenals/finger-debug", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/arsenals/finger-debug", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	debugFingerprint(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if len(stream.sent) != 1 || stream.sent[0].DebugCommand == nil {
		t.Fatalf("expected one debug command, got %#v", stream.sent)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(stream.sent[0].DebugCommand.PocContent), &payload); err != nil {
		t.Fatalf("decode fingerprint debug payload: %v", err)
	}
	rawRules, ok := payload["custom_rules"].([]interface{})
	if !ok || len(rawRules) != 2 || rawRules[0] != `body="only-one"` || rawRules[1] != `title="OnlyOne"` {
		t.Fatalf("expected custom_rules to be forwarded, got %#v", payload)
	}
	if payload["custom_rule"] != nil {
		t.Fatalf("custom_rule should not be required when custom_rules are provided: %#v", payload)
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
