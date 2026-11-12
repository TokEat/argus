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
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	grpcpkg "github.com/TokEat/argus/server/internal/grpc"
	pb "github.com/TokEat/argus/shared/proto/go/scan"
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
	oldContent := "# keep-me\nExistingProduct:\n    - body=\"old\"\nZedLast:\n    - title=\"z\"\n"
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
	existingIdx := strings.Index(arsenal.Content, "ExistingProduct:")
	zedIdx := strings.Index(arsenal.Content, "ZedLast:")
	newIdx := strings.Index(arsenal.Content, "ArgusMCP:")
	if existingIdx < 0 || zedIdx < 0 || newIdx < 0 || !(existingIdx < zedIdx && zedIdx < newIdx) {
		t.Fatalf("fingerprint save remashaled the dictionary:\n%s", arsenal.Content)
	}
	if !strings.Contains(arsenal.Content, "# keep-me") {
		t.Fatalf("fingerprint save dropped comments:\n%s", arsenal.Content)
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
			name: "help",
			body: `{"action":"help"}`,
			want: []string{"source-less MCP client", "argus://dir/spec", "info.author", "rule_get", "coverage", "string array"},
		},
		{
			name: "resources",
			body: `{"action":"resources"}`,
			want: []string{"argus://argus-mcp/quickstart", "argus://fingerprint/spec", "argus://dir/spec", "argus://workflow/spec", "recommended_reading_order"},
		},
		{
			name: "quickstart",
			body: `{"action":"quickstart"}`,
			want: []string{"debug", "save", "publish", "argus_debug_"},
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
		{name: "quickstart", handler: mcpArgusMCPQuickstart, wantURI: "argus://argus-mcp/quickstart", want: []string{"argus_debug_", "argus_save_", "argus_rule_apply"}},
		{name: "tool guide", handler: mcpArgusMCPToolGuide, wantURI: "argus://argus-mcp/tool-guide", want: []string{"coverage", "include_content", "name array"}},
		{name: "fingerprint spec", handler: mcpFingerprintSpec, wantURI: "argus://fingerprint/spec", want: []string{"body=", "product_name"}},
		{name: "dir spec", handler: mcpDirSpec, wantURI: "argus://dir/spec", want: []string{"rule_type: dir", "paths"}},
		{name: "dir template", handler: mcpDirTemplate, wantURI: "argus://dir/template", want: []string{"ExampleProduct", "/admin"}},
		{name: "behavior probe spec", handler: mcpBehaviorProbeSpec, wantURI: "argus://behavior-probe/spec", want: []string{"active-fingerprint", "argus-behavior-kind", "ordinary HTTP response", "risk_confirmed", "HTTP/HTTPS"}},
		{name: "behavior probe template", handler: mcpBehaviorProbeTemplate, wantURI: "argus://behavior-probe/template", want: []string{"example-product-detect", "Example-Product", "argus-behavior-kind", "{{randstr}}"}},
		{name: "poc spec", handler: mcpPOCSpec, wantURI: "argus://poc/spec", want: []string{"id:", "requests:", "matchers:"}},
		{name: "workflow spec", handler: mcpWorkflowSpec, wantURI: "argus://workflow/spec", want: []string{"root", "workflow_pocs", "General-Poc-*", "general POC workflow"}},
		{name: "full chain example", handler: mcpFullChainExample, wantURI: "argus://examples/fingerprint-poc-workflow", want: []string{"fingerprint", "rule_get", "test_only"}},
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

func TestMCPBehaviorProbeDraftPublishAndDeprecate(t *testing.T) {
	store := setupAITestDB(t)
	content := `id: mcp-behavior
info:
  name: MCP Behavior Probe
  severity: info
  metadata:
    argus-rule-kind: active-fingerprint
    argus-product: MCP-Product
    argus-behavior-kind: header
    max-request: 1
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      X-Argus-Probe: "{{randstr}}"
    matchers:
      - type: status
        status: [200]
`
	saveBody, err := json.Marshal(map[string]interface{}{
		"rule_type": "behavior_probe", "file_name": "mcp-behavior.yaml", "content": content,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/save", "operator", "operator-1")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/save", bytes.NewReader(saveBody))
	ctx.Request.Header.Set("Content-Type", "application/json")
	mcpRuleSave(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("save behavior probe: %d (%s)", recorder.Code, recorder.Body.String())
	}
	var saved map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if saved["state"] != "Draft" || saved["rule_type"] != "behavior_probe" {
		t.Fatalf("unexpected behavior draft response: %#v", saved)
	}

	apply := func(action, role string) *httptest.ResponseRecorder {
		t.Helper()
		body, marshalErr := json.Marshal(map[string]interface{}{
			"action": action, "rule_type": "behavior_probe", "file_name": "mcp-behavior.yaml",
			"artifact_id": saved["artifact_id"], "hash": saved["hash"], "version": saved["version"],
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		applyCtx, applyRecorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/apply", role, "admin-1")
		applyCtx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/apply", bytes.NewReader(body))
		applyCtx.Request.Header.Set("Content-Type", "application/json")
		mcpRuleApply(applyCtx)
		return applyRecorder
	}

	if publish := apply("publish", "admin"); publish.Code != http.StatusOK {
		t.Fatalf("publish behavior probe: %d (%s)", publish.Code, publish.Body.String())
	}
	if deprecate := apply("deprecate", "admin"); deprecate.Code != http.StatusOK {
		t.Fatalf("deprecate behavior probe: %d (%s)", deprecate.Code, deprecate.Body.String())
	}
	var artifact db.Arsenal
	if err := store.Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "active_fingerprint", "mcp-behavior.yaml").First(&artifact).Error; err != nil {
		t.Fatal(err)
	}
	if artifact.State != "Deprecated" {
		t.Fatalf("behavior probe state = %q, want Deprecated", artifact.State)
	}
	var actions []string
	if err := store.Model(&db.ArsenalEvent{}).Where("tenant_id = ? AND artifact_id = ?", "default", artifact.ID).Order("id").Pluck("action", &actions).Error; err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(actions, ","), "saved,published,deprecated"; got != want {
		t.Fatalf("behavior probe audit actions = %q, want %q", got, want)
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

func TestMCPContextCoverageFingerprintWithoutPOC(t *testing.T) {
	store := setupAITestDB(t)
	seed := []db.FingerprintRule{
		{TenantID: "default", ProductName: "HasPOC", RuleExpr: `body="a"`, SourceFile: "finger.yaml", State: "Approved", Enabled: true},
		{TenantID: "default", ProductName: "HasPOC", RuleExpr: `title="a"`, SourceFile: "finger.yaml", State: "Approved", Enabled: true},
		{TenantID: "default", ProductName: "MissingPOC", RuleExpr: `body="b"`, SourceFile: "finger.yaml", State: "Approved", Enabled: true},
		{TenantID: "default", ProductName: "AlsoMissing", RuleExpr: `body="c"`, SourceFile: "finger.yaml", State: "Approved", Enabled: true},
		{TenantID: "default", ProductName: "DisabledFP", RuleExpr: `body="d"`, SourceFile: "finger.yaml", State: "Draft", Enabled: true},
		{TenantID: "other", ProductName: "OtherTenant", RuleExpr: `body="e"`, SourceFile: "finger.yaml", State: "Approved", Enabled: true},
	}
	for i := range seed {
		if err := store.Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed fingerprint rule: %v", err)
		}
	}
	if err := store.Model(&db.FingerprintRule{}).Where("tenant_id = ? AND product_name = ?", "default", "DisabledFP").Update("enabled", false).Error; err != nil {
		t.Fatalf("disable fingerprint rule: %v", err)
	}
	if err := store.Create(&db.WorkflowRule{TenantID: "default", ProductName: "HasPOC", PocName: "has-poc", MatchType: "root", SourceFile: "workflow.yaml", State: "Approved", Enabled: true}).Error; err != nil {
		t.Fatalf("seed workflow rule: %v", err)
	}
	if err := store.Create(&db.WorkflowRule{TenantID: "default", ProductName: "General-Poc-Web", PocName: "generic", MatchType: "root", SourceFile: "workflow.yaml", State: "Approved", Enabled: true}).Error; err != nil {
		t.Fatalf("seed general poc workflow: %v", err)
	}
	if err := store.Create(&db.PocRule{TenantID: "default", Name: "has-poc", SourceFile: "has-poc.yaml", State: "Approved", Enabled: true}).Error; err != nil {
		t.Fatalf("seed poc rule: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/context", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/context", strings.NewReader(`{"action":"coverage"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	mcpRuleContext(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var got map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode coverage: %v", err)
	}
	if got["fingerprint_products"].(float64) != 3 || got["workflow_products_with_poc"].(float64) != 1 || got["fingerprint_without_poc"].(float64) != 2 || got["general_poc_groups"].(float64) != 1 {
		t.Fatalf("unexpected coverage counts: %#v", got)
	}
	products, _ := got["products"].([]interface{})
	if len(products) != 2 || products[0] != "AlsoMissing" || products[1] != "MissingPOC" {
		t.Fatalf("expected compact missing names, got %#v", got["products"])
	}
	for _, name := range products {
		if _, isObject := name.(map[string]interface{}); isObject {
			t.Fatalf("coverage products must be names only, got %#v", name)
		}
	}
	if strings.Contains(recorder.Body.String(), "OtherTenant") || strings.Contains(recorder.Body.String(), "DisabledFP") {
		t.Fatalf("coverage leaked other tenant or disabled rows: %s", recorder.Body.String())
	}

	ctx, recorder = newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/context", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/context", strings.NewReader(`{"action":"coverage","include_names":false}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	mcpRuleContext(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var countsOnly map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &countsOnly); err != nil {
		t.Fatalf("decode coverage without names: %v", err)
	}
	if _, exists := countsOnly["products"]; exists {
		t.Fatalf("include_names=false should omit products: %#v", countsOnly)
	}
	if countsOnly["fingerprint_without_poc"].(float64) != 2 {
		t.Fatalf("counts should remain when names are omitted: %#v", countsOnly)
	}

	if err := store.Create(&db.FingerprintRule{TenantID: "default", ProductName: "MCP-Server", RuleExpr: `body="mcp"`, SourceFile: "finger.yaml", State: "Approved", Enabled: true}).Error; err != nil {
		t.Fatalf("seed hyphenated fingerprint: %v", err)
	}
	ctx, recorder = newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/context", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/context", strings.NewReader(`{"action":"coverage","query":"MCP-Server"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	mcpRuleContext(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("hyphenated coverage query expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var hyphenated map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &hyphenated); err != nil {
		t.Fatalf("decode hyphenated coverage: %v", err)
	}
	hyphenProducts, _ := hyphenated["products"].([]interface{})
	if hyphenated["query"] != "mcp-server" || len(hyphenProducts) != 1 || hyphenProducts[0] != "MCP-Server" {
		t.Fatalf("query=MCP-Server should match the product name, got %#v", hyphenated)
	}

	ctx, recorder = newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/context", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/context", strings.NewReader(`{"action":"coverage","query":"No-Such-Product"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	mcpRuleContext(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("empty hyphenated coverage query expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var emptyQuery map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &emptyQuery); err != nil {
		t.Fatalf("decode empty coverage query: %v", err)
	}
	emptyProducts, _ := emptyQuery["products"].([]interface{})
	if emptyQuery["total"].(float64) != 0 || len(emptyProducts) != 0 {
		t.Fatalf("unmatched coverage query should return an empty list, got %#v", emptyQuery)
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
		sessions:    make(map[string]*debugSession),
		activeAgent: make(map[string]string),
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

func TestMCPDebugResultWaitReconcilesCompleteMatched(t *testing.T) {
	resultChan := make(chan map[string]interface{}, 2)
	resultChan <- map[string]interface{}{"type": "debug_result", "matched": true, "template_id": "poc-demo", "matched_at": "http://target.local/"}
	resultChan <- map[string]interface{}{"type": "debug_complete", "matched": false}

	result, err := waitMCPDebugResult(resultChan, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("wait result: %v", err)
	}
	if !result.Matched || result.Complete["matched"] != true || result.ExecutionResult["matched"] != true || result.ExecutionResult["success"] != true {
		t.Fatalf("expected complete.matched to follow result.matched: %#v", result)
	}
	if _, hasWarn := result.ExecutionResult["warnings"]; hasWarn {
		t.Fatalf("reconciled complete should not warn: %#v", result.ExecutionResult)
	}
}

func TestMCPRuleSaveWorkflowDraftWritesRiskLevelWithoutRewritingSiblings(t *testing.T) {
	store := setupAITestDB(t)
	oldContent := "KeepMe:\n  type:\n    - root\n  pocs:\n    - keep.yaml\n  risk_level: high\n"
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "workflow", "workflow.yaml"),
		TenantID: "default",
		Type:     "workflow",
		FileName: "workflow.yaml",
		Content:  oldContent,
		Hash:     "old-hash",
		Version:  1,
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed workflow arsenal: %v", err)
	}

	body := `{"rule_type":"workflow","product_name":"ArgusMCP","workflow_types":["root"],"workflow_pocs":["argus-mcp-poc.yaml"],"risk_level":"info"}`
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/mcp/tools/rule/save", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/mcp/tools/rule/save", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	mcpRuleSave(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var arsenal db.Arsenal
	if err := store.Where("tenant_id = ? AND type = ? AND file_name = ?", "default", "workflow", "workflow.yaml").First(&arsenal).Error; err != nil {
		t.Fatalf("load workflow arsenal: %v", err)
	}
	if !strings.Contains(arsenal.Content, "KeepMe:") || !strings.Contains(arsenal.Content, "risk_level: high") {
		t.Fatalf("workflow save rewrote sibling risk_level:\n%s", arsenal.Content)
	}
	if !strings.Contains(arsenal.Content, "ArgusMCP:") || !strings.Contains(arsenal.Content, "risk_level: info") {
		t.Fatalf("workflow save did not write risk_level:\n%s", arsenal.Content)
	}
}

func TestDebugSessionManagerLocksPerAgent(t *testing.T) {
	manager := &debugSessionManager{
		sessions:    make(map[string]*debugSession),
		activeAgent: make(map[string]string),
	}
	first, ok := manager.start("tenant-a", "agent-1", time.Second, nil)
	if !ok || first == nil {
		t.Fatal("first debug session should start")
	}
	if _, ok := manager.start("tenant-a", "agent-2", time.Second, nil); !ok {
		t.Fatal("same tenant different agent should not 409")
	}
	if _, ok := manager.start("tenant-b", "agent-1", time.Second, nil); ok {
		t.Fatal("same agent should still 409 even across tenants")
	}
	manager.finish(first.SessionID)
	if _, ok := manager.start("tenant-a", "agent-1", time.Second, nil); !ok {
		t.Fatal("agent should accept a new session after finish")
	}
}

func strconvQuote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}
