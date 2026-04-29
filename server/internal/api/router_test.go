package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	aipkg "github.com/user/dddd-server/internal/ai"
)

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
		{method: "GET", path: "/api/v1/projects/proj-1/members", want: "admin"},
		{method: "PUT", path: "/api/v1/projects/proj-1/members", want: "admin"},
		{method: "POST", path: "/api/v1/tasks", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/cancel", want: "operator"},
		{method: "DELETE", path: "/api/v1/nodes/agent-1", want: "operator"},
		{method: "POST", path: "/api/v1/dictionaries/workflow", want: "operator"},
		{method: "PUT", path: "/api/v1/dictionaries/workflow/product", want: "operator"},
		{method: "POST", path: "/api/v1/arsenals/poc/demo.yaml", want: "operator"},
		{method: "POST", path: "/api/v1/arsenals/poc/demo.yaml/approve", want: "admin"},
		{method: "POST", path: "/api/v1/arsenals/poc/demo.yaml/rollback", want: "admin"},
		{method: "GET", path: "/api/v1/users", want: "admin"},
		{method: "GET", path: "/api/v1/cloud/accounts", want: "operator"},
		{method: "POST", path: "/api/v1/cloud/accounts/ca-1/oss/upload", want: "operator"},
		{method: "POST", path: "/api/v1/build/client", want: "admin"},
		{method: "GET", path: "/api/v1/undocumented", want: "admin"},
	}
	for _, tt := range tests {
		if got := matchPermission(tt.method, tt.path); got != tt.want {
			t.Fatalf("%s %s expected %s, got %s", tt.method, tt.path, tt.want, got)
		}
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

func TestCopilotProfileAndContextCompaction(t *testing.T) {
	profile := resolveCopilotProfile("poc_inline")
	if profile.MaxTurns <= 4 || len(profile.Tools) != 4 {
		t.Fatalf("expected poc profile to enable 4 focused tools (incl node_capacity), got %+v", profile)
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
	modules := []string{"global", "poc_list", "poc_inline", "task_list", "task_results", "node_list", "asset_list", "workflow_list", "fingerprint_list", "dir_list", "dict_list", "dashboard", "unknown_module"}
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
