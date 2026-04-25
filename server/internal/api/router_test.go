package api

import (
	"strings"
	"testing"
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

func TestCopilotProfileAndContextCompaction(t *testing.T) {
	profile := resolveCopilotProfile("poc_inline")
	if profile.MaxTurns <= 4 || len(profile.Tools) != 3 {
		t.Fatalf("expected poc profile to enable focused tools, got %+v", profile)
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
