package api

import "testing"

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
		{method: "GET", path: "/api/v1/ai/config", want: "admin"},
		{method: "PUT", path: "/api/v1/ai/config", want: "admin"},
	}
	for _, tt := range tests {
		if got := matchPermission(tt.method, tt.path); got != tt.want {
			t.Fatalf("%s %s expected %s, got %s", tt.method, tt.path, tt.want, got)
		}
	}
}
