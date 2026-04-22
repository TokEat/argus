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
