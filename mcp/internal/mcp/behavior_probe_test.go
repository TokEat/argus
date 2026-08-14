package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBehaviorProbeRuleTypeAndToolContracts(t *testing.T) {
	for _, alias := range []string{"behavior_probe", "active_fingerprint", "active-fingerprint"} {
		if got := normalizeRuleType(alias); got != "active_fingerprint" {
			t.Fatalf("normalizeRuleType(%q) = %q", alias, got)
		}
	}
	if got := publicRuleType("active_fingerprint"); got != "behavior_probe" {
		t.Fatalf("public type = %q", got)
	}
	encoded, err := json.Marshal(tools())
	if err != nil {
		t.Fatal(err)
	}
	contract := string(encoded)
	for _, required := range []string{"behavior_probe", "risk_confirmed", "deprecate", "rollback"} {
		if !strings.Contains(contract, required) {
			t.Fatalf("MCP tool contract missing %q", required)
		}
	}
}
