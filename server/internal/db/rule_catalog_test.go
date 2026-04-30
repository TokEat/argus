package db

import "testing"

func TestCanonicalArsenalTypeEXP(t *testing.T) {
	if got := CanonicalArsenalType("exploit"); got != "exp" {
		t.Fatalf("CanonicalArsenalType(exploit) = %q, want exp", got)
	}
	aliases := ArsenalTypeAliases("exp")
	if len(aliases) != 2 || aliases[0] != "exp" || aliases[1] != "exploit" {
		t.Fatalf("ArsenalTypeAliases(exp) = %#v, want [exp exploit]", aliases)
	}
}

func TestMaterializeExploitRule(t *testing.T) {
	arsenal := Arsenal{
		ID:       "exp_demo.yaml",
		TenantID: "default",
		Type:     "exp",
		FileName: "demo.yaml",
		Content: `kind: argus-exp/v1
id: exp-demo
info:
  name: Demo EXP
  risk_level: high
  target_product: DemoProduct
  cve: CVE-2026-0001
  linked_pocs:
    - demo-poc.yaml
policy:
  requires_auth: true
  cleanup_supported: true
  cleanup_required: true
  timeout_sec: 90
  capabilities:
    - http.request
    - evidence.write
  side_effects:
    - creates proof marker
params:
  marker:
    type: string
runtime:
  engine: starlark
`,
		Hash:    "hash",
		Version: 2,
		State:   "Approved",
	}

	rule, err := materializeExploitRule(arsenal)
	if err != nil {
		t.Fatalf("materializeExploitRule returned error: %v", err)
	}
	if rule.RuleID != "exp-demo" || rule.Name != "Demo EXP" || rule.TargetProduct != "DemoProduct" {
		t.Fatalf("unexpected materialized identity: %#v", rule)
	}
	if rule.RiskLevel != "high" || !rule.RequiresAuth || !rule.CleanupRequired || !rule.CleanupSupported {
		t.Fatalf("unexpected risk/policy fields: %#v", rule)
	}
	if rule.Capabilities != `["http.request","evidence.write"]` {
		t.Fatalf("Capabilities = %q", rule.Capabilities)
	}
	if rule.LinkedPocs != `["demo-poc.yaml"]` {
		t.Fatalf("LinkedPocs = %q", rule.LinkedPocs)
	}
	if rule.TimeoutSec != 90 || rule.RuntimeEngine != "starlark" || !rule.Enabled {
		t.Fatalf("unexpected runtime fields: %#v", rule)
	}
}
