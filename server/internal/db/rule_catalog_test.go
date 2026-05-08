package db

import (
	"strings"
	"testing"
	"unicode/utf8"
)

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

func TestMaterializePocRuleIndexesMetadata(t *testing.T) {
	arsenal := Arsenal{
		ID:       "poc_demo.yaml",
		TenantID: "default",
		Type:     "poc",
		FileName: "demo.yaml",
		Content: `id: CVE-2026-0002
info:
  name: Demo POC
  severity: high
  author:
    - polar
  tags: demo,auth
  description: demo description
  classification:
    cve-id: CVE-2026-0002
  metadata:
    product: DemoProduct
    version: v1.2.3
`,
		Hash:    "hash",
		Version: 3,
		State:   "Approved",
	}

	rule := materializePocRule(arsenal)
	if rule.Name != "CVE-2026-0002" || rule.TargetProduct != "DemoProduct" || rule.CVE != "CVE-2026-0002" {
		t.Fatalf("unexpected poc metadata identity: %#v", rule)
	}
	if rule.CompatibilityStatus != "indexed" || rule.SourceVersion != "v1.2.3" || rule.Severity != "high" {
		t.Fatalf("unexpected poc governance metadata: %#v", rule)
	}
	if rule.Author != "polar" || rule.Tags != "demo,auth" || !rule.Enabled {
		t.Fatalf("unexpected poc author/tags/state: %#v", rule)
	}
}

func TestMaterializePocRuleSanitizesInvalidUTF8(t *testing.T) {
	arsenal := Arsenal{
		ID:       "poc_invalid.yaml",
		TenantID: "default",
		Type:     "poc",
		FileName: "invalid.yaml",
		Content:  "id: invalid\ninfo:\n  author: alice" + string([]byte{0xe4}) + "\n  severity: high\n  description: " + strings.Repeat("界", 600) + "\n",
		Hash:     "hash",
		Version:  1,
		State:    "Approved",
	}

	rule := materializePocRule(arsenal)
	if !utf8.ValidString(rule.Author) || !utf8.ValidString(rule.Description) {
		t.Fatalf("materialized poc metadata contains invalid UTF-8: %#v", rule)
	}
	if rule.Author != "alice" {
		t.Fatalf("Author = %q, want alice", rule.Author)
	}
	if got := utf8.RuneCountInString(rule.Description); got != maxPocDescriptionRunes {
		t.Fatalf("Description rune count = %d, want %d", got, maxPocDescriptionRunes)
	}
}

func TestMaterializePocRuleSanitizesNullEscapes(t *testing.T) {
	arsenal := Arsenal{
		ID:       "poc_null.yaml",
		TenantID: "default",
		Type:     "poc",
		FileName: "null.yaml",
		Content:  "id: null\ninfo:\n  author: \"alice\\0bob\"\n  severity: high\n  description: \"left\\0right\"\n",
		Hash:     "hash",
		Version:  1,
		State:    "Approved",
	}

	rule := materializePocRule(arsenal)
	if strings.ContainsRune(rule.Author, '\x00') || strings.ContainsRune(rule.Description, '\x00') {
		t.Fatalf("materialized poc metadata contains NUL: %#v", rule)
	}
	if rule.Author != "alicebob" || rule.Description != "leftright" {
		t.Fatalf("unexpected sanitized metadata: %#v", rule)
	}
}

func TestSanitizeArsenalTextFieldsRehashesContent(t *testing.T) {
	arsenal := Arsenal{
		ID:       "poc_invalid.yaml",
		TenantID: "default",
		Type:     "poc",
		FileName: "invalid.yaml",
		Content:  "author: alice" + string([]byte{0xe4}) + "\x00\n",
		Hash:     "stale",
		State:    "Approved",
	}

	if !sanitizeArsenalTextFields(&arsenal) {
		t.Fatal("sanitizeArsenalTextFields returned false for invalid PostgreSQL text content")
	}
	if !utf8.ValidString(arsenal.Content) || strings.ContainsRune(arsenal.Content, '\x00') {
		t.Fatalf("Content still contains invalid PostgreSQL text: %q", arsenal.Content)
	}
	if arsenal.Hash != hashString(arsenal.Content) {
		t.Fatalf("Hash = %q, want %q", arsenal.Hash, hashString(arsenal.Content))
	}
}

func TestSanitizeStringFieldsForPostgres(t *testing.T) {
	rule := PocRule{
		Name:        "demo\x00rule",
		Author:      "alice" + string([]byte{0xe4}),
		Description: "left\x00right",
	}

	if !sanitizeStringFieldsForPostgres(&rule) {
		t.Fatal("sanitizeStringFieldsForPostgres returned false")
	}
	if rule.Name != "demorule" || rule.Author != "alice" || rule.Description != "leftright" {
		t.Fatalf("unexpected sanitized rule: %#v", rule)
	}
}
