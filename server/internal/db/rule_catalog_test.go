package db

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCanonicalArsenalTypePocAsset(t *testing.T) {
	if got := CanonicalArsenalType("pocasset"); got != "poc_asset" {
		t.Fatalf("CanonicalArsenalType(pocasset) = %q, want poc_asset", got)
	}
	aliases := ArsenalTypeAliases("poc_asset")
	if len(aliases) != 2 || aliases[0] != "poc_asset" || aliases[1] != "pocasset" {
		t.Fatalf("ArsenalTypeAliases(poc_asset) = %#v, want [poc_asset pocasset]", aliases)
	}
}

func TestCanonicalArsenalTypeConfigAsset(t *testing.T) {
	if got := CanonicalArsenalType("dict_asset"); got != "config_asset" {
		t.Fatalf("CanonicalArsenalType(dict_asset) = %q, want config_asset", got)
	}
	aliases := ArsenalTypeAliases("config_asset")
	want := []string{"config_asset", "configasset", "dict_asset", "dictasset"}
	if len(aliases) != len(want) {
		t.Fatalf("ArsenalTypeAliases(config_asset) = %#v, want %#v", aliases, want)
	}
	for i := range want {
		if aliases[i] != want[i] {
			t.Fatalf("ArsenalTypeAliases(config_asset) = %#v, want %#v", aliases, want)
		}
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
    argus-execution-class: verification
    argus-risk-level: high
`,
		Hash:    "hash",
		Version: 3,
		State:   "Approved",
	}

	rule, err := materializePocRule(arsenal)
	if err != nil {
		t.Fatalf("materialize POC rule: %v", err)
	}
	if rule.Name != "CVE-2026-0002" || rule.TargetProduct != "DemoProduct" || rule.CVE != "CVE-2026-0002" {
		t.Fatalf("unexpected poc metadata identity: %#v", rule)
	}
	if rule.CompatibilityStatus != "indexed" || rule.SourceVersion != "v1.2.3" || rule.Severity != "high" {
		t.Fatalf("unexpected poc governance metadata: %#v", rule)
	}
	if rule.ExecutionClass != PocExecutionClassVerification || rule.RiskLevel != PocRiskLevelHigh || !PocRequiresSecondConfirmation(rule.RiskLevel) {
		t.Fatalf("unexpected POC execution governance: %#v", rule)
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

	rule, err := materializePocRule(arsenal)
	if err != nil {
		t.Fatalf("materialize POC rule: %v", err)
	}
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

	rule, err := materializePocRule(arsenal)
	if err != nil {
		t.Fatalf("materialize POC rule: %v", err)
	}
	if strings.ContainsRune(rule.Author, '\x00') || strings.ContainsRune(rule.Description, '\x00') {
		t.Fatalf("materialized poc metadata contains NUL: %#v", rule)
	}
	if rule.Author != "alicebob" || rule.Description != "leftright" {
		t.Fatalf("unexpected sanitized metadata: %#v", rule)
	}
}

func TestMaterializePocRuleDefaultsLegacyMetadataAndRejectsEXPClass(t *testing.T) {
	legacy, err := materializePocRule(Arsenal{
		TenantID: "default", Type: "poc", FileName: "legacy.yaml",
		Content: "id: legacy\ninfo:\n  name: Legacy\n  severity: info\n", State: "Approved",
	})
	if err != nil {
		t.Fatalf("legacy POC should stay compatible: %v", err)
	}
	if legacy.ExecutionClass != PocExecutionClassDetection || legacy.RiskLevel != PocRiskLevelUnknown {
		t.Fatalf("unexpected legacy defaults: %#v", legacy)
	}
	if !PocRequiresSecondConfirmation(legacy.RiskLevel) {
		t.Fatal("unknown legacy risk must require second confirmation")
	}

	_, err = materializePocRule(Arsenal{
		TenantID: "default", Type: "poc", FileName: "exploit.yaml",
		Content: "id: exploit\ninfo:\n  name: Exploit\n  severity: high\n  metadata:\n    argus-execution-class: exploit\n    argus-risk-level: high\n",
	})
	if err == nil || !strings.Contains(err.Error(), "separate EXP package") {
		t.Fatalf("expected exploit POC class to be rejected, got %v", err)
	}
}

func TestMaterializeFingerprintRulesSupportsJSONSingleRecord(t *testing.T) {
	rows, err := materializeFingerprintRules(Arsenal{
		ID:       "finger_json",
		TenantID: "default",
		Type:     "finger",
		FileName: "finger.json",
		Content:  `{"product":"JSONProduct","rule":"body=\"json-product\"","category":"service","tags":["json"]}`,
		Hash:     "hash-json",
		Version:  2,
		State:    "Approved",
	})
	if err != nil {
		t.Fatalf("materializeFingerprintRules returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one fingerprint rule, got %d", len(rows))
	}
	if rows[0].ProductName != "JSONProduct" || rows[0].RuleExpr != `body="json-product"` || rows[0].Category != "service" || !rows[0].Enabled {
		t.Fatalf("unexpected JSON fingerprint row: %#v", rows[0])
	}
}

func TestMaterializeFingerprintRulesSupportsYAMLStringValue(t *testing.T) {
	rows, err := materializeFingerprintRules(Arsenal{
		ID:       "finger_string",
		TenantID: "default",
		Type:     "finger",
		FileName: "finger.yaml",
		Content:  "StringProduct: body=\"string-product\"\n",
		Hash:     "hash-string",
		Version:  1,
		State:    "Approved",
	})
	if err != nil {
		t.Fatalf("materializeFingerprintRules returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one fingerprint rule, got %d", len(rows))
	}
	if rows[0].ProductName != "StringProduct" || rows[0].RuleExpr != `body="string-product"` {
		t.Fatalf("unexpected YAML string fingerprint row: %#v", rows[0])
	}
}

func TestMaterializeWorkflowAndDirRulesSupportJSONSingleRecord(t *testing.T) {
	workflowRows, err := materializeWorkflowRules(Arsenal{
		ID:       "workflow_json",
		TenantID: "default",
		Type:     "workflow",
		FileName: "workflow.json",
		Content:  `{"product":"JSONWorkflow","poc":"json-poc.yaml","match_type":"root"}`,
		Hash:     "hash-workflow",
		Version:  3,
		State:    "Approved",
	})
	if err != nil {
		t.Fatalf("materializeWorkflowRules returned error: %v", err)
	}
	if len(workflowRows) != 1 || workflowRows[0].ProductName != "JSONWorkflow" || workflowRows[0].PocName != "json-poc.yaml" || workflowRows[0].MatchType != "root" {
		t.Fatalf("unexpected JSON workflow rows: %#v", workflowRows)
	}

	dirRows, err := materializeDirRules(Arsenal{
		ID:       "dir_json",
		TenantID: "default",
		Type:     "dir",
		FileName: "dir.json",
		Content:  `{"product":"JSONDir","path":"/admin"}`,
		Hash:     "hash-dir",
		Version:  3,
		State:    "Approved",
	})
	if err != nil {
		t.Fatalf("materializeDirRules returned error: %v", err)
	}
	if len(dirRows) != 1 || dirRows[0].ProductName != "JSONDir" || dirRows[0].Path != "/admin" {
		t.Fatalf("unexpected JSON dir rows: %#v", dirRows)
	}
}

func TestCreateInBatchesIgnoresDuplicateRows(t *testing.T) {
	store := setupRuleCatalogSyncTestDB(t)
	rows := []FingerprintRule{
		{
			TenantID:    "default",
			ProductName: "DuplicateProduct",
			RuleExpr:    `body="dup"`,
			Category:    "web",
			State:       "Approved",
			Enabled:     true,
		},
		{
			TenantID:    "default",
			ProductName: "DuplicateProduct",
			RuleExpr:    `body="dup"`,
			Category:    "web",
			State:       "Approved",
			Enabled:     true,
		},
	}
	if err := createInBatches(store, rows); err != nil {
		t.Fatalf("createInBatches returned error for duplicate rows: %v", err)
	}
	var count int64
	if err := store.Model(&FingerprintRule{}).Where("tenant_id = ? AND product_name = ?", "default", "DuplicateProduct").Count(&count).Error; err != nil {
		t.Fatalf("count duplicate rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one duplicate row to be inserted, got %d", count)
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

func TestMaterializeActiveFingerprintRecomputesAutomaticProfile(t *testing.T) {
	rule, err := materializeActiveFingerprintRule(Arsenal{
		ID: "active_fingerprint_shiro-detect.yaml", TenantID: "default", Type: "active_fingerprint",
		FileName: "shiro-detect.yaml", Hash: "hash", Version: 2, State: "Approved",
		Content: `id: shiro-detect
info:
  name: Detect Apache Shiro
  severity: info
  metadata:
    argus-rule-kind: active-fingerprint
    argus-product: APACHE-Shiro
    argus-auto-profile: controlled
    max-request: 1
http:
  - method: GET
    path: ['{{BaseURL}}']
    matchers: [{type: status, status: [200]}]
`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rule.AutoEligible || rule.ComputedAutoProfile != "safe" || rule.DeclaredAutoProfile != "controlled" || rule.ProductName != "APACHE-Shiro" || !rule.Enabled {
		t.Fatalf("unexpected materialized active fingerprint: %#v", rule)
	}
}

func TestValidateAutomaticActiveFingerprintLimitPerTenant(t *testing.T) {
	rules := make([]ActiveFingerprintRule, 0, 10)
	for index := 0; index < 9; index++ {
		name := "probe-" + string(rune('a'+index))
		rules = append(rules, ActiveFingerprintRule{TenantID: "tenant-a", Name: name, SourceFile: name + ".yaml", Enabled: true, AutoEligible: true})
	}
	rules = append(rules, ActiveFingerprintRule{TenantID: "tenant-b", Name: "probe-a", SourceFile: "probe-a.yaml", Enabled: true, AutoEligible: true})
	if err := validateAutomaticActiveFingerprintLimit(rules); err == nil || !strings.Contains(err.Error(), "maximum is 8") {
		t.Fatalf("expected tenant automatic probe budget rejection, got %v", err)
	}
	rules[8].Enabled = false
	if err := validateAutomaticActiveFingerprintLimit(rules); err != nil {
		t.Fatalf("eight enabled automatic probes must be accepted: %v", err)
	}
	rules[0].Name, rules[0].SourceFile = "duplicate", "one.yaml"
	rules[1].Name, rules[1].SourceFile = "Duplicate", "two.yaml"
	if err := validateAutomaticActiveFingerprintLimit(rules); err == nil || !strings.Contains(err.Error(), "duplicate template id") {
		t.Fatalf("expected duplicate Nuclei id rejection, got %v", err)
	}
}
