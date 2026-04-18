package arsenal

import (
	"os"
	"testing"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	dbPath := t.TempDir() + "/test_arsenal.db"
	if err := OpenDB(dbPath); err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
}

// ---------- Fingerprint Tests ----------

func TestAddAndListFingerprint(t *testing.T) {
	setupTestDB(t)

	f := &Fingerprint{
		ProductName: "TestProduct",
		RuleExpr:    `body="test" && title="Test"`,
		Category:    "web",
		Source:      "user",
		Enabled:     true,
	}

	created, err := AddFingerprint(f)
	if err != nil {
		t.Fatalf("AddFingerprint error: %v", err)
	}
	if !created {
		t.Fatal("expected created=true for new fingerprint")
	}

	// 重复添加应返回 created=false
	created, err = AddFingerprint(f)
	if err != nil {
		t.Fatalf("AddFingerprint duplicate error: %v", err)
	}
	if created {
		t.Fatal("expected created=false for duplicate fingerprint")
	}

	// 查询
	fingers, total, err := ListFingerprints("TestProduct", "", "", false, 10, 0)
	if err != nil {
		t.Fatalf("ListFingerprints error: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", total)
	}
	if fingers[0].ProductName != "TestProduct" {
		t.Fatalf("expected product TestProduct, got %s", fingers[0].ProductName)
	}
}

func TestDeleteFingerprint(t *testing.T) {
	setupTestDB(t)

	f := &Fingerprint{
		ProductName: "DelTest",
		RuleExpr:    `title="del"`,
		Source:      "user",
		Enabled:     true,
	}
	AddFingerprint(f)

	affected, err := DeleteFingerprint("DelTest", `title="del"`)
	if err != nil {
		t.Fatalf("DeleteFingerprint error: %v", err)
	}
	if affected != 1 {
		t.Fatalf("expected 1 affected, got %d", affected)
	}

	_, total, _ := ListFingerprints("DelTest", "", "", false, 10, 0)
	if total != 0 {
		t.Fatalf("expected 0 after delete, got %d", total)
	}
}

func TestCountFingerprints(t *testing.T) {
	setupTestDB(t)

	AddFingerprint(&Fingerprint{ProductName: "A", RuleExpr: `body="a"`, Source: "builtin", Enabled: true})
	AddFingerprint(&Fingerprint{ProductName: "B", RuleExpr: `body="b"`, Source: "user", Enabled: true})

	total, bySource := CountFingerprints()
	if total != 2 {
		t.Fatalf("expected 2, got %d", total)
	}
	if bySource["builtin"] != 1 || bySource["user"] != 1 {
		t.Fatalf("unexpected source distribution: %v", bySource)
	}
}

// ---------- Poc Tests ----------

func TestAddAndGetPoc(t *testing.T) {
	setupTestDB(t)

	p := &Poc{
		Name:        "CVE-2023-TEST",
		FileName:    "CVE-2023-TEST.yaml",
		Content:     "id: CVE-2023-TEST\ninfo:\n  severity: high",
		ContentHash: "abc123",
		Severity:    "high",
		Source:      "user",
		Enabled:     true,
	}

	created, err := AddPoc(p)
	if err != nil {
		t.Fatalf("AddPoc error: %v", err)
	}
	if !created {
		t.Fatal("expected created=true")
	}

	// 重复添加应更新
	p.Content = "updated content"
	created, err = AddPoc(p)
	if err != nil {
		t.Fatalf("AddPoc update error: %v", err)
	}
	if created {
		t.Fatal("expected created=false for update")
	}

	poc, err := GetPocByName("CVE-2023-TEST")
	if err != nil {
		t.Fatalf("GetPocByName error: %v", err)
	}
	if poc.Content != "updated content" {
		t.Fatalf("expected updated content, got: %s", poc.Content)
	}
}

func TestDeletePoc(t *testing.T) {
	setupTestDB(t)

	AddPoc(&Poc{Name: "DEL-POC", FileName: "DEL-POC.yaml", Content: "test", Enabled: true})
	affected, err := DeletePoc("DEL-POC")
	if err != nil {
		t.Fatalf("DeletePoc error: %v", err)
	}
	if affected != 1 {
		t.Fatalf("expected 1, got %d", affected)
	}
}

// ---------- Workflow Tests ----------

func TestAddAndListWorkflow(t *testing.T) {
	setupTestDB(t)

	w := &Workflow{
		ProductName: "Nacos",
		PocName:     "nacos-auth-bypass",
		MatchType:   "root",
		Enabled:     true,
	}

	created, err := AddWorkflow(w)
	if err != nil {
		t.Fatalf("AddWorkflow error: %v", err)
	}
	if !created {
		t.Fatal("expected created=true")
	}

	// 重复
	created, _ = AddWorkflow(w)
	if created {
		t.Fatal("expected created=false for duplicate")
	}

	workflows, total, err := ListWorkflows("Nacos", 10, 0)
	if err != nil {
		t.Fatalf("ListWorkflows error: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1, got %d", total)
	}
	if workflows[0].PocName != "nacos-auth-bypass" {
		t.Fatalf("unexpected poc name: %s", workflows[0].PocName)
	}
}

// ---------- Import/Export Tests ----------

func TestImportExportFingerYAML(t *testing.T) {
	setupTestDB(t)

	yaml := `
TestProduct:
  - 'body="test1"'
  - 'title="test2"'
AnotherProduct:
  - 'header="X-Test"'
`
	added, skipped, err := ImportFingerYAML([]byte(yaml), "user")
	if err != nil {
		t.Fatalf("ImportFingerYAML error: %v", err)
	}
	if added != 3 {
		t.Fatalf("expected 3 added, got %d (skipped: %d)", added, skipped)
	}

	// 导出
	exported, err := ExportFingerYAML()
	if err != nil {
		t.Fatalf("ExportFingerYAML error: %v", err)
	}
	exportStr := string(exported)
	if len(exportStr) == 0 {
		t.Fatal("exported YAML is empty")
	}
	// 应包含两个产品名
	if !contains(exportStr, "TestProduct") || !contains(exportStr, "AnotherProduct") {
		t.Fatalf("exported YAML missing product names:\n%s", exportStr)
	}
}

func TestImportWorkflowYAML(t *testing.T) {
	setupTestDB(t)

	yaml := `
TestProduct:
  type:
    - root
    - dir
  pocs:
    - CVE-2023-001
    - CVE-2023-002
`
	added, _, err := ImportWorkflowYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("ImportWorkflowYAML error: %v", err)
	}
	// 2 pocs × 2 types = 4 records
	if added != 4 {
		t.Fatalf("expected 4 added, got %d", added)
	}
}

func TestImportDirYAML(t *testing.T) {
	setupTestDB(t)

	yaml := `
Nacos:
  - "/nacos/"
  - "/api/nacos/"
`
	added, _, err := ImportDirYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("ImportDirYAML error: %v", err)
	}
	if added != 2 {
		t.Fatalf("expected 2 added, got %d", added)
	}
}

// ---------- Validator Tests ----------

func TestValidateFingerRule(t *testing.T) {
	tests := []struct {
		rule    string
		wantErr bool
	}{
		{`body="test"`, false},
		{`body="test" && title="hello"`, false},
		{`body="test" || header="X-Test"`, false},
		{`(body="test" && title="hello") || header="X-Powered"`, false},
		{``, true},                    // 空规则
		{`body=test`, true},           // 缺少引号
		{`(body="test"`, true},        // 括号不匹配
		{`invalidfield="test"`, true}, // 不支持的字段
	}

	for _, tt := range tests {
		err := ValidateFingerRule(tt.rule)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateFingerRule(%q) error=%v, wantErr=%v", tt.rule, err, tt.wantErr)
		}
	}
}

// ---------- PocMeta Tests ----------

func TestParsePocMeta(t *testing.T) {
	content := `id: CVE-2023-12345
info:
  name: Test Vulnerability
  author: tester
  severity: high
  tags: rce,java
  description: A test vulnerability
`
	meta := parsePocMeta([]byte(content))
	if meta.id != "CVE-2023-12345" {
		t.Fatalf("expected id CVE-2023-12345, got %s", meta.id)
	}
	if meta.severity != "high" {
		t.Fatalf("expected severity high, got %s", meta.severity)
	}
	if meta.author != "tester" {
		t.Fatalf("expected author tester, got %s", meta.author)
	}
}

// ---------- Helpers ----------

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && os.Getenv("") == "" && // 防止空判断被优化
		len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
