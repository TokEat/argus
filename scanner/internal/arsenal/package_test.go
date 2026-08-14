package arsenal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/shared/proto/go/activefingerprint"
)

func TestInspectRulePackageUsesStableSemanticVersion(t *testing.T) {
	first := filepath.Join(t.TempDir(), "space # package", "first.db")
	second := filepath.Join(t.TempDir(), "second.db")
	createInspectionPackage(t, first, time.Unix(10, 0), "detection")
	createInspectionPackage(t, second, time.Unix(20, 0), "detection")

	firstInfo, err := InspectRulePackage(first)
	if err != nil {
		t.Fatalf("inspect first package: %v", err)
	}
	secondInfo, err := InspectRulePackage(second)
	if err != nil {
		t.Fatalf("inspect second package: %v", err)
	}
	if firstInfo.RuleVersion != secondInfo.RuleVersion {
		t.Fatalf("semantic versions differ: %s != %s", firstInfo.RuleVersion, secondInfo.RuleVersion)
	}
	if firstInfo.RuleVersion == "" || firstInfo.SchemaVersion != RulePackageSchemaVersion {
		t.Fatalf("unexpected inspection: %+v", firstInfo)
	}
}

func TestInspectRulePackageRejectsExploitPOC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arsenal.db")
	createInspectionPackage(t, path, time.Now(), "exploit")
	if _, err := InspectRulePackage(path); err == nil {
		t.Fatal("expected exploit-class POC to be rejected")
	}
}

func TestBuildRulePackageFromConfigIncludesRuntimeAssets(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	writePackageTestFile(t, filepath.Join(configDir, "finger.yaml"), "Demo:\n  - 'body=\"demo\"'\n")
	writePackageTestFile(t, filepath.Join(configDir, "workflow.yaml"), "Demo:\n  type: [root]\n  pocs: [demo.yaml]\n")
	writePackageTestFile(t, filepath.Join(configDir, "dir.yaml"), "Demo:\n  - /demo\n")
	writePackageTestFile(t, filepath.Join(configDir, "pocs", "demo.yaml"), "id: demo\ninfo:\n  name: demo\n  author: test\n  severity: info\nhttp: []\n")
	writePackageTestFile(t, filepath.Join(configDir, "active-fingerprints", "demo-detect.yaml"), "id: demo-detect\ninfo:\n  name: demo detect\n  severity: info\n  metadata:\n    argus-rule-kind: active-fingerprint\n    argus-product: Demo\n    argus-auto-profile: safe\n    max-request: 1\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        words: [demo]\n")
	writePackageTestFile(t, filepath.Join(configDir, "pocs", "helpers", "payload.txt"), "payload\n")
	writePackageTestFile(t, filepath.Join(configDir, "dict", "mysql.txt"), "root:root\n")
	writePackageTestFile(t, filepath.Join(configDir, "subdomains.txt"), "www\n")

	output := filepath.Join(root, "out", "arsenal.db")
	inspection, err := BuildRulePackageFromConfig(configDir, output)
	if err != nil {
		t.Fatalf("build package: %v", err)
	}
	if inspection.Counts.Fingerprints != 1 || inspection.Counts.ActiveFingerprints != 1 || inspection.Counts.Pocs != 1 || inspection.Counts.PocAssets != 1 || inspection.Counts.ConfigAssets != 2 {
		t.Fatalf("unexpected counts: %+v", inspection.Counts)
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("expected package output: %v", err)
	}
	secondOutput := filepath.Join(root, "out", "arsenal-second.db")
	secondInspection, err := BuildRulePackageFromConfig(configDir, secondOutput)
	if err != nil {
		t.Fatalf("build second package: %v", err)
	}
	if inspection.RuleVersion != secondInspection.RuleVersion || inspection.FileHash != secondInspection.FileHash {
		t.Fatalf("release package is not reproducible: first=%+v second=%+v", inspection, secondInspection)
	}
}

func TestReviewedShiroRuleIsAnIndependentActiveFingerprint(t *testing.T) {
	configDir := filepath.Join("..", "..", "common", "config")
	activePath := filepath.Join(configDir, "active-fingerprints", "shiro-detect.yaml")
	content, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	classification, err := activefingerprint.Inspect("shiro-detect.yaml", content)
	if err != nil {
		t.Fatal(err)
	}
	if !classification.AutoEligible || classification.Product != "APACHE-Shiro" || classification.MaxRequests != 1 {
		t.Fatalf("unexpected Shiro behavior probe classification: %+v", classification)
	}
	if _, err := os.Stat(filepath.Join(configDir, "pocs", "shiro-detect.yaml")); !os.IsNotExist(err) {
		t.Fatalf("legacy Shiro POC must be absent, stat error=%v", err)
	}
	workflow, err := os.ReadFile(filepath.Join(configDir, "workflow.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(workflow), "General-Poc-Shiro") {
		t.Fatal("legacy General-Poc-Shiro workflow remains enabled")
	}
}

func createInspectionPackage(t *testing.T, path string, timestamp time.Time, executionClass string) {
	t.Helper()
	if err := OpenDB(path); err != nil {
		t.Fatalf("open package: %v", err)
	}
	models := []any{
		&Fingerprint{ProductName: "Demo", RuleExpr: `body="demo"`, Category: "web", Enabled: true, CreatedAt: timestamp, UpdatedAt: timestamp},
		&Workflow{ProductName: "Demo", PocName: "demo.yaml", MatchType: "root", Enabled: true, CreatedAt: timestamp, UpdatedAt: timestamp},
		&DirProbe{ProductName: "Demo", Path: "/demo", Enabled: true, CreatedAt: timestamp, UpdatedAt: timestamp},
		&Poc{Name: "demo", FileName: "demo.yaml", Content: "id: demo\n", Severity: "info", ExecutionClass: executionClass, RiskLevel: "unknown", Enabled: true, CreatedAt: timestamp, UpdatedAt: timestamp},
	}
	for _, model := range models {
		if err := DB.Create(model).Error; err != nil {
			t.Fatalf("create package row: %v", err)
		}
	}
	if err := CloseDB(); err != nil {
		t.Fatalf("close package: %v", err)
	}
}

func writePackageTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
