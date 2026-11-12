package arsenal

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePocMetaExecutionGovernance(t *testing.T) {
	meta := parsePocMeta([]byte(`id: governed
info:
  name: Governed
  severity: high
  metadata:
    argus-execution-class: verification
`))

	if meta.executionClass != "verification" || meta.riskLevel != "high" {
		t.Fatalf("unexpected POC governance metadata: %+v", meta)
	}
	if err := validatePocGovernanceMeta(meta); err != nil {
		t.Fatalf("expected governed POC to be accepted: %v", err)
	}
}

func TestParsePocMetaUsesNucleiSeverityForRisk(t *testing.T) {
	info := parsePocMeta([]byte("id: info\ninfo:\n  name: Info\n  severity: info\n"))
	if info.executionClass != "detection" || info.riskLevel != "info" {
		t.Fatalf("unexpected info POC governance: %+v", info)
	}
	if err := validatePocGovernanceMeta(info); err != nil {
		t.Fatalf("expected info POC to remain importable: %v", err)
	}

	missing := parsePocMeta([]byte("id: missing\ninfo:\n  name: Missing\n"))
	if missing.riskLevel != "unknown" || missing.severity != "info" {
		t.Fatalf("missing severity should stay unknown risk: %+v", missing)
	}

	critical := parsePocMeta([]byte("id: critical\ninfo:\n  name: Critical\n  severity: critical\n"))
	if critical.riskLevel != "high" {
		t.Fatalf("critical should store as high: %+v", critical)
	}

	ignored := parsePocMeta([]byte("id: ignore\ninfo:\n  name: Ignore\n  severity: info\n  metadata:\n    argus-risk-level: high\n"))
	if ignored.riskLevel != "info" {
		t.Fatalf("argus-risk-level must be ignored: %+v", ignored)
	}
}

func TestValidatePocGovernanceRejectsExploitClass(t *testing.T) {
	err := validatePocGovernanceMeta(pocMeta{executionClass: "exploit", riskLevel: "high"})
	if err == nil || !strings.Contains(err.Error(), "separate EXP package") {
		t.Fatalf("expected exploit-class POC rejection, got %v", err)
	}
}

func TestBuiltinActiveFingerprintDoesNotOverwriteCustomConflict(t *testing.T) {
	if err := OpenDB(filepath.Join(t.TempDir(), "arsenal.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseDB() })
	custom := ActiveFingerprint{Name: "custom-shiro", FileName: "shiro-detect.yaml", ProductName: "Custom-Shiro", Content: "custom", ContentHash: "custom-hash", AutoEligible: false, Enabled: true, Source: "custom"}
	if err := DB.Create(&custom).Error; err != nil {
		t.Fatal(err)
	}
	created, err := AddActiveFingerprint(&ActiveFingerprint{Name: "shiro-detect", FileName: custom.FileName, ProductName: "APACHE-Shiro", Content: "builtin", ContentHash: "builtin-hash", AutoEligible: true, Enabled: true, Source: "builtin"})
	if err != nil || created {
		t.Fatalf("builtin conflict result: created=%t err=%v", created, err)
	}
	var stored ActiveFingerprint
	if err := DB.Where("file_name = ?", custom.FileName).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Source != "custom" || stored.Content != "custom" || stored.ProductName != "Custom-Shiro" {
		t.Fatalf("custom active fingerprint was overwritten: %+v", stored)
	}
}
