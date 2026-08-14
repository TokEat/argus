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
    argus-risk-level: high
`))

	if meta.executionClass != "verification" || meta.riskLevel != "high" {
		t.Fatalf("unexpected POC governance metadata: %+v", meta)
	}
	if err := validatePocGovernanceMeta(meta); err != nil {
		t.Fatalf("expected governed POC to be accepted: %v", err)
	}
}

func TestParsePocMetaUsesSafeLegacyDefaults(t *testing.T) {
	meta := parsePocMeta([]byte("id: legacy\ninfo:\n  name: Legacy\n  severity: info\n"))

	if meta.executionClass != "detection" || meta.riskLevel != "unknown" {
		t.Fatalf("unexpected legacy POC governance defaults: %+v", meta)
	}
	if err := validatePocGovernanceMeta(meta); err != nil {
		t.Fatalf("expected legacy POC to remain importable: %v", err)
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
