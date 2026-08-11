package arsenal

import (
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
