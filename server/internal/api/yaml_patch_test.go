package api

import (
	"strings"
	"testing"
)

func TestUpsertYAMLMappingKeyPreservesSiblingOrderAndComments(t *testing.T) {
	existing := "# keep-me\nExistingProduct:\n    - body=\"old\"\nZedLast:\n    - title=\"z\"\n"
	got, err := upsertYAMLMappingKey(existing, "ArgusMCP", []string{`body="new"`})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	existingIdx := strings.Index(got, "ExistingProduct:")
	zedIdx := strings.Index(got, "ZedLast:")
	newIdx := strings.Index(got, "ArgusMCP:")
	if existingIdx < 0 || zedIdx < 0 || newIdx < 0 {
		t.Fatalf("missing keys in:\n%s", got)
	}
	if !(existingIdx < zedIdx && zedIdx < newIdx) {
		t.Fatalf("expected ExistingProduct then ZedLast then ArgusMCP, got:\n%s", got)
	}
	if !strings.Contains(got, "# keep-me") {
		t.Fatalf("lost comment:\n%s", got)
	}
	if !strings.Contains(got, `body="old"`) || !strings.Contains(got, `title="z"`) || !strings.Contains(got, `body="new"`) {
		t.Fatalf("lost mapping values:\n%s", got)
	}
}

func TestUpsertYAMLMappingKeyReplacesOneWorkflowEntry(t *testing.T) {
	existing := "KeepMe:\n  type:\n    - root\n  pocs:\n    - keep.yaml\n  risk_level: high\n"
	got, err := upsertYAMLMappingKey(existing, "KeepMe", WorkflowEntry{
		Type:      []string{"root", "base"},
		Pocs:      []string{"keep.yaml", "extra.yaml"},
		RiskLevel: "info",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !strings.Contains(got, "risk_level: info") || strings.Contains(got, "risk_level: high") {
		t.Fatalf("risk_level not replaced:\n%s", got)
	}
	if !strings.Contains(got, "extra.yaml") {
		t.Fatalf("pocs not replaced:\n%s", got)
	}
}
