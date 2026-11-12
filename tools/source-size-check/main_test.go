package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanRejectsNewOversizedFile(t *testing.T) {
	root := t.TempDir()
	writeLines(t, filepath.Join(root, "server", "large.go"), 801)

	result, err := scan(root, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Violations) != 1 || result.Violations[0].Path != "server/large.go" {
		t.Fatalf("violations = %+v, want server/large.go", result.Violations)
	}
}

func TestScanAllowsFileWithinRecordedBaseline(t *testing.T) {
	root := t.TempDir()
	writeLines(t, filepath.Join(root, "server", "legacy.go"), 900)

	result, err := scan(root, map[string]int{"server/legacy.go": 900})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Fatalf("violations = %+v, want none", result.Violations)
	}
	if len(result.BaselineWarnings) != 1 {
		t.Fatalf("baseline warnings = %+v, want one", result.BaselineWarnings)
	}
}

func TestScanRejectsBaselineGrowth(t *testing.T) {
	root := t.TempDir()
	writeLines(t, filepath.Join(root, "server-ui", "src", "Legacy.tsx"), 711)

	result, err := scan(root, map[string]int{"server-ui/src/Legacy.tsx": 710})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Violations) != 1 || !strings.Contains(result.Violations[0].Reason, "baseline 710") {
		t.Fatalf("violations = %+v, want baseline growth", result.Violations)
	}
}

func TestScanIgnoresGeneratedDirectory(t *testing.T) {
	root := t.TempDir()
	writeLines(t, filepath.Join(root, "shared", "generated", "large.go"), 1200)

	result, err := scan(root, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Violations) != 0 {
		t.Fatalf("violations = %+v, want generated directory ignored", result.Violations)
	}
}

func writeLines(t *testing.T, path string, count int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x\n", count)), 0o644); err != nil {
		t.Fatal(err)
	}
}
