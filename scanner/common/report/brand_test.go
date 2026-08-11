package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportsUseArgusBrand(t *testing.T) {
	startedAt := time.Date(2026, time.August, 11, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "argus-report.html")
	session, err := NewSession(Options{
		Path: path, RunID: "brand-test", SourceFile: "result.txt", StartedAt: startedAt,
	})
	if err != nil {
		t.Fatalf("create report session: %v", err)
	}
	t.Cleanup(func() { _ = session.Abort() })
	if err := session.Finish(Summary{Status: "completed", FinishedAt: startedAt.Add(time.Second)}); err != nil {
		t.Fatalf("finish report session: %v", err)
	}
	contentBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	content := string(contentBytes)
	legacyName := "dd" + "dd"
	if !strings.Contains(content, "Argus") {
		t.Fatal("unified report is missing the Argus brand")
	}
	if strings.Contains(strings.ToLower(content), legacyName) {
		t.Fatalf("unified report still contains the legacy brand %q", legacyName)
	}
}
