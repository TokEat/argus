package localstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunSummaryAtomicRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.txt")
	want := runSummary{
		RunID: "run-1", Status: "failed", TerminalStatus: "failed", MergeStatus: "merged",
		StartedAt: time.Unix(1, 2), FinishedAt: time.Unix(3, 4), MergedAt: time.Unix(5, 6),
		TargetCount: 2, FindingCount: 3, CoverageCount: 4, Error: "failed\twith\nmultiple lines",
		Difference: DifferenceSummary{
			AssetNew: 5, ServiceChanged: 6, AssetDisappeared: 7, AssetNotAssessed: 8,
			StageExecuted: 9, StageReused: 10, FullTargets: 11, IncrementalTargets: 12,
		},
	}
	if err := writeRunSummary(path, want); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	got, err := readRunSummary(path)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if got.RunID != want.RunID || got.Status != want.Status || got.MergeStatus != want.MergeStatus ||
		!got.StartedAt.Equal(want.StartedAt) || !got.MergedAt.Equal(want.MergedAt) || got.Error != want.Error || got.Difference != want.Difference {
		t.Fatalf("summary = %#v, want %#v", got, want)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("list summary directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".summary.txt.tmp-") {
			t.Fatalf("summary temporary file remains: %s", entry.Name())
		}
	}
}

func TestReadLegacyRunSummaryDefaultsDifferenceCounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.txt")
	contents := strings.Join([]string{
		"schema_version=" + RunSummarySchemaVersion,
		"run_id=legacy-run",
		"status=completed",
		"started_at=2026-08-09T00:00:00Z",
		"target_count=1",
		"finding_count=0",
		"coverage_count=0",
		"error=",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := readRunSummary(path)
	if err != nil {
		t.Fatalf("read legacy summary: %v", err)
	}
	if summary.Difference != (DifferenceSummary{}) {
		t.Fatalf("legacy difference = %#v", summary.Difference)
	}
}

func TestReadRunSummaryRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.txt")
	contents := "schema_version=" + RunSummarySchemaVersion + "\nrun_id=one\nrun_id=two\nstatus=running\nstarted_at=2026-08-09T00:00:00Z\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	if _, err := readRunSummary(path); err == nil || !strings.Contains(err.Error(), "repeats key") {
		t.Fatalf("duplicate key error = %v", err)
	}
}
