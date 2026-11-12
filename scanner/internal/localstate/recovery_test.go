package localstate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/internal/engine"
)

func TestRecoveryLeavesActiveRunUntouchedThenMarksItInterrupted(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	run := mustStartDeterministicRun(t, layout, time.Unix(10, 0), 4, []string{"192.0.2.20"})
	run.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: "192.0.2.20", Port: "80"})
	warnings, err := recoverRuns(layout, time.Unix(20, 0))
	if err != nil {
		t.Fatalf("recover with active run: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("active run warnings = %v", warnings)
	}
	assertSummaryValue(t, run.SummaryPath, "status", "running")

	run.mu.Lock()
	_ = run.findingsFile.Close()
	_ = run.coverageFile.Close()
	_ = run.timingFile.Close()
	run.releaseActiveLock(false)
	run.mu.Unlock()
	warnings, err = recoverRuns(layout, time.Unix(30, 0))
	if err != nil {
		t.Fatalf("recover interrupted run: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "marked interrupted") {
		t.Fatalf("interrupted warnings = %v", warnings)
	}
	assertSummaryValue(t, run.SummaryPath, "status", "interrupted")
	assertSummaryValue(t, run.SummaryPath, "merge_status", "not_merged")
	if rows := mustReadTable(t, layout.AssetsPath, assetsSchema); len(rows) != 0 {
		t.Fatalf("interrupted run contaminated assets: %#v", rows)
	}
}

func TestRecoveryCompletesPendingStateMergeIdempotently(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	run := mustStartDeterministicRun(t, layout, time.Unix(10, 0), 5, []string{"https://example.test"})
	run.ObserveOutput(engine.OutputMessage{Type: "Web", URI: "https://example.test", Web: engine.WebInfo{Status: "200"}})
	run.mu.Lock()
	_ = run.findingsFile.Close()
	_ = run.coverageFile.Close()
	_ = run.timingFile.Close()
	summary := runSummary{
		RunID: run.ID, Status: "finalizing", TerminalStatus: "completed", MergeStatus: "pending",
		StartedAt: run.startedAt, FinishedAt: time.Unix(20, 0), TargetCount: 1, FindingCount: 1,
	}
	if err := writeRunSummary(run.SummaryPath, summary); err != nil {
		run.mu.Unlock()
		t.Fatalf("write finalizing summary: %v", err)
	}
	run.releaseActiveLock(false)
	run.mu.Unlock()

	warnings, err := recoverRuns(layout, time.Unix(30, 0))
	if err != nil {
		t.Fatalf("recover finalizing run: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "pending state merge recovered") {
		t.Fatalf("recovery warnings = %v", warnings)
	}
	assertSummaryValue(t, run.SummaryPath, "status", "completed")
	assertSummaryValue(t, run.SummaryPath, "merge_status", "merged")
	if rows := mustReadTable(t, layout.AssetsPath, assetsSchema); len(rows) != 1 {
		t.Fatalf("recovered assets = %#v", rows)
	}
	warnings, err = recoverRuns(layout, time.Unix(40, 0))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("idempotent recovery warnings/error = %v / %v", warnings, err)
	}
	if rows := mustReadTable(t, layout.AssetsPath, assetsSchema); len(rows) != 1 {
		t.Fatalf("idempotent recovered assets = %#v", rows)
	}
}

func TestRecoveryReportsDamagedRunWithoutBlockingNewHistory(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	damagedDir := filepath.Join(layout.RunsDir, "damaged-run")
	if err := os.Mkdir(damagedDir, 0o700); err != nil {
		t.Fatalf("create damaged run: %v", err)
	}
	if err := os.WriteFile(filepath.Join(damagedDir, "summary.txt"), []byte("broken\n"), 0o600); err != nil {
		t.Fatalf("write damaged summary: %v", err)
	}
	warnings, err := recoverRuns(layout, time.Unix(30, 0))
	if err != nil {
		t.Fatalf("recover damaged run: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "recovery skipped") {
		t.Fatalf("damaged run warnings = %v", warnings)
	}
	warnings, err = recoverRuns(layout, time.Unix(35, 0))
	if err != nil || !strings.Contains(strings.Join(warnings, "\n"), "recovery skipped") {
		t.Fatalf("damaged run retry warnings/error = %v / %v", warnings, err)
	}
	run, err := startRun(layout, []string{"192.0.2.30"}, time.Unix(40, 0), bytes.NewReader(bytes.Repeat([]byte{6}, 6)))
	if err != nil {
		t.Fatalf("start new run after damaged history: %v", err)
	}
	if err := run.Finish(nil); err != nil {
		t.Fatalf("finish new run: %v", err)
	}
}

func TestRecoveryImportsCompletedG24RunWithoutMergeMetadata(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	runID := "20260809T000000.000000000Z-aabbccddeeff"
	runDir := filepath.Join(layout.RunsDir, runID)
	if err := os.Mkdir(runDir, 0o700); err != nil {
		t.Fatalf("create legacy run: %v", err)
	}
	for name, schema := range map[string]tableSchema{
		"targets.tsv": targetsSchema, "findings.tsv": findingsSchema, "coverage.tsv": runCoverageSchema,
	} {
		file, err := createRunTable(filepath.Join(runDir, name), schema)
		if err != nil {
			t.Fatalf("create legacy %s: %v", name, err)
		}
		if name == "findings.tsv" {
			row := make([]string, len(findingsSchema.Columns))
			row[0], row[1], row[2], row[3], row[4], row[5] = "1", time.Unix(10, 0).UTC().Format(time.RFC3339Nano), "PortScan", "192.0.2.50:443", "192.0.2.50", "443"
			if _, err := file.WriteString(encodeTSVRow(row...)); err != nil {
				t.Fatalf("write legacy finding: %v", err)
			}
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close legacy %s: %v", name, err)
		}
	}
	legacySummary := strings.Join([]string{
		"schema_version=" + RunSummarySchemaVersion,
		"run_id=" + runID,
		"status=completed",
		"started_at=2026-08-09T00:00:00Z",
		"finished_at=2026-08-09T00:00:01Z",
		"target_count=1",
		"finding_count=1",
		"coverage_count=0",
		"error=",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(runDir, "summary.txt"), []byte(legacySummary), 0o600); err != nil {
		t.Fatalf("write legacy summary: %v", err)
	}
	warnings, err := recoverRuns(layout, time.Unix(30, 0))
	if err != nil {
		t.Fatalf("recover legacy run: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "pending state merge recovered") {
		t.Fatalf("legacy recovery warnings = %v", warnings)
	}
	assertSummaryValue(t, filepath.Join(runDir, "summary.txt"), "merge_status", "merged")
	if rows := mustReadTable(t, layout.AssetsPath, assetsSchema); len(rows) != 1 || rows[0][1] != "192.0.2.50:443" {
		t.Fatalf("legacy recovered assets = %#v", rows)
	}
}
