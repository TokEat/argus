package localstate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
)

func TestFinishedRunsAtomicallyMergeAssetsAndCoverage(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	run1 := mustStartDeterministicRun(t, layout, time.Unix(10, 0), 1, []string{"https://example.test"})
	run1.ObserveOutput(engine.OutputMessage{Type: "Web", URI: "https://example.test/?token=one", Web: engine.WebInfo{Status: "200", Title: "first"}})
	run1.ObserveOutput(engine.OutputMessage{Type: "Finger", URI: "https://example.test/", Finger: []string{"nginx"}})
	run1.ObserveCoverage("executed", "full_scan", CoverageRecord{
		WorkKey: "work-1", NormalizedTarget: "https://example.test/", Stage: "http_probe",
		ScopeHash: "scope", ConfigHash: "config", RuleVersion: "rules-1", Outcome: "success",
		ContentHash: "content-1", ObservedAt: time.Unix(20, 0), ValidUntil: time.Unix(30, 0),
	})
	if err := run1.Finish(nil); err != nil {
		t.Fatalf("finish run 1: %v", err)
	}
	assets1 := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(assets1) != 1 || assets1[0][1] != "https://example.test/" || assets1[0][6] != run1.ID {
		t.Fatalf("assets after run 1 = %#v", assets1)
	}
	firstSeen := assets1[0][4]
	firstContent := assets1[0][8]
	coverage1 := mustReadTable(t, layout.CoveragePath, coverageSchema)
	if len(coverage1) != 1 || coverage1[0][0] != "work-1" || coverage1[0][10] != run1.ID {
		t.Fatalf("coverage after run 1 = %#v", coverage1)
	}

	run2 := mustStartDeterministicRun(t, layout, time.Unix(40, 0), 2, []string{"https://example.test", "https://example.test"})
	run2.ObserveOutput(engine.OutputMessage{Type: "Web", URI: "https://example.test/", Web: engine.WebInfo{Status: "200", Title: "changed"}})
	run2.ObserveCoverage("executed", "refresh", CoverageRecord{
		WorkKey: "work-1", NormalizedTarget: "https://example.test/", Stage: "http_probe",
		ScopeHash: "scope", ConfigHash: "config", RuleVersion: "rules-1", Outcome: "negative",
		ContentHash: "content-2", ObservedAt: time.Unix(50, 0), ValidUntil: time.Unix(60, 0),
	})
	if err := run2.Finish(nil); err != nil {
		t.Fatalf("finish run 2: %v", err)
	}
	assets2 := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(assets2) != 1 || assets2[0][4] != firstSeen || assets2[0][6] != run2.ID || assets2[0][8] == firstContent {
		t.Fatalf("assets after run 2 = %#v", assets2)
	}
	coverage2 := mustReadTable(t, layout.CoveragePath, coverageSchema)
	if len(coverage2) != 1 || coverage2[0][6] != "negative" || coverage2[0][7] != "content-2" || coverage2[0][10] != run2.ID {
		t.Fatalf("coverage after run 2 = %#v", coverage2)
	}
	run3 := mustStartDeterministicRun(t, layout, time.Unix(70, 0), 7, []string{"https://example.test"})
	run3.ObserveCoverage("executed", "late_old_evidence", CoverageRecord{
		WorkKey: "work-1", NormalizedTarget: "https://example.test/", Stage: "http_probe",
		ScopeHash: "scope", ConfigHash: "config", RuleVersion: "rules-1", Outcome: "success",
		ContentHash: "stale-content", ObservedAt: time.Unix(45, 0), ValidUntil: time.Unix(55, 0),
	})
	if err := run3.Finish(nil); err != nil {
		t.Fatalf("finish run 3: %v", err)
	}
	coverage3 := mustReadTable(t, layout.CoveragePath, coverageSchema)
	if len(coverage3) != 1 || coverage3[0][7] != "content-2" || coverage3[0][10] != run2.ID {
		t.Fatalf("older coverage replaced newer evidence: %#v", coverage3)
	}
	assertSummaryValue(t, run2.SummaryPath, "merge_status", "merged")
	if _, err := os.Stat(filepath.Join(run2.Dir, ".active.lock")); !os.IsNotExist(err) {
		t.Fatalf("completed run retained active lock: %v", err)
	}
}

func TestMergeReportsAndRemovesDamagedDataRows(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	assetFile, err := os.OpenFile(layout.AssetsPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open assets: %v", err)
	}
	_, _ = assetFile.WriteString("damaged\\q\nwrong\tcolumns\n")
	_ = assetFile.Close()
	run := mustStartDeterministicRun(t, layout, time.Unix(10, 0), 3, []string{"192.0.2.10"})
	run.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: "192.0.2.10", Port: "443"})
	if err := run.Finish(nil); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	warnings := strings.Join(run.Warnings(), "\n")
	if !strings.Contains(warnings, "assets.tsv line 3 skipped") || !strings.Contains(warnings, "assets.tsv line 4 skipped") {
		t.Fatalf("warnings = %q", warnings)
	}
	rows := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(rows) != 1 || rows[0][1] != "192.0.2.10:443" {
		t.Fatalf("cleaned assets = %#v", rows)
	}
}

func TestConcurrentRunFinalizationDoesNotLoseState(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	runA := mustStartDeterministicRun(t, layout, time.Unix(10, 0), 8, []string{"192.0.2.80"})
	runB := mustStartDeterministicRun(t, layout, time.Unix(11, 0), 9, []string{"192.0.2.90"})
	runA.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: "192.0.2.80", Port: "80"})
	runB.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: "192.0.2.90", Port: "90"})
	var wait sync.WaitGroup
	errorsByRun := make(chan error, 2)
	for _, run := range []*Run{runA, runB} {
		wait.Add(1)
		go func(run *Run) {
			defer wait.Done()
			errorsByRun <- run.Finish(nil)
		}(run)
	}
	wait.Wait()
	close(errorsByRun)
	for err := range errorsByRun {
		if err != nil {
			t.Fatalf("concurrent finish: %v", err)
		}
	}
	rows := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(rows) != 2 {
		t.Fatalf("concurrent state merge lost an asset: %#v", rows)
	}
}

func TestUnsafeCoverageTargetFailsClosedWithoutStateMerge(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	run := mustStartDeterministicRun(t, layout, time.Unix(10, 0), 10, []string{"https://example.test"})
	run.ObserveCoverage("executed", "full_scan", CoverageRecord{
		WorkKey: "work-unsafe", NormalizedTarget: "https://user:secret@example.test/?token=secret", Stage: "fingerprint",
		ScopeHash: "scope", ConfigHash: "config", RuleVersion: "rules-1", Outcome: "success",
		ObservedAt: time.Unix(20, 0), ValidUntil: time.Unix(30, 0),
	})
	if err := run.Finish(nil); err == nil || !strings.Contains(err.Error(), "coverage normalized_target") {
		t.Fatalf("unsafe coverage finish error = %v", err)
	}
	assertSummaryValue(t, run.SummaryPath, "merge_status", "not_merged")
	if rows := mustReadTable(t, layout.CoveragePath, coverageSchema); len(rows) != 0 {
		t.Fatalf("unsafe coverage contaminated state: %#v", rows)
	}
}

func TestValidLocalRunIDRejectsPathTraversal(t *testing.T) {
	for _, value := range []string{"", ".", "..", "../run", `..\run`, `C:\run`, " run-1", "run-1\n"} {
		if validLocalRunID(value) {
			t.Fatalf("unsafe run id %q was accepted", value)
		}
	}
	for _, value := range []string{"run-1", "20260809T201624.167553000Z-84616c680d96"} {
		if !validLocalRunID(value) {
			t.Fatalf("safe run id %q was rejected", value)
		}
	}
}

func mustStartDeterministicRun(t *testing.T, layout Layout, startedAt time.Time, randomByte byte, targets []string) *Run {
	t.Helper()
	run, err := startRun(layout, targets, startedAt, bytes.NewReader(bytes.Repeat([]byte{randomByte}, 6)))
	if err != nil {
		t.Fatalf("start run: %v", err)
	}
	return run
}

func mustReadTable(t *testing.T, path string, schema tableSchema) [][]string {
	t.Helper()
	rows, warnings, err := readTable(path, schema)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(warnings) != 0 {
		t.Fatalf("read %s warnings: %v", path, warnings)
	}
	return rows
}
