package localstate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
)

func TestRunDeltaConfirmsDisappearanceAndReappearance(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatal(err)
	}
	target := "192.0.2.10"
	run1 := mustStartDeterministicRun(t, layout, time.Unix(10, 0), 31, []string{target})
	mustSetFullDecision(t, run1, target)
	run1.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: target, Port: "443"})
	run1.ObserveCoverage("executed", "stage_completed", portCoverage(run1.ID, target, "success", time.Now().UTC()))
	if err := run1.Finish(nil); err != nil {
		t.Fatalf("finish first run: %v", err)
	}
	firstState := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(firstState) != 1 || firstState[0][7] != "active" {
		t.Fatalf("first state = %#v", firstState)
	}
	firstSeen := firstState[0][4]
	firstDelta, err := readDelta(run1.DeltaPath)
	if err != nil || countDeltaKind(firstDelta, DeltaAssetNew) != 1 || countDeltaKind(firstDelta, DeltaStageExecuted) != 1 {
		t.Fatalf("first delta = %#v / %v", firstDelta, err)
	}

	run2 := mustStartDeterministicRun(t, layout, time.Unix(20, 0), 32, []string{target})
	mustSetFullDecision(t, run2, target)
	run2.ObserveCoverage("executed", "stage_completed", portCoverage(run2.ID, target, "negative", time.Now().UTC()))
	if err := run2.Finish(nil); err != nil {
		t.Fatalf("finish disappearance run: %v", err)
	}
	secondDelta, err := readDelta(run2.DeltaPath)
	if err != nil || countDeltaKind(secondDelta, DeltaAssetDisappeared) != 1 {
		t.Fatalf("disappearance delta = %#v / %v", secondDelta, err)
	}
	secondState := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(secondState) != 1 || secondState[0][7] != "disappeared" || secondState[0][4] != firstSeen || secondState[0][6] != run2.ID || secondState[0][5] == firstState[0][5] {
		t.Fatalf("tombstone state = %#v", secondState)
	}

	run3 := mustStartDeterministicRun(t, layout, time.Unix(30, 0), 33, []string{target})
	mustSetFullDecision(t, run3, target)
	run3.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: target, Port: "443"})
	run3.ObserveCoverage("executed", "stage_completed", portCoverage(run3.ID, target, "success", time.Now().UTC()))
	if err := run3.Finish(nil); err != nil {
		t.Fatalf("finish reappearance run: %v", err)
	}
	thirdDelta, err := readDelta(run3.DeltaPath)
	if err != nil || countDeltaKind(thirdDelta, DeltaServiceChanged) != 1 || !hasDeltaReason(thirdDelta, "asset_reappeared") {
		t.Fatalf("reappearance delta = %#v / %v", thirdDelta, err)
	}
	thirdState := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(thirdState) != 1 || thirdState[0][7] != "active" || thirdState[0][4] != firstSeen || thirdState[0][6] != run3.ID {
		t.Fatalf("reactivated state = %#v", thirdState)
	}
}

func TestIncrementalAndFailedRunsNeverConfirmDisappearance(t *testing.T) {
	layout, target := baselinePortAsset(t)
	baseline := mustReadTable(t, layout.AssetsPath, assetsSchema)

	run2 := mustStartDeterministicRun(t, layout, time.Unix(20, 0), 35, []string{target})
	if err := run2.SetTargetDecisions(map[string]TargetDecision{target: {Action: "incremental", Reason: "known_services_revalidated"}}); err != nil {
		t.Fatal(err)
	}
	previousCoverage := mustReadTable(t, layout.CoveragePath, coverageSchema)[0]
	observedAt, _ := time.Parse(time.RFC3339Nano, previousCoverage[8])
	validUntil, _ := parseSummaryTime(previousCoverage[9], false)
	run2.ObserveCoverage("reused", "valid_local_coverage", CoverageRecord{
		WorkKey: previousCoverage[0], NormalizedTarget: previousCoverage[1], Stage: previousCoverage[2],
		ScopeHash: previousCoverage[3], ConfigHash: previousCoverage[4], RuleVersion: previousCoverage[5],
		Outcome: previousCoverage[6], ContentHash: previousCoverage[7], ObservedAt: observedAt,
		ValidUntil: validUntil, LastRunID: previousCoverage[10],
	})
	if err := run2.Finish(nil); err != nil {
		t.Fatalf("finish incremental run: %v", err)
	}
	delta, err := readDelta(run2.DeltaPath)
	if err != nil || countDeltaKind(delta, DeltaAssetDisappeared) != 0 || countDeltaKind(delta, DeltaAssetNotAssessed) != 1 || countDeltaKind(delta, DeltaStageReused) != 1 {
		t.Fatalf("incremental delta = %#v / %v", delta, err)
	}
	if state := mustReadTable(t, layout.AssetsPath, assetsSchema); state[0][7] != "active" || state[0][6] != baseline[0][6] || state[0][8] != baseline[0][8] {
		t.Fatalf("incremental run changed asset state: %#v", state)
	}

	run3 := mustStartDeterministicRun(t, layout, time.Unix(30, 0), 36, []string{target})
	mustSetFullDecision(t, run3, target)
	run3.ObserveCoverage("executed", "stage_completed", portCoverage(run3.ID, target, "negative", time.Now().UTC()))
	if err := run3.Finish(errors.New("scan failed")); err != nil {
		t.Fatalf("finish failed scan history: %v", err)
	}
	delta, err = readDelta(run3.DeltaPath)
	if err != nil || countDeltaKind(delta, DeltaAssetDisappeared) != 0 || countDeltaKind(delta, DeltaAssetNotAssessed) != 1 {
		t.Fatalf("failed-run delta = %#v / %v", delta, err)
	}
	if state := mustReadTable(t, layout.AssetsPath, assetsSchema); state[0][7] != "active" {
		t.Fatalf("failed run created tombstone: %#v", state)
	}
}

func TestFailedRunCannotReactivateTombstone(t *testing.T) {
	layout, target := baselinePortAsset(t)
	disappearance := mustStartDeterministicRun(t, layout, time.Unix(20, 0), 51, []string{target})
	mustSetFullDecision(t, disappearance, target)
	disappearance.ObserveCoverage("executed", "stage_completed", portCoverage(disappearance.ID, target, "negative", time.Now().UTC()))
	if err := disappearance.Finish(nil); err != nil {
		t.Fatalf("finish disappearance run: %v", err)
	}
	tombstone := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(tombstone) != 1 || tombstone[0][7] != "disappeared" {
		t.Fatalf("tombstone state = %#v", tombstone)
	}

	failed := mustStartDeterministicRun(t, layout, time.Unix(30, 0), 52, []string{target})
	mustSetFullDecision(t, failed, target)
	failed.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: target, Port: "443"})
	failed.ObserveCoverage("executed", "stage_completed", portCoverage(failed.ID, target, "success", time.Now().UTC()))
	if err := failed.Finish(errors.New("scan failed after partial output")); err != nil {
		t.Fatalf("finish failed run history: %v", err)
	}
	delta, err := readDelta(failed.DeltaPath)
	if err != nil || countDeltaKind(delta, DeltaServiceChanged) != 0 || countDeltaKind(delta, DeltaAssetNotAssessed) != 1 {
		t.Fatalf("failed reappearance delta = %#v / %v", delta, err)
	}
	after := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(after) != 1 || strings.Join(after[0], "\x00") != strings.Join(tombstone[0], "\x00") {
		t.Fatalf("failed run reactivated or advanced tombstone: before=%#v after=%#v", tombstone, after)
	}
}

func TestDelayedOlderObservationCannotReactivateNewerTombstone(t *testing.T) {
	layout, target := baselinePortAsset(t)
	delayed := mustStartDeterministicRun(t, layout, time.Unix(20, 0), 53, []string{target})
	mustSetFullDecision(t, delayed, target)
	delayed.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: target, Port: "443"})
	delayed.ObserveCoverage("executed", "stage_completed", portCoverage(delayed.ID, target, "success", time.Now().UTC()))
	time.Sleep(2 * time.Millisecond)

	disappearance := mustStartDeterministicRun(t, layout, time.Unix(30, 0), 54, []string{target})
	mustSetFullDecision(t, disappearance, target)
	disappearance.ObserveCoverage("executed", "stage_completed", portCoverage(disappearance.ID, target, "negative", time.Now().UTC()))
	if err := disappearance.Finish(nil); err != nil {
		t.Fatalf("finish disappearance run: %v", err)
	}
	tombstone := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if err := delayed.Finish(nil); err != nil {
		t.Fatalf("finish delayed run: %v", err)
	}
	delta, err := readDelta(delayed.DeltaPath)
	if err != nil || countDeltaKind(delta, DeltaServiceChanged) != 0 || !hasDeltaReason(delta, "stale_observation") {
		t.Fatalf("delayed observation delta = %#v / %v", delta, err)
	}
	after := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(after) != 1 || strings.Join(after[0], "\x00") != strings.Join(tombstone[0], "\x00") {
		t.Fatalf("delayed observation reactivated tombstone: before=%#v after=%#v", tombstone, after)
	}
}

func TestRecoverySkipsStaleDisappearanceAfterNewerObservation(t *testing.T) {
	layout, target := baselinePortAsset(t)
	stale := mustStartDeterministicRun(t, layout, time.Unix(20, 0), 55, []string{target})
	mustSetFullDecision(t, stale, target)
	stale.ObserveCoverage("executed", "stage_completed", portCoverage(stale.ID, target, "negative", time.Now().UTC()))
	stale.mu.Lock()
	_ = stale.findingsFile.Close()
	_ = stale.coverageFile.Close()
	_ = stale.timingFile.Close()
	summary := runSummary{
		RunID: stale.ID, Status: "finalizing", TerminalStatus: "completed", MergeStatus: "pending",
		StartedAt: stale.startedAt, FinishedAt: time.Now().UTC(), TargetCount: 1, CoverageCount: 1,
	}
	if err := writeRunSummary(stale.SummaryPath, summary); err != nil {
		stale.mu.Unlock()
		t.Fatal(err)
	}
	stateLock, locked, err := acquireFileLock(filepath.Join(layout.StateDir, ".merge.lock"), false)
	if err != nil || !locked {
		stale.mu.Unlock()
		t.Fatalf("acquire merge lock: %v / %v", locked, err)
	}
	_, difference, _, err := prepareRunDifference(layout, stale.Dir, true)
	_ = releaseFileLock(stateLock)
	if err != nil || difference.AssetDisappeared != 1 {
		stale.mu.Unlock()
		t.Fatalf("prepare stale disappearance: %#v / %v", difference, err)
	}
	stale.mu.Unlock()

	newer := mustStartDeterministicRun(t, layout, time.Unix(30, 0), 56, []string{target})
	mustSetFullDecision(t, newer, target)
	newer.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: target, Port: "443"})
	newer.ObserveCoverage("executed", "stage_completed", portCoverage(newer.ID, target, "success", time.Now().UTC()))
	if err := newer.Finish(nil); err != nil {
		t.Fatalf("finish newer run: %v", err)
	}
	newerState := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(newerState) != 1 || newerState[0][6] != newer.ID || newerState[0][7] != "active" {
		t.Fatalf("newer state = %#v", newerState)
	}

	stale.mu.Lock()
	stale.releaseActiveLock(false)
	stale.mu.Unlock()
	warnings, err := recoverRuns(layout, time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("recover stale run: %v", err)
	}
	after := mustReadTable(t, layout.AssetsPath, assetsSchema)
	if len(after) != 1 || after[0][6] != newer.ID || after[0][7] != "active" || !strings.Contains(strings.Join(warnings, "\n"), "stale disappearance") {
		t.Fatalf("stale recovery changed newer state: warnings=%v state=%#v", warnings, after)
	}
}

func TestRecoveryReusesDeltaAndDamagedDeltaFailsClosed(t *testing.T) {
	for _, damaged := range []bool{false, true} {
		t.Run(map[bool]string{false: "reuse", true: "damaged"}[damaged], func(t *testing.T) {
			layout, target := baselinePortAsset(t)
			run := mustStartDeterministicRun(t, layout, time.Unix(40, 0), 37, []string{target})
			mustSetFullDecision(t, run, target)
			run.ObserveCoverage("executed", "stage_completed", portCoverage(run.ID, target, "negative", time.Now().UTC()))
			run.mu.Lock()
			_ = run.findingsFile.Close()
			_ = run.coverageFile.Close()
			_ = run.timingFile.Close()
			summary := runSummary{
				RunID: run.ID, Status: "finalizing", TerminalStatus: "completed", MergeStatus: "pending",
				StartedAt: run.startedAt, FinishedAt: time.Now().UTC(), TargetCount: 1, CoverageCount: 1,
			}
			if err := writeRunSummary(run.SummaryPath, summary); err != nil {
				run.mu.Unlock()
				t.Fatal(err)
			}
			stateLock, locked, err := acquireFileLock(filepath.Join(layout.StateDir, ".merge.lock"), false)
			if err != nil || !locked {
				run.mu.Unlock()
				t.Fatalf("acquire merge lock: %v / %v", locked, err)
			}
			_, difference, _, err := prepareRunDifference(layout, run.Dir, true)
			_ = releaseFileLock(stateLock)
			if err != nil || difference.AssetDisappeared != 1 {
				run.mu.Unlock()
				t.Fatalf("prepare delta: %#v / %v", difference, err)
			}
			before, _ := os.ReadFile(run.DeltaPath)
			if damaged {
				if err := os.WriteFile(run.DeltaPath, []byte("broken\n"), 0o600); err != nil {
					run.mu.Unlock()
					t.Fatal(err)
				}
			}
			run.releaseActiveLock(false)
			run.mu.Unlock()

			warnings, err := recoverRuns(layout, time.Now().UTC().Add(time.Minute))
			if err != nil {
				t.Fatalf("recover: %v", err)
			}
			state := mustReadTable(t, layout.AssetsPath, assetsSchema)
			if damaged {
				if !strings.Contains(strings.Join(warnings, "\n"), "state merge recovery failed") || state[0][7] != "active" {
					t.Fatalf("damaged delta did not fail closed: %v / %#v", warnings, state)
				}
				return
			}
			after, _ := os.ReadFile(run.DeltaPath)
			if !bytes.Equal(before, after) || state[0][7] != "disappeared" {
				t.Fatalf("recovery recomputed delta or missed tombstone: same=%v state=%#v", bytes.Equal(before, after), state)
			}
			recovered, err := readRunSummary(run.SummaryPath)
			if err != nil || recovered.Difference.AssetDisappeared != 1 || recovered.MergeStatus != "merged" {
				t.Fatalf("recovered summary = %#v / %v", recovered, err)
			}
		})
	}
}

func TestConcurrentSameAssetIsNewInOnlyOneRun(t *testing.T) {
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatal(err)
	}
	runs := []*Run{
		mustStartDeterministicRun(t, layout, time.Unix(10, 0), 41, []string{"192.0.2.40"}),
		mustStartDeterministicRun(t, layout, time.Unix(11, 0), 42, []string{"192.0.2.40"}),
	}
	for _, run := range runs {
		run.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: "192.0.2.40", Port: "443"})
	}
	var wait sync.WaitGroup
	errs := make(chan error, len(runs))
	for _, run := range runs {
		wait.Add(1)
		go func(run *Run) { defer wait.Done(); errs <- run.Finish(nil) }(run)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	newCount := 0
	for _, run := range runs {
		summary, err := run.DifferenceSummary()
		if err != nil {
			t.Fatal(err)
		}
		newCount += summary.AssetNew
	}
	if newCount != 1 {
		t.Fatalf("concurrent runs counted new asset %d times", newCount)
	}
}

func baselinePortAsset(t *testing.T) (Layout, string) {
	t.Helper()
	layout, err := EnsureLayout(Home{Root: filepath.Join(t.TempDir(), "argus-data")})
	if err != nil {
		t.Fatal(err)
	}
	target := "192.0.2.34"
	run := mustStartDeterministicRun(t, layout, time.Unix(10, 0), 34, []string{target})
	mustSetFullDecision(t, run, target)
	run.ObserveOutput(engine.OutputMessage{Type: "PortScan", IP: target, Port: "443"})
	run.ObserveCoverage("executed", "stage_completed", portCoverage(run.ID, target, "success", time.Now().UTC()))
	if err := run.Finish(nil); err != nil {
		t.Fatalf("finish baseline: %v", err)
	}
	return layout, target
}

func portCoverage(runID, target, outcome string, observedAt time.Time) CoverageRecord {
	return CoverageRecord{
		WorkKey: "port-work-" + target, NormalizedTarget: target, Stage: "port_scan",
		ScopeHash: "scope", ConfigHash: "config", RuleVersion: "rules", Outcome: outcome,
		ContentHash: "ports", ObservedAt: observedAt, ValidUntil: observedAt.Add(time.Hour), LastRunID: runID,
	}
}

func mustSetFullDecision(t *testing.T, run *Run, target string) {
	t.Helper()
	if err := run.SetTargetDecisions(map[string]TargetDecision{target: {Action: "full", Reason: "full_scan"}}); err != nil {
		t.Fatal(err)
	}
}

func countDeltaKind(records []DeltaRecord, kind DeltaKind) int {
	count := 0
	for _, record := range records {
		if record.Kind == kind {
			count++
		}
	}
	return count
}

func hasDeltaReason(records []DeltaRecord, reason string) bool {
	for _, record := range records {
		if record.Reason == reason {
			return true
		}
	}
	return false
}
