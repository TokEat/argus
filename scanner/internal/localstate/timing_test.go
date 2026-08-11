package localstate

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/user/dddd-proto/go/scanplan"
)

func TestReadTimingSummarySeparatesOverlappingKinds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timing.tsv")
	start := time.Date(2026, 8, 10, 3, 0, 0, 0, time.UTC)
	build := func(kind scanplan.TimingKind, stage scanplan.Stage, duration time.Duration) scanplan.TimingEvent {
		event, err := (scanplan.TimingEventBuilder{AttemptID: "run-1", AgentID: "cli-local", Kind: kind, Stage: stage, Outcome: scanplan.ObservationSuccess, StartedAt: start, FinishedAt: start.Add(duration), Duration: duration}).Build()
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	events := []scanplan.TimingEvent{
		build(scanplan.TimingProcessStartup, "", 10*time.Millisecond),
		build(scanplan.TimingRulePrepare, "", 4*time.Millisecond),
		build(scanplan.TimingContextInit, "", 500*time.Microsecond),
		build(scanplan.TimingStage, scanplan.StageHTTPProbe, 3*time.Millisecond),
		build(scanplan.TimingStage, scanplan.StageFingerprint, 2*time.Millisecond),
	}
	rows := make([][]string, 0, len(events))
	for _, event := range events {
		rows = append(rows, []string{event.EventID, event.AttemptID, event.AgentID, string(event.Kind), string(event.Stage), string(event.Outcome), event.StartedAt.Format(time.RFC3339Nano), event.FinishedAt.Format(time.RFC3339Nano), formatInt64(event.DurationNS)})
	}
	if err := writeTableAtomic(path, timingSchema, rows); err != nil {
		t.Fatal(err)
	}
	summary, err := ReadTimingSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Available || summary.EventCount != 5 || summary.Bootstrap != 10*time.Millisecond || summary.RulePrepare != 4*time.Millisecond || summary.ContextInit != 500*time.Microsecond || summary.StageTotal != 5*time.Millisecond || summary.SlowestStage != string(scanplan.StageHTTPProbe) {
		t.Fatalf("unexpected timing summary: %+v", summary)
	}
}

func TestReadTimingSummaryLegacyUnavailableAndCorruptFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.tsv")
	summary, err := ReadTimingSummary(path)
	if err != nil || summary.Available {
		t.Fatalf("legacy timing = %+v, %v", summary, err)
	}
	if err := os.WriteFile(path, []byte("argus-tsv/v1\ttiming\nbad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTimingSummary(path); err == nil {
		t.Fatal("corrupt timing evidence was accepted")
	}
}

func formatInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}
