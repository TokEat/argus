package main

import (
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/localstate"
)

func TestFormatRunDifferenceSummaryKeepsJSONOutputClean(t *testing.T) {
	summary := localstate.DifferenceSummary{AssetNew: 1, StageExecuted: 2}
	if line, ok := formatRunDifferenceSummary("json", "run-1", summary); ok || line != "" {
		t.Fatalf("json output received human summary %q", line)
	}
}

func TestFormatTimingSummarySeparatesBootstrapAndStageSum(t *testing.T) {
	summary := localstate.TimingSummary{Available: true, Bootstrap: 10 * time.Millisecond, RulePrepare: 4 * time.Millisecond, ContextInit: 500 * time.Microsecond, StageTotal: 5 * time.Millisecond, SlowestStage: "http_probe", SlowestStageDuration: 3 * time.Millisecond}
	line, ok := formatTimingSummary("text", summary)
	if !ok {
		t.Fatal("text timing summary was suppressed")
	}
	for _, want := range []string{"bootstrap=10ms", "rule=4ms", "context=<1ms", "stage_sum=5ms", "slowest_stage=http_probe (3ms)"} {
		if !strings.Contains(line, want) {
			t.Fatalf("timing summary %q does not contain %q", line, want)
		}
	}
	if strings.Contains(line, "total=") {
		t.Fatalf("overlapping timing segments were presented as a wall-clock total: %q", line)
	}
	if line, ok := formatTimingSummary("json", summary); ok || line != "" {
		t.Fatalf("JSON output received timing text %q", line)
	}
}

func TestFormatRunDifferenceSummaryIsConciseAndComplete(t *testing.T) {
	summary := localstate.DifferenceSummary{
		AssetNew: 1, ServiceChanged: 2, AssetDisappeared: 3, AssetNotAssessed: 4,
		StageExecuted: 5, StageReused: 6, FullTargets: 7, IncrementalTargets: 8,
	}
	line, ok := formatRunDifferenceSummary("text", "run-1", summary)
	if !ok {
		t.Fatal("text summary was suppressed")
	}
	for _, want := range []string{
		"Argus Run run-1", "new=1", "changed=2", "disappeared=3", "not_assessed=4",
		"executed=5", "reused=6", "full=7", "incremental=8",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("summary %q does not contain %q", line, want)
		}
	}
}
