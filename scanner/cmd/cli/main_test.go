package main

import (
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/internal/localstate"
)

func TestFormatRunDifferenceSummaryKeepsJSONOutputClean(t *testing.T) {
	summary := localstate.DifferenceSummary{AssetNew: 1, StageExecuted: 2}
	if line, ok := formatRunDifferenceSummary("json", "run-1", summary, localstate.PlanSummary{}); ok || line != "" {
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
	summary := localstate.DifferenceSummary{StageExecuted: 5}
	plan := localstate.PlanSummary{InputsFull: 1, InputsPartial: 2, InputsSkipped: 3, AssetsPlanned: 250, AssetsSkipped: 6}
	line, ok := formatRunDifferenceSummary("text", "run-1", summary, plan)
	if !ok {
		t.Fatal("text summary was suppressed")
	}
	for _, want := range []string{
		"Argus Run run-1", "executed=5", "full=1", "partial=2", "skipped=3",
		"scheduled=250", "history_skipped=6",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("summary %q does not contain %q", line, want)
		}
	}
}
