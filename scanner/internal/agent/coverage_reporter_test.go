package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

func TestStageObservationReporterSkipsEmptyTargets(t *testing.T) {
	reporter := newStageObservationReporter("attempt-empty", "agent-a", nil, []byte(`{"ExecutionMode":"risk_validation"}`), "rules-a", "risk_validation")
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseNuclei, Status: "start"})
	if events := reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseNuclei, Status: "end", Message: "native match produced no eligible pocs"}); len(events) != 0 {
		t.Fatalf("empty-target reporter emitted coverage events: %+v", events)
	}
	if events := reporter.finalize(nil, false); len(events) != 0 {
		t.Fatalf("empty-target finalize emitted coverage events: %+v", events)
	}
}

func TestStageObservationReporterProducesOrderIndependentContentHash(t *testing.T) {
	now := time.Date(2026, 8, 9, 1, 2, 3, 0, time.UTC)
	makeEvent := func(payloads []string) *scanplan.StageObservationEvent {
		reporter := newStageObservationReporter("attempt-a", "agent-a", []string{" target-b ", "target-a", "target-a"}, []byte(`{}`), "rules-a", "")
		reporter.now = func() time.Time { return now }
		reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})
		for _, payload := range payloads {
			reporter.recordOutput("Web", []byte(payload))
		}
		events := reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "end"})
		if len(events) != 1 {
			t.Fatalf("terminal events=%d, want 1", len(events))
		}
		return events[0]
	}
	first := makeEvent([]string{"one", "two"})
	second := makeEvent([]string{"two", "one"})
	if first.ContentHash != second.ContentHash {
		t.Fatalf("content hash depends on concurrent output order: %s != %s", first.ContentHash, second.ContentHash)
	}
	if first.Outcome != scanplan.ObservationSuccess || len(first.Targets) != 2 || first.Targets[0] != "target-a" {
		t.Fatalf("unexpected success event: %+v", first)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("success event invalid: %v", err)
	}
}

func TestStageObservationReporterRecordsHTTPBudgetFailure(t *testing.T) {
	reporter := newStageObservationReporter("attempt-a", "agent-a", []string{"target-fast", "target-timeout"}, nil, "rules-a", "")
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})
	events := reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "failed", Message: "target HTTP budget exhausted"})
	if len(events) != 1 {
		t.Fatalf("terminal events=%d, want 1", len(events))
	}
	event := events[0]
	if event.Outcome != scanplan.ObservationFailed || event.Stage != scanplan.StageHTTPProbe || event.Checkpoint != nil {
		t.Fatalf("unexpected HTTP failure event: %+v", event)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("HTTP failure event invalid: %v", err)
	}
}

func TestStageObservationReporterDoesNotMarkUnobservedHTTPTargetsNegativeOnEnd(t *testing.T) {
	reporter := newStageObservationReporter("attempt-a", "agent-a", []string{"https://fast.example", "https://timeout.example"}, nil, "rules-a", "")
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})
	payload, _ := json.Marshal(engine.OutputMessage{Type: "Web", URI: "https://fast.example:443/"})
	reporter.recordOutput("Web", payload)
	events := reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "end"})
	if len(events) != 2 {
		t.Fatalf("terminal events=%d, want success+failed", len(events))
	}
	byOutcome := map[scanplan.ObservationOutcome]*scanplan.StageObservationEvent{}
	for _, event := range events {
		if err := event.Validate(); err != nil {
			t.Fatalf("HTTP split event invalid: %v", err)
		}
		byOutcome[event.Outcome] = event
	}
	success := byOutcome[scanplan.ObservationSuccess]
	failed := byOutcome[scanplan.ObservationFailed]
	if success == nil || len(success.Targets) != 1 || success.Targets[0] != "https://fast.example" {
		t.Fatalf("unexpected HTTP success split: %+v", success)
	}
	if failed == nil || len(failed.Targets) != 1 || failed.Targets[0] != "https://timeout.example" || failed.ErrorCode != "phase_incomplete" {
		t.Fatalf("unobserved HTTP targets must not be reusable negative coverage: %+v", failed)
	}
	if byOutcome[scanplan.ObservationNegative] != nil {
		t.Fatalf("unobserved HTTP remainder was negative: %+v", byOutcome[scanplan.ObservationNegative])
	}
}

func TestStageObservationReporterKeepsSuccessfulHTTPTargetsWhenBudgetExpires(t *testing.T) {
	reporter := newStageObservationReporter("attempt-a", "agent-a", []string{"https://fast.example", "https://timeout.example"}, nil, "rules-a", "")
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})
	payload, _ := json.Marshal(engine.OutputMessage{Type: "Web", URI: "https://fast.example:443/"})
	reporter.recordOutput("Web", payload)
	events := reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "failed", Message: "target HTTP budget exhausted"})
	if len(events) != 2 {
		t.Fatalf("terminal events=%d, want success+failed", len(events))
	}
	byOutcome := map[scanplan.ObservationOutcome]*scanplan.StageObservationEvent{}
	for _, event := range events {
		if err := event.Validate(); err != nil {
			t.Fatalf("HTTP split event invalid: %v", err)
		}
		byOutcome[event.Outcome] = event
	}
	success := byOutcome[scanplan.ObservationSuccess]
	failed := byOutcome[scanplan.ObservationFailed]
	if success == nil || len(success.Targets) != 1 || success.Targets[0] != "https://fast.example" || success.ErrorMessage != "" {
		t.Fatalf("unexpected HTTP success split: %+v", success)
	}
	if failed == nil || len(failed.Targets) != 1 || failed.Targets[0] != "https://timeout.example" || failed.ErrorMessage != "target HTTP budget exhausted" {
		t.Fatalf("unexpected HTTP failure split: %+v", failed)
	}
}

func TestHTTPObservationMatchesDefaultHTTPSPort(t *testing.T) {
	if !httpObservationMatchesTarget("https://zhmrmp.szpcc.com", "https://zhmrmp.szpcc.com:443/") {
		t.Fatal("https default port should match observed :443 URL")
	}
	if httpObservationMatchesTarget("https://timeout.example", "https://fast.example/") {
		t.Fatal("different hosts must not match")
	}
}

func TestStageObservationReporterEmitsBoundedSingleTargetCheckpoint(t *testing.T) {
	reporter := newStageObservationReporter("attempt-checkpoint", "agent-a", []string{"10.0.0.1"}, []byte(`{}`), "rules-a", "")
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "start"})
	for _, message := range []engine.OutputMessage{
		{Type: "PortScan", IP: "10.0.0.1", Port: "443"},
		{Type: "PortScan", IP: "10.0.0.1", Port: "53", Transport: "udp", Protocol: "dns"},
		{Type: "PortScan", IP: "10.0.0.1", Port: "22"},
		{Type: "PortScan", IP: "10.0.0.1", Port: "443"},
	} {
		payload, _ := json.Marshal(message)
		reporter.recordOutput(message.Type, payload)
	}
	events := reporter.observePhase(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "end"})
	if len(events) != 1 || events[0].Checkpoint == nil {
		t.Fatalf("checkpoint event=%+v", events)
	}
	checkpoint := events[0].Checkpoint
	if len(checkpoint.OpenPorts) != 2 || checkpoint.OpenPorts[0] != "10.0.0.1:22" || checkpoint.OpenPorts[1] != "10.0.0.1:443" {
		t.Fatalf("checkpoint was not canonical: %+v", checkpoint)
	}
	if err := events[0].Validate(); err != nil {
		t.Fatalf("checkpoint event invalid: %v", err)
	}

	multi := newStageObservationReporter("attempt-multi", "agent-a", []string{"10.0.0.1", "10.0.0.2"}, []byte(`{}`), "rules-a", "")
	multi.observePhase(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "start"})
	payload, _ := json.Marshal(engine.OutputMessage{Type: "PortScan", IP: "10.0.0.1", Port: "443"})
	multi.recordOutput("PortScan", payload)
	multiEvents := multi.observePhase(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "end"})
	if len(multiEvents) != 1 || multiEvents[0].Checkpoint != nil {
		t.Fatalf("multi-target event should not carry an unattributed checkpoint: %+v", multiEvents)
	}
}

func TestStageObservationEventIDIncludesCheckpoint(t *testing.T) {
	now := time.Now().UTC()
	base := &scanplan.StageObservationEvent{
		SchemaVersion: scanplan.SchemaVersion, AttemptID: "attempt-a", AgentID: "agent-a",
		Stage: scanplan.StagePortScan, Outcome: scanplan.ObservationSuccess, Targets: []string{"10.0.0.1"},
		ConfigHash: "config-a", RuleVersion: "rules-a", StartedAt: now.Add(-time.Second), FinishedAt: now, ContentHash: "content-a",
		Checkpoint: &scanplan.StageCheckpoint{SchemaVersion: scanplan.CheckpointSchemaVersion, Stage: scanplan.StagePortScan, OpenPorts: []string{"10.0.0.1:22"}},
	}
	first := stageObservationEventID(base)
	changed := *base
	changed.Checkpoint = &scanplan.StageCheckpoint{SchemaVersion: scanplan.CheckpointSchemaVersion, Stage: scanplan.StagePortScan, OpenPorts: []string{"10.0.0.1:443"}}
	if second := stageObservationEventID(&changed); second == first {
		t.Fatal("checkpoint change did not change event identity")
	}
}

func TestStageObservationReporterFailsActiveStageAndSkipsUnknownCoverage(t *testing.T) {
	reporter := newStageObservationReporter("attempt-a", "agent-a", []string{"target-a"}, nil, "", "")
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "start"})
	events := reporter.finalize(errors.New("port scanner failed"), false)
	if len(events) != len(assetObservationStages) {
		t.Fatalf("final events=%d, want %d", len(events), len(assetObservationStages))
	}
	var failed, skipped int
	for _, event := range events {
		if err := event.Validate(); err != nil {
			t.Fatalf("invalid final event %+v: %v", event, err)
		}
		if event.Stage == scanplan.StageSearchEngine {
			t.Fatal("retired search_engine coverage was emitted")
		}
		switch event.Outcome {
		case scanplan.ObservationFailed:
			failed++
			if event.Stage != scanplan.StagePortScan {
				t.Fatalf("unexpected failed stage %s", event.Stage)
			}
		case scanplan.ObservationSkipped:
			skipped++
		default:
			t.Fatalf("unexpected final outcome %s", event.Outcome)
		}
	}
	if failed != 1 || skipped != len(assetObservationStages)-1 {
		t.Fatalf("failed=%d skipped=%d", failed, skipped)
	}
}

func TestStageObservationReporterResumeEmitsOnlyExecutionSuffix(t *testing.T) {
	reporter := newStageObservationReporter(
		"attempt-resume", "agent-a", []string{"192.0.2.10"}, []byte(`{"ResumePlan":{}}`), "rules-a", "",
		stageObservationReporterPlan{
			ConfigHash: strings.Repeat("a", 64),
			Stages:     []scanplan.Stage{scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe},
		},
	)
	if events := reporter.observePhase(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "start"}); len(events) != 0 {
		t.Fatalf("reused port phase produced events: %+v", events)
	}
	if events := reporter.observePhase(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "end"}); len(events) != 0 {
		t.Fatalf("reused port phase produced terminal events: %+v", events)
	}
	reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseProtocol, Status: "start"})
	protocolEvents := reporter.observePhase(engine.PhaseEvent{Phase: engine.PhaseProtocol, Status: "end"})
	if len(protocolEvents) != 1 || protocolEvents[0].Stage != scanplan.StageProtocolIdentify || protocolEvents[0].ConfigHash != strings.Repeat("a", 64) {
		t.Fatalf("unexpected resumed protocol event: %+v", protocolEvents)
	}
	final := reporter.finalize(nil, false)
	if len(final) != 1 || final[0].Stage != scanplan.StageHTTPProbe || final[0].Outcome != scanplan.ObservationSkipped {
		t.Fatalf("resume finalization included reused work or missed execution work: %+v", final)
	}
}
