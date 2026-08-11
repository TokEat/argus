package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"google.golang.org/grpc/metadata"
)

func TestWorkerStreamsTargetFreeTimingForPreparationContextAndTerminalStage(t *testing.T) {
	prepareUsableAgentConfig(t)
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	t.Cleanup(func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	})
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		time.Sleep(time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{Config: cfg, Ctx: ctx, Cancel: cancel}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})
		time.Sleep(time.Millisecond)
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "failed", Message: "must not leave the Agent"})
		return nil
	}

	stream := &fakeResultStream{}
	client := &fakeAgentClient{stream: stream}
	worker := NewWorker("agent-timing", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.ruleVersion = "rules-v1"
	worker.sessionToken = "timing-session-token"
	worker.executeTask(&pb.Task{TaskId: "attempt-timing", Targets: []string{"https://sensitive.example"}, Config: []byte(`{"secret":"not-in-timing"}`)})

	seen := make(map[scanplan.TimingKind]scanplan.TimingEvent)
	for _, result := range stream.results() {
		if result.PayloadType != scanplan.TimingEventPayloadType {
			continue
		}
		if bytes.Contains(result.Payload, []byte("sensitive.example")) || bytes.Contains(result.Payload, []byte("secret")) || bytes.Contains(result.Payload, []byte("must not leave")) {
			t.Fatalf("timing payload leaked task data: %s", result.Payload)
		}
		var event scanplan.TimingEvent
		if err := json.Unmarshal(result.Payload, &event); err != nil {
			t.Fatalf("decode timing event: %v", err)
		}
		if err := event.Validate(); err != nil {
			t.Fatalf("invalid timing event: %v", err)
		}
		seen[event.Kind] = event
	}
	if seen[scanplan.TimingRulePrepare].Outcome != scanplan.ObservationSuccess || seen[scanplan.TimingContextInit].Outcome != scanplan.ObservationSuccess {
		t.Fatalf("preparation timing outcomes = %+v", seen)
	}
	if tokens, _ := metadata.FromOutgoingContext(client.streamResultCtx); len(tokens.Get("x-agent-token")) != 1 || tokens.Get("x-agent-token")[0] != "timing-session-token" {
		t.Fatalf("timing stream token = %v", tokens.Get("x-agent-token"))
	}
	stage, ok := seen[scanplan.TimingStage]
	if !ok || stage.Stage != scanplan.StageHTTPProbe || stage.Outcome != scanplan.ObservationFailed {
		t.Fatalf("terminal stage timing = %+v", stage)
	}
}

func TestStageTimingTrackerSkipsUnstartedAndUsesProducerDuration(t *testing.T) {
	now := time.Now().UTC()
	times := []time.Time{now, now.Add(2 * time.Millisecond)}
	tracker := newStageTimingTracker(func() time.Time {
		value := times[0]
		times = times[1:]
		return value
	})
	event, err := tracker.eventForObservation(&scanplan.StageObservationEvent{
		AttemptID: "attempt-timing", AgentID: "agent-timing", Stage: scanplan.StageHTTPProbe,
		Outcome: scanplan.ObservationSkipped, StartedAt: now, FinishedAt: now,
	})
	if err != nil || event != nil {
		t.Fatalf("unstarted skipped stage timing = %#v, %v", event, err)
	}
	tracker.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})
	measured, err := tracker.eventForObservation(&scanplan.StageObservationEvent{
		AttemptID: "attempt-timing", AgentID: "agent-timing", Stage: scanplan.StageHTTPProbe,
		Outcome: scanplan.ObservationSuccess, StartedAt: now, FinishedAt: now,
	})
	if err != nil || measured == nil || measured.DurationNS != int64(2*time.Millisecond) {
		t.Fatalf("producer stage duration was not preserved: %#v, %v", measured, err)
	}
}

func TestStageTimingTrackerPreservesZeroDuration(t *testing.T) {
	now := time.Now().UTC()
	tracker := newStageTimingTracker(func() time.Time { return now })
	tracker.observePhase(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})

	event, err := tracker.eventForObservation(&scanplan.StageObservationEvent{
		AttemptID: "attempt-zero", AgentID: "agent-zero", Stage: scanplan.StageHTTPProbe,
		Outcome: scanplan.ObservationSuccess, StartedAt: now, FinishedAt: now,
	})
	if err != nil {
		t.Fatalf("build zero-duration stage timing: %v", err)
	}
	if event == nil || event.DurationNS != 0 || !event.FinishedAt.Equal(event.StartedAt) {
		t.Fatalf("zero-duration stage timing = %#v", event)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("validate zero-duration stage timing: %v", err)
	}
}
