package scanplan

import (
	"strings"
	"testing"
	"time"
)

func TestTimingEventBuilderAndStableID(t *testing.T) {
	start := time.Date(2026, 8, 10, 1, 2, 3, 4, time.FixedZone("local", 3600))
	builder := TimingEventBuilder{AttemptID: "attempt-1", AgentID: "agent-1", Kind: TimingStage, Stage: StageHTTPProbe, Outcome: ObservationNegative, StartedAt: start, Duration: 17 * time.Millisecond}
	one, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	two, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	if one.EventID != two.EventID || !one.FinishedAt.Equal(one.StartedAt.Add(17*time.Millisecond)) || one.StartedAt.Location() != time.UTC {
		t.Fatalf("unexpected stable transport event: %#v", one)
	}
	if err := one.Validate(); err != nil {
		t.Fatal(err)
	}
	one.EventID = strings.ToUpper(one.EventID)
	if err := one.Validate(); err == nil {
		t.Fatal("uppercase ID accepted")
	}
}

func TestTimingEventBuilderPreservesZeroDuration(t *testing.T) {
	start := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	event, err := (TimingEventBuilder{
		AttemptID: "attempt-zero", AgentID: "agent-zero", Kind: TimingStage,
		Stage: StageHTTPProbe, Outcome: ObservationSuccess, StartedAt: start,
	}).Build()
	if err != nil {
		t.Fatalf("build zero-duration timing event: %v", err)
	}
	if event.DurationNS != 0 || !event.FinishedAt.Equal(start) {
		t.Fatalf("zero-duration timing event = %+v", event)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("validate zero-duration timing event: %v", err)
	}
}

func TestTimingEventRejectsForbiddenCombinations(t *testing.T) {
	start := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	base := TimingEvent{SchemaVersion: TimingSchemaVersion, AttemptID: "attempt", AgentID: "agent", Kind: TimingProcessStartup, Outcome: ObservationSuccess, StartedAt: start, FinishedAt: start.Add(time.Second), DurationNS: int64(time.Second)}
	for name, mutate := range map[string]func(*TimingEvent){
		"non-stage stage":    func(e *TimingEvent) { e.Stage = StageHTTPProbe },
		"non-stage negative": func(e *TimingEvent) { e.Outcome = ObservationNegative },
		"negative interval":  func(e *TimingEvent) { e.FinishedAt = e.StartedAt.Add(-time.Nanosecond); e.DurationNS = -1 },
		"inexact duration":   func(e *TimingEvent) { e.DurationNS++ },
		"non-UTC timestamp":  func(e *TimingEvent) { e.StartedAt = e.StartedAt.In(time.FixedZone("local", 3600)) },
		"overlong identity":  func(e *TimingEvent) { e.AttemptID = strings.Repeat("a", TimingIdentityMaxLength+1) },
	} {
		t.Run(name, func(t *testing.T) {
			event := base
			mutate(&event)
			if _, err := TimingEventID(event); err == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
}
