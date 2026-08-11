package timing

import (
	"testing"
	"time"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

type fakeClock struct {
	times []time.Time
	index int
}

func (c *fakeClock) Now() time.Time { value := c.times[c.index]; c.index++; return value }

func TestRecorderDeferredBindStableOrderAndIdempotentFinish(t *testing.T) {
	start := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	r := NewRecorder(&fakeClock{times: []time.Time{start, start.Add(time.Millisecond), start.Add(2 * time.Millisecond), start.Add(5 * time.Millisecond)}})
	first, err := r.Begin(scanplan.TimingRulePrepare, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Begin(scanplan.TimingStage, scanplan.StageHTTPProbe)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Finish(scanplan.ObservationSuccess); err != nil {
		t.Fatal(err)
	}
	if err := first.Finish(scanplan.ObservationFailed); err != nil {
		t.Fatal(err)
	}
	if err := second.Finish(scanplan.ObservationNegative); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Snapshot(); err == nil {
		t.Fatal("unbound recorder exported events")
	}
	if err := r.Bind("attempt-1", "agent-1"); err != nil {
		t.Fatal(err)
	}
	events, err := r.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Kind != scanplan.TimingRulePrepare || events[0].Outcome != scanplan.ObservationSuccess || events[1].Stage != scanplan.StageHTTPProbe {
		t.Fatalf("unexpected events: %#v", events)
	}
	for _, event := range events {
		if err := event.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if events[0].DurationNS != int64(2*time.Millisecond) || events[1].DurationNS != int64(4*time.Millisecond) {
		t.Fatalf("durations were not preserved: %#v", events)
	}
}

func TestRecorderRejectsInvalidKindStageAndOutcome(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	r := NewRecorder(&fakeClock{times: []time.Time{now}})
	if _, err := r.Begin(scanplan.TimingRulePrepare, scanplan.StageHTTPProbe); err == nil {
		t.Fatal("non-stage event accepted stage")
	}
	span, err := r.Begin(scanplan.TimingRulePrepare, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := span.Finish(scanplan.ObservationNegative); err == nil {
		t.Fatal("non-stage negative accepted")
	}
}
