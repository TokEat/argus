package agent

import (
	"strings"
	"sync"
	"time"

	"github.com/TokEat/argus/scanner/internal/engine"
	"github.com/TokEat/argus/scanner/internal/timing"

	"github.com/TokEat/argus/shared/proto/go/scanplan"
)

// stageTimingTracker keeps the monotonic component from time.Now for actual
// stage duration. Coverage timestamps are UTC evidence and must not be reused
// as the authoritative elapsed-time clock.
type stageTimingTracker struct {
	mu      sync.Mutex
	now     func() time.Time
	started map[scanplan.Stage]time.Time
}

func newStageTimingTracker(now func() time.Time) *stageTimingTracker {
	if now == nil {
		now = time.Now
	}
	return &stageTimingTracker{now: now, started: make(map[scanplan.Stage]time.Time)}
}

func (tracker *stageTimingTracker) observePhase(phase engine.PhaseEvent) {
	if tracker == nil || !strings.EqualFold(strings.TrimSpace(phase.Status), "start") {
		return
	}
	stage, ok := engine.CanonicalStageForPhase(phase.Phase)
	if !ok {
		return
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if _, exists := tracker.started[stage]; !exists {
		tracker.started[stage] = tracker.now()
	}
}

// eventForObservation derives target-free timing evidence only for a stage
// that was actually observed starting. The duration uses the producer's
// monotonic clock while UTC timestamps remain transport metadata.
func (tracker *stageTimingTracker) eventForObservation(observation *scanplan.StageObservationEvent) (*scanplan.TimingEvent, error) {
	if tracker == nil || observation == nil {
		return nil, nil
	}
	tracker.mu.Lock()
	startedAt, started := tracker.started[observation.Stage]
	if started {
		delete(tracker.started, observation.Stage)
	}
	tracker.mu.Unlock()
	if !started {
		return nil, nil
	}
	finishedAt := tracker.now()
	event, err := (scanplan.TimingEventBuilder{
		AttemptID: observation.AttemptID,
		AgentID:   observation.AgentID,
		Kind:      scanplan.TimingStage,
		Stage:     observation.Stage,
		Outcome:   observation.Outcome,
		StartedAt: startedAt.UTC(),
		Duration:  finishedAt.Sub(startedAt),
	}).Build()
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// finishTimingSpan preserves the producer's measured interval. A zero value is
// valid evidence at the local clock's resolution and remains distinguishable
// from an unavailable event.
func finishTimingSpan(span *timing.Span, outcome scanplan.ObservationOutcome) error {
	if span == nil {
		return nil
	}
	return span.Finish(outcome)
}
