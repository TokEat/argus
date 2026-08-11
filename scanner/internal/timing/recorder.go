// Package timing records bounded scanner timing intervals without coupling the
// recorder to a transport or to scanner targets.
package timing

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type Recorder struct {
	clock     Clock
	mu        sync.Mutex
	attemptID string
	agentID   string
	next      uint64
	spans     []*span
}

type span struct {
	sequence uint64
	kind     scanplan.TimingKind
	stage    scanplan.Stage
	started  time.Time
	finished bool
	outcome  scanplan.ObservationOutcome
	duration time.Duration
}

type Span struct {
	recorder *Recorder
	sequence uint64
}

func NewRecorder(clock Clock) *Recorder {
	if clock == nil {
		clock = systemClock{}
	}
	return &Recorder{clock: clock}
}

func (r *Recorder) Bind(attemptID, agentID string) error {
	// Use the shared builder validation so recorder and transport reject the
	// same unbounded or malformed identities.
	_, err := (scanplan.TimingEventBuilder{AttemptID: attemptID, AgentID: agentID, Kind: scanplan.TimingProcessStartup, Outcome: scanplan.ObservationSuccess, StartedAt: time.Unix(0, 0), Duration: time.Nanosecond}).Build()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attemptID != "" && (r.attemptID != attemptID || r.agentID != agentID) {
		return errors.New("timing recorder is already bound")
	}
	r.attemptID, r.agentID = attemptID, agentID
	return nil
}

func (r *Recorder) Begin(kind scanplan.TimingKind, stage scanplan.Stage) (*Span, error) {
	if !kind.Valid() || (kind == scanplan.TimingStage && !stage.Valid()) || (kind != scanplan.TimingStage && stage != "") {
		return nil, errors.New("invalid timing kind/stage")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	r.spans = append(r.spans, &span{sequence: r.next, kind: kind, stage: stage, started: r.clock.Now()})
	return &Span{recorder: r, sequence: r.next}, nil
}

// Finish is idempotent. A repeated finish never changes the first terminal
// outcome or duration, making concurrent instrumentation safe to retry.
func (s *Span) Finish(outcome scanplan.ObservationOutcome) error {
	if s == nil || s.recorder == nil {
		return errors.New("nil timing span")
	}
	r := s.recorder
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range r.spans {
		if item.sequence != s.sequence {
			continue
		}
		if item.finished {
			return nil
		}
		if !outcome.Valid() || (item.kind != scanplan.TimingStage && outcome == scanplan.ObservationNegative) {
			return errors.New("invalid timing outcome")
		}
		duration := r.clock.Now().Sub(item.started) // uses monotonic components when supplied by time.Now.
		if duration < 0 || duration > 24*time.Hour {
			return errors.New("invalid timing duration")
		}
		item.outcome, item.duration, item.finished = outcome, duration, true
		return nil
	}
	return errors.New("timing span does not belong to recorder")
}

// Snapshot returns completed events in Begin order. Binding may happen after
// recording, but it must happen before events can be exported.
func (r *Recorder) Snapshot() ([]scanplan.TimingEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attemptID == "" || r.agentID == "" {
		return nil, errors.New("timing recorder is not bound")
	}
	spans := append([]*span(nil), r.spans...)
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].sequence < spans[j].sequence })
	events := make([]scanplan.TimingEvent, 0, len(spans))
	for _, item := range spans {
		if !item.finished {
			continue
		}
		event, err := (scanplan.TimingEventBuilder{AttemptID: r.attemptID, AgentID: r.agentID, Kind: item.kind, Stage: item.stage, Outcome: item.outcome, StartedAt: item.started.UTC(), FinishedAt: item.started.UTC().Add(item.duration), Duration: item.duration}).Build()
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}
