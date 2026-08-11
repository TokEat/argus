package scanplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	TimingSchemaVersion     = "argus.timing/v1"
	TimingEventPayloadType  = "attempt_timing_event"
	TimingIdentityMaxLength = 128
	maxTimingDuration       = 24 * time.Hour
)

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TimingKind names the small, fixed set of locally observable intervals. It
// intentionally has no generic kind or message field, so timing evidence
// cannot become an unbounded log transport.
type TimingKind string

const (
	TimingProcessStartup TimingKind = "process_startup"
	TimingRulePrepare    TimingKind = "rule_prepare"
	TimingContextInit    TimingKind = "context_init"
	TimingStage          TimingKind = "stage"
)

func (k TimingKind) Valid() bool {
	switch k {
	case TimingProcessStartup, TimingRulePrepare, TimingContextInit, TimingStage:
		return true
	default:
		return false
	}
}

// TimingEvent is an append-only, target-free timing observation for one
// attempt. FinishedAt is a transport timestamp; DurationNS remains the
// authoritative monotonic interval measured by the producer.
type TimingEvent struct {
	SchemaVersion string             `json:"schema_version"`
	EventID       string             `json:"event_id"`
	AttemptID     string             `json:"attempt_id"`
	AgentID       string             `json:"agent_id"`
	Kind          TimingKind         `json:"kind"`
	Stage         Stage              `json:"stage,omitempty"`
	Outcome       ObservationOutcome `json:"outcome"`
	StartedAt     time.Time          `json:"started_at"`
	FinishedAt    time.Time          `json:"finished_at"`
	DurationNS    int64              `json:"duration_ns"`
}

// TimingEventBuilder supplies only the bounded fields accepted by the timing
// transport. Build normalizes timestamps to UTC and derives the stable ID.
type TimingEventBuilder struct {
	AttemptID  string
	AgentID    string
	Kind       TimingKind
	Stage      Stage
	Outcome    ObservationOutcome
	StartedAt  time.Time
	FinishedAt time.Time
	Duration   time.Duration
}

func (b TimingEventBuilder) Build() (TimingEvent, error) {
	started := b.StartedAt.UTC()
	finished := b.FinishedAt.UTC()
	if b.Duration != 0 || (b.FinishedAt.IsZero() && !b.StartedAt.IsZero()) {
		if started.IsZero() {
			return TimingEvent{}, errors.New("timing event requires started_at")
		}
		finished = started.Add(b.Duration)
	}
	event := TimingEvent{
		SchemaVersion: TimingSchemaVersion, AttemptID: b.AttemptID, AgentID: b.AgentID,
		Kind: b.Kind, Stage: b.Stage, Outcome: b.Outcome, StartedAt: started,
		FinishedAt: finished, DurationNS: int64(finished.Sub(started)),
	}
	if err := event.validateFields(); err != nil {
		return TimingEvent{}, err
	}
	id, err := TimingEventID(event)
	if err != nil {
		return TimingEvent{}, err
	}
	event.EventID = id
	return event, nil
}

func (e TimingEvent) Validate() error {
	if err := e.validateFields(); err != nil {
		return err
	}
	if !lowerHex64.MatchString(e.EventID) {
		return errors.New("timing event_id must be 64 lowercase hexadecimal characters")
	}
	expected, err := TimingEventID(e)
	if err != nil {
		return err
	}
	if e.EventID != expected {
		return errors.New("timing event_id does not match canonical event fields")
	}
	return nil
}

func (e TimingEvent) validateFields() error {
	if e.SchemaVersion != TimingSchemaVersion {
		return fmt.Errorf("unsupported timing schema %q", e.SchemaVersion)
	}
	if err := validateTimingIdentity("attempt_id", e.AttemptID); err != nil {
		return err
	}
	if err := validateTimingIdentity("agent_id", e.AgentID); err != nil {
		return err
	}
	if !e.Kind.Valid() {
		return fmt.Errorf("unsupported timing kind %q", e.Kind)
	}
	if e.Kind == TimingStage {
		if !e.Stage.Valid() {
			return fmt.Errorf("timing stage kind requires a supported stage, got %q", e.Stage)
		}
	} else if e.Stage != "" {
		return errors.New("non-stage timing event must not include stage")
	}
	if !e.Outcome.Valid() {
		return fmt.Errorf("unsupported timing outcome %q", e.Outcome)
	}
	if e.Kind != TimingStage && e.Outcome == ObservationNegative {
		return errors.New("negative timing outcome is only valid for a stage")
	}
	if e.StartedAt.IsZero() || e.FinishedAt.IsZero() || e.FinishedAt.Before(e.StartedAt) {
		return errors.New("timing event requires a valid non-negative interval")
	}
	if e.StartedAt.Location() != time.UTC || e.FinishedAt.Location() != time.UTC {
		return errors.New("timing event timestamps must be UTC")
	}
	duration := e.FinishedAt.Sub(e.StartedAt)
	if duration < 0 || duration > maxTimingDuration || e.DurationNS != int64(duration) {
		return errors.New("timing duration_ns must exactly match an interval within 24h")
	}
	return nil
}

func validateTimingIdentity(name, value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > TimingIdentityMaxLength || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s must be a bounded normalized identifier", name)
	}
	return nil
}

// TimingEventID deterministically derives the event ID from the canonical
// public fields. It accepts an empty EventID because that field is excluded.
func TimingEventID(event TimingEvent) (string, error) {
	if err := event.validateFields(); err != nil {
		return "", err
	}
	canonical := struct {
		SchemaVersion string             `json:"schema_version"`
		AttemptID     string             `json:"attempt_id"`
		AgentID       string             `json:"agent_id"`
		Kind          TimingKind         `json:"kind"`
		Stage         Stage              `json:"stage,omitempty"`
		Outcome       ObservationOutcome `json:"outcome"`
		StartedAt     time.Time          `json:"started_at"`
		FinishedAt    time.Time          `json:"finished_at"`
		DurationNS    int64              `json:"duration_ns"`
	}{event.SchemaVersion, event.AttemptID, event.AgentID, event.Kind, event.Stage, event.Outcome, event.StartedAt.UTC(), event.FinishedAt.UTC(), event.DurationNS}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
