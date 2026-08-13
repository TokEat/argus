package scanplan

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type CoverageStatus string

const (
	CoverageComplete    CoverageStatus = "complete"
	CoverageIncomplete  CoverageStatus = "incomplete"
	CoverageInvalidated CoverageStatus = "invalidated"
)

func (s CoverageStatus) Valid() bool {
	switch s {
	case CoverageComplete, CoverageIncomplete, CoverageInvalidated:
		return true
	default:
		return false
	}
}

type Coverage struct {
	SchemaVersion   string             `json:"schema_version"`
	WorkKey         WorkKey            `json:"work_key"`
	Status          CoverageStatus     `json:"status"`
	Outcome         ObservationOutcome `json:"outcome"`
	StartedAt       time.Time          `json:"started_at"`
	FinishedAt      time.Time          `json:"finished_at"`
	ValidUntil      *time.Time         `json:"valid_until,omitempty"`
	ObservationHash string             `json:"observation_hash,omitempty"`
	SourceTaskID    string             `json:"source_task_id,omitempty"`
	SourceBatchID   string             `json:"source_batch_id,omitempty"`
	SourceAttemptID string             `json:"source_attempt_id,omitempty"`
	InvalidReason   string             `json:"invalid_reason,omitempty"`
}

func (c Coverage) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported coverage schema %q", c.SchemaVersion)
	}
	if err := c.WorkKey.Validate(); err != nil {
		return fmt.Errorf("invalid coverage work key: %w", err)
	}
	if !c.Status.Valid() {
		return fmt.Errorf("unsupported coverage status %q", c.Status)
	}
	if !c.Outcome.Valid() {
		return fmt.Errorf("unsupported coverage outcome %q", c.Outcome)
	}
	if c.StartedAt.IsZero() || c.FinishedAt.IsZero() || c.FinishedAt.Before(c.StartedAt) {
		return errors.New("coverage requires a valid started_at/finished_at interval")
	}
	if c.ValidUntil != nil && c.ValidUntil.Before(c.FinishedAt) {
		return errors.New("coverage valid_until cannot precede finished_at")
	}
	if c.Status == CoverageComplete && c.Outcome != ObservationSuccess && c.Outcome != ObservationNegative {
		return errors.New("complete coverage requires a success or negative observation")
	}
	if c.Status == CoverageIncomplete && c.Outcome != ObservationFailed && c.Outcome != ObservationSkipped {
		return errors.New("incomplete coverage requires a failed or skipped observation")
	}
	if c.Status == CoverageInvalidated && strings.TrimSpace(c.InvalidReason) == "" {
		return errors.New("invalidated coverage requires invalid_reason")
	}
	return nil
}
