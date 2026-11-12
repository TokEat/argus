package db

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TokEat/argus/shared/proto/go/scanplan"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const ScanTimingEventSchemaVersion = "argus.timing/v1"

// ScanTimingEvent is append-only, bounded performance evidence. It never
// stores targets, configuration bodies, messages, credentials, or raw logs.
type ScanTimingEvent struct {
	ID            uint      `gorm:"primaryKey;autoIncrement"`
	SchemaVersion string    `gorm:"not null;size:64"`
	TenantID      string    `gorm:"not null;uniqueIndex:idx_scan_timing_events_tenant_source_event,priority:1;index:idx_scan_timing_events_scope_created,priority:1;index:idx_scan_timing_events_attempt_created,priority:1"`
	ProjectID     string    `gorm:"not null;index:idx_scan_timing_events_scope_created,priority:2;index:idx_scan_timing_events_attempt_created,priority:2"`
	RootTaskID    string    `gorm:"not null;index:idx_scan_timing_events_scope_created,priority:3;index:idx_scan_timing_events_attempt_created,priority:3"`
	BatchID       string    `gorm:"not null"`
	AttemptID     string    `gorm:"not null;index:idx_scan_timing_events_attempt_created,priority:4"`
	AgentID       string    `gorm:"not null"`
	SourceEventID string    `gorm:"not null;size:64;uniqueIndex:idx_scan_timing_events_tenant_source_event,priority:2"`
	Kind          string    `gorm:"not null;size:32"`
	Stage         string    `gorm:"not null;size:64"`
	Outcome       string    `gorm:"not null;size:32"`
	StartedAt     time.Time `gorm:"not null"`
	FinishedAt    time.Time `gorm:"not null"`
	DurationNS    int64     `gorm:"not null"`
	ConfigVersion int       `gorm:"not null"`
	RuleVersion   string    `gorm:"not null;type:text"`
	CreatedAt     time.Time `gorm:"not null;index:idx_scan_timing_events_scope_created,priority:4;index:idx_scan_timing_events_attempt_created,priority:5"`
}

func (ScanTimingEvent) TableName() string { return "scan_timing_events" }

var ErrScanTimingEventConflict = errors.New("scan timing event conflict")

// RecordScanTimingEvent binds Agent-provided timing to the persisted attempt
// before insertion. Replaying the same evidence returns the existing row;
// reuse of an event ID with different evidence is rejected.
func RecordScanTimingEvent(store *gorm.DB, attempt SubTask, event scanplan.TimingEvent) (ScanTimingEvent, bool, error) {
	if store == nil {
		return ScanTimingEvent{}, false, errors.New("scan timing event store is unavailable")
	}
	if err := event.Validate(); err != nil {
		return ScanTimingEvent{}, false, fmt.Errorf("validate scan timing event: %w", err)
	}
	if strings.TrimSpace(attempt.ID) == "" || event.AttemptID != attempt.ID || event.AgentID != attempt.AgentID {
		return ScanTimingEvent{}, false, errors.New("timing event source does not match the assigned attempt")
	}

	var result ScanTimingEvent
	replayed := false
	err := store.Transaction(func(tx *gorm.DB) error {
		var owned SubTask
		if err := tx.Where("id = ? AND tenant_id = ?", attempt.ID, attempt.TenantID).First(&owned).Error; err != nil {
			return fmt.Errorf("load timing attempt ownership: %w", err)
		}
		if owned.ProjectID == "" || owned.RootTaskID == "" || owned.BatchID == "" || owned.AgentID == "" || event.AttemptID != owned.ID || event.AgentID != owned.AgentID {
			return errors.New("timing event source no longer matches the assigned attempt")
		}
		configVersion := owned.ConfigVersion
		if configVersion < 1 {
			configVersion = 1
		}
		ruleVersion := strings.TrimSpace(owned.RuleVersion)
		if ruleVersion == "" {
			ruleVersion = "_unknown"
		}
		candidate := ScanTimingEvent{
			SchemaVersion: ScanTimingEventSchemaVersion,
			TenantID:      owned.TenantID, ProjectID: owned.ProjectID, RootTaskID: owned.RootTaskID, BatchID: owned.BatchID, AttemptID: owned.ID, AgentID: owned.AgentID,
			SourceEventID: event.EventID, Kind: string(event.Kind), Stage: string(event.Stage), Outcome: string(event.Outcome),
			StartedAt: event.StartedAt.UTC(), FinishedAt: event.FinishedAt.UTC(), DurationNS: event.DurationNS,
			ConfigVersion: configVersion, RuleVersion: ruleVersion, CreatedAt: time.Now().UTC(),
		}
		created := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "source_event_id"}}, DoNothing: true}).Create(&candidate)
		if created.Error != nil {
			return fmt.Errorf("record timing event: %w", created.Error)
		}
		if created.RowsAffected == 1 {
			result = candidate
			return nil
		}
		var existing ScanTimingEvent
		if err := tx.Where("tenant_id = ? AND source_event_id = ?", owned.TenantID, event.EventID).First(&existing).Error; err != nil {
			return fmt.Errorf("load idempotent timing event: %w", err)
		}
		if !sameScanTimingEvent(existing, candidate) {
			return ErrScanTimingEventConflict
		}
		result, replayed = existing, true
		return nil
	})
	return result, replayed, err
}

func sameScanTimingEvent(a, b ScanTimingEvent) bool {
	return a.SchemaVersion == b.SchemaVersion && a.TenantID == b.TenantID && a.ProjectID == b.ProjectID && a.RootTaskID == b.RootTaskID && a.BatchID == b.BatchID && a.AttemptID == b.AttemptID && a.AgentID == b.AgentID && a.SourceEventID == b.SourceEventID && a.Kind == b.Kind && a.Stage == b.Stage && a.Outcome == b.Outcome && a.StartedAt.Equal(b.StartedAt) && a.FinishedAt.Equal(b.FinishedAt) && a.DurationNS == b.DurationNS && a.ConfigVersion == b.ConfigVersion && a.RuleVersion == b.RuleVersion
}

type TaskTimingProjection struct {
	Attempts  []AttemptTimingProjection `json:"attempts"`
	Truncated bool                      `json:"truncated"`
}

type AttemptTimingProjection struct {
	AttemptID         string                  `json:"attempt_id"`
	Available         bool                    `json:"available"`
	UnavailableReason string                  `json:"unavailable_reason,omitempty"`
	Events            []TimingProjectionEvent `json:"events"`
}

type TimingProjectionEvent struct {
	Kind       string    `json:"kind"`
	Stage      string    `json:"stage,omitempty"`
	Outcome    string    `json:"outcome"`
	DurationNS int64     `json:"duration_ns"`
	DurationMS int64     `json:"duration_ms"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// BuildTaskTimingProjection reads only the requested task scope and returns a
// bounded, stable ordering suitable for authorized task detail views.
func BuildTaskTimingProjection(store *gorm.DB, root RootTask, attempts []SubTask) (TaskTimingProjection, error) {
	result := TaskTimingProjection{Attempts: make([]AttemptTimingProjection, 0, len(attempts))}
	if store == nil {
		return result, errors.New("scan timing projection store is unavailable")
	}
	if strings.TrimSpace(root.TenantID) == "" || strings.TrimSpace(root.ProjectID) == "" || strings.TrimSpace(root.ID) == "" {
		return result, errors.New("timing projection root scope is required")
	}
	byAttempt := make(map[string]int, len(attempts))
	sources := make([]SubTask, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.ID == "" || attempt.TenantID != root.TenantID || attempt.ProjectID != root.ProjectID || attempt.RootTaskID != root.ID {
			continue
		}
		if _, exists := byAttempt[attempt.ID]; exists {
			continue
		}
		byAttempt[attempt.ID] = len(result.Attempts)
		result.Attempts = append(result.Attempts, AttemptTimingProjection{AttemptID: attempt.ID})
		sources = append(sources, attempt)
	}
	if len(byAttempt) == 0 {
		return result, nil
	}
	var events []ScanTimingEvent
	const limit = 5000
	if err := store.Where("tenant_id = ? AND project_id = ? AND root_task_id = ?", root.TenantID, root.ProjectID, root.ID).
		Order("attempt_id ASC").Order("started_at ASC").Order("kind ASC").Order("stage ASC").Order("id ASC").Limit(limit + 1).Find(&events).Error; err != nil {
		return result, fmt.Errorf("load task timing projection: %w", err)
	}
	if len(events) > limit {
		events, result.Truncated = events[:limit], true
	}
	for _, event := range events {
		attemptIndex, exists := byAttempt[event.AttemptID]
		if !exists {
			continue
		}
		attempt := &result.Attempts[attemptIndex]
		attempt.Available = true
		attempt.Events = append(attempt.Events, TimingProjectionEvent{Kind: event.Kind, Stage: event.Stage, Outcome: event.Outcome, DurationNS: event.DurationNS, DurationMS: event.DurationNS / int64(time.Millisecond), StartedAt: event.StartedAt, FinishedAt: event.FinishedAt})
	}
	for i := range result.Attempts {
		if !result.Attempts[i].Available {
			result.Attempts[i].UnavailableReason = timingUnavailableReason(sources[i])
		}
		sort.SliceStable(result.Attempts[i].Events, func(a, b int) bool {
			x, y := result.Attempts[i].Events[a], result.Attempts[i].Events[b]
			if x.StartedAt != y.StartedAt {
				return x.StartedAt.Before(y.StartedAt)
			}
			if x.Kind != y.Kind {
				return x.Kind < y.Kind
			}
			return x.Stage < y.Stage
		})
	}
	return result, nil
}

const (
	TimingUnavailableNotExecuted = "not_executed"
	TimingUnavailableNotReported = "not_reported"
	TimingUnavailablePending     = "pending"
)

func timingUnavailableReason(attempt SubTask) string {
	if !IsTerminalAttemptStatus(attempt.Status) {
		return TimingUnavailablePending
	}
	if strings.TrimSpace(attempt.AgentID) == "" && attempt.StartedAt == nil {
		return TimingUnavailableNotExecuted
	}
	return TimingUnavailableNotReported
}
