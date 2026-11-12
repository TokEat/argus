package localstate

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/TokEat/argus/shared/proto/go/scanplan"
)

type TimingSummary struct {
	Available            bool
	EventCount           int
	Bootstrap            time.Duration
	RulePrepare          time.Duration
	ContextInit          time.Duration
	StageTotal           time.Duration
	SlowestStage         string
	SlowestStageDuration time.Duration
}

func (run *Run) TimingSummary() (TimingSummary, error) {
	run.mu.Lock()
	defer run.mu.Unlock()
	if !run.persistTables {
		return summarizeTimingEvents(run.timingEvents)
	}
	return ReadTimingSummary(run.TimingPath)
}

func ReadTimingSummary(path string) (TimingSummary, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return TimingSummary{Available: false}, nil
	} else if err != nil {
		return TimingSummary{}, err
	}
	rows, _, err := readTable(path, timingSchema)
	if err != nil {
		return TimingSummary{}, err
	}
	events := make([]scanplan.TimingEvent, 0, len(rows))
	for _, row := range rows {
		if len(row) != len(timingSchema.Columns) {
			return TimingSummary{}, fmt.Errorf("timing row has invalid column count")
		}
		started, err := time.Parse(time.RFC3339Nano, row[6])
		if err != nil {
			return TimingSummary{}, err
		}
		finished, err := time.Parse(time.RFC3339Nano, row[7])
		if err != nil {
			return TimingSummary{}, err
		}
		duration, err := strconv.ParseInt(row[8], 10, 64)
		if err != nil {
			return TimingSummary{}, err
		}
		event := scanplan.TimingEvent{SchemaVersion: scanplan.TimingSchemaVersion, EventID: row[0], AttemptID: row[1], AgentID: row[2], Kind: scanplan.TimingKind(row[3]), Stage: scanplan.Stage(row[4]), Outcome: scanplan.ObservationOutcome(row[5]), StartedAt: started, FinishedAt: finished, DurationNS: duration}
		if err := event.Validate(); err != nil {
			return TimingSummary{}, fmt.Errorf("invalid timing evidence: %w", err)
		}
		events = append(events, event)
	}
	return summarizeTimingEvents(events)
}

func summarizeTimingEvents(events []scanplan.TimingEvent) (TimingSummary, error) {
	result := TimingSummary{Available: len(events) > 0}
	for _, event := range events {
		if err := event.Validate(); err != nil {
			return TimingSummary{}, fmt.Errorf("invalid timing evidence: %w", err)
		}
		d := time.Duration(event.DurationNS)
		result.EventCount++
		switch event.Kind {
		case scanplan.TimingProcessStartup:
			result.Bootstrap += d
		case scanplan.TimingRulePrepare:
			result.RulePrepare += d
		case scanplan.TimingContextInit:
			result.ContextInit += d
		case scanplan.TimingStage:
			result.StageTotal += d
			if d > result.SlowestStageDuration {
				result.SlowestStage, result.SlowestStageDuration = string(event.Stage), d
			}
		}
	}
	return result, nil
}
