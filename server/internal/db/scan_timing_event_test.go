package db

import (
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/user/dddd-proto/go/scanplan"
	"gorm.io/gorm"
)

func TestRecordScanTimingEventIsOwnedAndIdempotent(t *testing.T) {
	store, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&SubTask{}, &ScanTimingEvent{}); err != nil {
		t.Fatal(err)
	}
	attempt := SubTask{ID: "attempt-1", TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "root-a", BatchID: "batch-a", AgentID: "agent-a", ConfigVersion: 3, RuleVersion: "rules-v3"}
	if err := store.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	event := timingEvent(t, attempt.ID, attempt.AgentID, "event-1")
	stored, replayed, err := RecordScanTimingEvent(store, attempt, event)
	if err != nil || replayed {
		t.Fatalf("first record = (%+v, %v, %v)", stored, replayed, err)
	}
	if stored.TenantID != attempt.TenantID || stored.ProjectID != attempt.ProjectID || stored.ConfigVersion != 3 || stored.RuleVersion != "rules-v3" {
		t.Fatalf("server ownership binding lost: %+v", stored)
	}
	replayedRow, replayed, err := RecordScanTimingEvent(store, attempt, event)
	if err != nil || !replayed || replayedRow.ID != stored.ID {
		t.Fatalf("replay = (%+v, %v, %v)", replayedRow, replayed, err)
	}
	if err := store.Model(&ScanTimingEvent{}).Where("id = ?", stored.ID).Update("outcome", string(scanplan.ObservationFailed)).Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := RecordScanTimingEvent(store, attempt, event); !errors.Is(err, ErrScanTimingEventConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}

	attempt.AgentID = "agent-b"
	if _, _, err := RecordScanTimingEvent(store, attempt, timingEvent(t, attempt.ID, "agent-b", "event-2")); err == nil {
		t.Fatal("expected persisted attempt agent mismatch")
	}
	legacy := SubTask{ID: "attempt-legacy", TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "root-a", BatchID: "batch-a", AgentID: "agent-legacy"}
	if err := store.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	legacyEvent, _, err := RecordScanTimingEvent(store, legacy, timingEvent(t, legacy.ID, legacy.AgentID, "event-3"))
	if err != nil || legacyEvent.ConfigVersion != 1 || legacyEvent.RuleVersion != "_unknown" {
		t.Fatalf("legacy version fallback = %+v, %v", legacyEvent, err)
	}
}

func TestBuildTaskTimingProjectionIsScopedAndBounded(t *testing.T) {
	store, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&ScanTimingEvent{}); err != nil {
		t.Fatal(err)
	}
	root := RootTask{ID: "root-a", TenantID: "tenant-a", ProjectID: "project-a"}
	now := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	rows := []ScanTimingEvent{
		{SchemaVersion: ScanTimingEventSchemaVersion, TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "root-a", BatchID: "batch", AttemptID: "attempt-1", AgentID: "agent", SourceEventID: "a", Kind: "stage", Stage: "http_probe", Outcome: "success", StartedAt: now.Add(time.Second), FinishedAt: now.Add(3 * time.Second), DurationNS: int64(2 * time.Second), ConfigVersion: 1, RuleVersion: "r", CreatedAt: now},
		{SchemaVersion: ScanTimingEventSchemaVersion, TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "root-a", BatchID: "batch", AttemptID: "attempt-1", AgentID: "agent", SourceEventID: "b", Kind: "rule_prepare", Stage: "", Outcome: "success", StartedAt: now, FinishedAt: now.Add(time.Second), DurationNS: int64(time.Second), ConfigVersion: 1, RuleVersion: "r", CreatedAt: now},
		{SchemaVersion: ScanTimingEventSchemaVersion, TenantID: "tenant-a", ProjectID: "other", RootTaskID: "root-a", BatchID: "batch", AttemptID: "attempt-1", AgentID: "agent", SourceEventID: "outside", Kind: "rule_prepare", Stage: "", Outcome: "success", StartedAt: now, FinishedAt: now.Add(time.Second), DurationNS: int64(time.Second), ConfigVersion: 1, RuleVersion: "r", CreatedAt: now},
	}
	if err := store.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	projection, err := BuildTaskTimingProjection(store, root, []SubTask{{ID: "attempt-1", TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "root-a"}, {ID: "old-agent", TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "root-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if projection.Truncated || len(projection.Attempts) != 2 || !projection.Attempts[0].Available || projection.Attempts[1].Available {
		t.Fatalf("projection availability = %+v", projection)
	}
	if got := projection.Attempts[0].Events; len(got) != 2 || got[0].Kind != "rule_prepare" || got[1].DurationMS != 2000 {
		t.Fatalf("projection events = %+v", got)
	}
}

func timingEvent(t *testing.T, attemptID, agentID, _ string) scanplan.TimingEvent {
	t.Helper()
	start := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	event, err := (scanplan.TimingEventBuilder{AttemptID: attemptID, AgentID: agentID, Kind: scanplan.TimingRulePrepare, Outcome: scanplan.ObservationSuccess, StartedAt: start, Duration: time.Second}).Build()
	if err != nil {
		t.Fatal(err)
	}
	return event
}
