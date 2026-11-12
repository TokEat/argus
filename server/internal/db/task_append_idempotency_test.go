package db

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func openTaskAppendIdempotencyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), time.Now().UnixNano())), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&TaskAppendIdempotency{}); err != nil {
		t.Fatalf("migrate model: %v", err)
	}
	sqlDB, _ := store.DB()
	t.Cleanup(func() { _ = sqlDB.Close() })
	return store
}

func taskAppendIdempotencyDraft() TaskAppendIdempotencyDraft {
	return TaskAppendIdempotencyDraft{
		TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "task-a", OperatorID: "operator-a", Operation: "append_task_v1",
		IdempotencyKey: "key-a", RequestHash: strings.Repeat("a", 64), Outcome: "appended", ConfigVersion: 2, ConfigHash: strings.Repeat("b", 64), RuleVersion: "rules-2",
		BeforeStatus: "Finished", AfterStatus: "Running", BatchIDs: []string{"task-a-batch-1"}, AttemptIDs: []string{"task-a-batch-1-attempt-1"},
		RequestedTargets: 2, NewTargets: 1, DuplicateTargets: 1, ProjectScopeAdded: 1, ProjectSeedsAdded: 1, TotalChunks: 2, TotalTargets: 3,
	}
}

func TestRecordAndLookupTaskAppendIdempotencyReplayAndConflict(t *testing.T) {
	store := openTaskAppendIdempotencyTestDB(t)
	draft := taskAppendIdempotencyDraft()
	first, err := RecordTaskAppendIdempotency(store, draft)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if first.Replayed || first.Record.ID == 0 || first.Record.IdempotencyKeyHash == draft.IdempotencyKey || !validTaskAppendIdempotencyHash(first.Record.IdempotencyKeyHash) {
		t.Fatalf("unexpected first record: %#v", first)
	}
	replayDraft := draft
	replayDraft.BatchIDs = []string{"regenerated-batch"}
	replayDraft.AttemptIDs = []string{"regenerated-attempt"}
	replayDraft.NewTargets, replayDraft.DuplicateTargets = 2, 0
	replayed, err := RecordTaskAppendIdempotency(store, replayDraft)
	if err != nil || !replayed.Replayed || replayed.Record.ID != first.Record.ID {
		t.Fatalf("unexpected replay: result=%#v err=%v", replayed, err)
	}
	if replayed.Record.BatchIDs != first.Record.BatchIDs || replayed.Record.AttemptIDs != first.Record.AttemptIDs || replayed.Record.NewTargets != first.Record.NewTargets {
		t.Fatalf("replay did not return immutable original record: %#v", replayed.Record)
	}
	_, err = LookupTaskAppendIdempotencyTx(store, draft.TenantID, draft.ProjectID, draft.RootTaskID, draft.OperatorID, draft.Operation, draft.IdempotencyKey, strings.Repeat("c", 64))
	if !errors.Is(err, ErrTaskAppendIdempotencyConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	missing, err := LookupTaskAppendIdempotencyTx(store, draft.TenantID, draft.ProjectID, "task-other", draft.OperatorID, draft.Operation, draft.IdempotencyKey, draft.RequestHash)
	if err != nil || missing.Replayed {
		t.Fatalf("task scope should isolate lookup: %#v, %v", missing, err)
	}
}

func TestTaskAppendIdempotencyScopesRollbackAndValidation(t *testing.T) {
	store := openTaskAppendIdempotencyTestDB(t)
	draft := taskAppendIdempotencyDraft()
	if _, err := RecordTaskAppendIdempotency(store, draft); err != nil {
		t.Fatal(err)
	}
	draft.OperatorID = "operator-b"
	if _, err := RecordTaskAppendIdempotency(store, draft); err != nil {
		t.Fatalf("operator isolation: %v", err)
	}
	draft.OperatorID, draft.RootTaskID = "operator-a", "task-b"
	if _, err := RecordTaskAppendIdempotency(store, draft); err != nil {
		t.Fatalf("task isolation: %v", err)
	}
	draft = taskAppendIdempotencyDraft()
	draft.IdempotencyKey = "bad key"
	if err := validateTaskAppendIdempotencyDraft(draft); err == nil {
		t.Fatal("expected invalid key rejection")
	}
	draft = taskAppendIdempotencyDraft()
	draft.Outcome, draft.NewTargets, draft.DuplicateTargets, draft.BatchIDs, draft.AttemptIDs = "unchanged", 0, 2, nil, nil
	if err := validateTaskAppendIdempotencyDraft(draft); err != nil {
		t.Fatalf("valid unchanged outcome rejected: %v", err)
	}
	draft = taskAppendIdempotencyDraft()
	draft.BatchIDs = []string{"same", "same"}
	if err := validateTaskAppendIdempotencyDraft(draft); err == nil {
		t.Fatal("expected duplicate batch rejection")
	}

	rollbackStore := openTaskAppendIdempotencyTestDB(t)
	if err := rollbackStore.Callback().Create().Before("gorm:create").Register("test:reject_task_append_idempotency", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "TaskAppendIdempotency" {
			tx.AddError(errors.New("forced write failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordTaskAppendIdempotency(rollbackStore, taskAppendIdempotencyDraft()); err == nil {
		t.Fatal("expected write failure")
	}
	var count int64
	rollbackStore.Model(&TaskAppendIdempotency{}).Count(&count)
	if count != 0 {
		t.Fatalf("failed transaction persisted %d records", count)
	}
}

func TestTaskAppendIdempotencyModelIsSafeAndIndexed(t *testing.T) {
	model := reflect.TypeOf(TaskAppendIdempotency{})
	for i := 0; i < model.NumField(); i++ {
		name := strings.ToLower(model.Field(i).Name)
		for _, forbidden := range []string{"credential", "apikey", "token", "secret", "provider", "rawresponse", "responsebody", "targetlist", "configbody"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("model contains forbidden field %s", model.Field(i).Name)
			}
		}
	}
	store := openTaskAppendIdempotencyTestDB(t)
	for _, index := range []string{"idx_tai_scope_id", "idx_tai_idempotency", "idx_tai_task_created", "idx_tai_operator_created"} {
		if !store.Migrator().HasIndex(&TaskAppendIdempotency{}, index) {
			t.Fatalf("runtime model missing migration index %s", index)
		}
	}
}
