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

func openTaskRetryIdempotencyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), time.Now().UnixNano())), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&TaskRetryIdempotency{}); err != nil {
		t.Fatalf("migrate model: %v", err)
	}
	sqlDB, _ := store.DB()
	t.Cleanup(func() { _ = sqlDB.Close() })
	return store
}

func taskRetryIdempotencyDraft() TaskRetryIdempotencyDraft {
	return TaskRetryIdempotencyDraft{
		TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "task-a", OperatorID: "operator-a", Operation: "retry_task_v1",
		IdempotencyKey: "key-a", RequestHash: strings.Repeat("a", 64), BeforeStatus: "PartialDone", AfterStatus: "Running",
		AttemptIDs: []string{"task-a-batch-1-attempt-2"}, CompletedSkipped: 2, PausedSkipped: 1,
	}
}

func TestRecordAndLookupTaskRetryIdempotencyReplayAndConflict(t *testing.T) {
	store := openTaskRetryIdempotencyTestDB(t)
	draft := taskRetryIdempotencyDraft()
	first, err := RecordTaskRetryIdempotency(store, draft)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if first.Replayed || first.Record.ID == 0 || first.Record.IdempotencyKeyHash == draft.IdempotencyKey || !validTaskRetryIdempotencyHash(first.Record.IdempotencyKeyHash) {
		t.Fatalf("unexpected first record: %#v", first)
	}
	replayDraft := draft
	replayDraft.AttemptIDs = []string{"regenerated-attempt"}
	replayDraft.CompletedSkipped = 0
	replayed, err := RecordTaskRetryIdempotency(store, replayDraft)
	if err != nil || !replayed.Replayed || replayed.Record.ID != first.Record.ID {
		t.Fatalf("unexpected replay: result=%#v err=%v", replayed, err)
	}
	if replayed.Record.AttemptIDs != first.Record.AttemptIDs || replayed.Record.CompletedSkipped != first.Record.CompletedSkipped {
		t.Fatalf("replay did not return immutable original record: %#v", replayed.Record)
	}
	_, err = LookupTaskRetryIdempotencyTx(store, draft.TenantID, draft.ProjectID, draft.RootTaskID, draft.OperatorID, draft.Operation, draft.IdempotencyKey, strings.Repeat("c", 64))
	if !errors.Is(err, ErrTaskRetryIdempotencyConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	missing, err := LookupTaskRetryIdempotencyTx(store, draft.TenantID, draft.ProjectID, "task-other", draft.OperatorID, draft.Operation, draft.IdempotencyKey, draft.RequestHash)
	if err != nil || missing.Replayed {
		t.Fatalf("task scope should isolate lookup: %#v, %v", missing, err)
	}
}

func TestTaskRetryIdempotencyScopesRollbackAndValidation(t *testing.T) {
	store := openTaskRetryIdempotencyTestDB(t)
	draft := taskRetryIdempotencyDraft()
	if _, err := RecordTaskRetryIdempotency(store, draft); err != nil {
		t.Fatal(err)
	}
	draft.OperatorID = "operator-b"
	if _, err := RecordTaskRetryIdempotency(store, draft); err != nil {
		t.Fatalf("operator isolation: %v", err)
	}
	draft.OperatorID, draft.RootTaskID = "operator-a", "task-b"
	if _, err := RecordTaskRetryIdempotency(store, draft); err != nil {
		t.Fatalf("task isolation: %v", err)
	}
	draft = taskRetryIdempotencyDraft()
	draft.IdempotencyKey = "bad key"
	if err := validateTaskRetryIdempotencyDraft(draft); err == nil {
		t.Fatal("expected invalid key rejection")
	}
	draft = taskRetryIdempotencyDraft()
	draft.AttemptIDs = []string{"same", "same"}
	if err := validateTaskRetryIdempotencyDraft(draft); err == nil {
		t.Fatal("expected duplicate attempt rejection")
	}
	draft = taskRetryIdempotencyDraft()
	draft.AttemptIDs = nil
	if err := validateTaskRetryIdempotencyDraft(draft); err == nil {
		t.Fatal("expected empty attempt rejection")
	}

	rollbackStore := openTaskRetryIdempotencyTestDB(t)
	if err := rollbackStore.Callback().Create().Before("gorm:create").Register("test:reject_task_retry_idempotency", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "TaskRetryIdempotency" {
			tx.AddError(errors.New("forced write failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordTaskRetryIdempotency(rollbackStore, taskRetryIdempotencyDraft()); err == nil {
		t.Fatal("expected write failure")
	}
	var count int64
	rollbackStore.Model(&TaskRetryIdempotency{}).Count(&count)
	if count != 0 {
		t.Fatalf("failed transaction persisted %d records", count)
	}
}

func TestTaskRetryIdempotencyModelIsSafeAndIndexed(t *testing.T) {
	model := reflect.TypeOf(TaskRetryIdempotency{})
	for i := 0; i < model.NumField(); i++ {
		name := strings.ToLower(model.Field(i).Name)
		for _, forbidden := range []string{"credential", "apikey", "token", "secret", "provider", "rawresponse", "responsebody", "targetlist", "configbody"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("model contains forbidden field %s", model.Field(i).Name)
			}
		}
	}
	store := openTaskRetryIdempotencyTestDB(t)
	for _, index := range []string{"idx_tri_scope_id", "idx_tri_idempotency", "idx_tri_task_created", "idx_tri_operator_created"} {
		if !store.Migrator().HasIndex(&TaskRetryIdempotency{}, index) {
			t.Fatalf("runtime model missing migration index %s", index)
		}
	}
}
