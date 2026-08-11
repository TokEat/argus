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

func openTaskCreationIdempotencyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), time.Now().UnixNano())), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&TaskCreationIdempotency{}); err != nil {
		t.Fatalf("migrate model: %v", err)
	}
	sqlDB, _ := store.DB()
	t.Cleanup(func() { _ = sqlDB.Close() })
	return store
}

func taskCreationIdempotencyDraft() TaskCreationIdempotencyDraft {
	return TaskCreationIdempotencyDraft{
		TenantID: "tenant-a", ProjectID: "project-a", OperatorID: "operator-a", Operation: "create_task",
		IdempotencyKey: "key-a", RequestHash: strings.Repeat("a", 64), RootTaskID: "task-a",
		AttemptIDs: []string{"task-a-attempt-1"}, ProjectScopeAdded: 1, ProjectSeedsAdded: 1,
	}
}

func TestRecordTaskCreationIdempotencyReplayAndConflict(t *testing.T) {
	store := openTaskCreationIdempotencyTestDB(t)
	draft := taskCreationIdempotencyDraft()
	first, err := RecordTaskCreationIdempotency(store, draft)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if first.Replayed || first.Record.ID == 0 || first.Record.IdempotencyKeyHash == draft.IdempotencyKey || !validTaskCreationIdempotencyHash(first.Record.IdempotencyKeyHash) {
		t.Fatalf("unexpected first record: %#v", first)
	}
	replayDraft := draft
	replayDraft.RootTaskID = "task-regenerated"
	replayDraft.AttemptIDs = []string{"task-regenerated-attempt-1", "task-regenerated-attempt-2"}
	replayDraft.ProjectScopeAdded = 99
	replayDraft.ProjectSeedsAdded = 88
	replayed, err := RecordTaskCreationIdempotency(store, replayDraft)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replayed.Replayed || replayed.Record.ID != first.Record.ID {
		t.Fatalf("unexpected replay: %#v", replayed)
	}
	if replayed.Record.RootTaskID != draft.RootTaskID || replayed.Record.AttemptIDs != first.Record.AttemptIDs || replayed.Record.ProjectScopeAdded != draft.ProjectScopeAdded || replayed.Record.ProjectSeedsAdded != draft.ProjectSeedsAdded {
		t.Fatalf("replay did not return immutable original record: %#v", replayed.Record)
	}
	replayDraft.RequestHash = strings.Repeat("b", 64)
	if _, err := RecordTaskCreationIdempotency(store, replayDraft); !errors.Is(err, ErrTaskCreationIdempotencyConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestRecordTaskCreationIdempotencyScopesAndRollsBack(t *testing.T) {
	store := openTaskCreationIdempotencyTestDB(t)
	draft := taskCreationIdempotencyDraft()
	if _, err := RecordTaskCreationIdempotency(store, draft); err != nil {
		t.Fatal(err)
	}
	draft.OperatorID = "operator-b"
	if _, err := RecordTaskCreationIdempotency(store, draft); err != nil {
		t.Fatalf("operator isolation: %v", err)
	}
	draft.OperatorID, draft.ProjectID = "operator-a", "project-b"
	if _, err := RecordTaskCreationIdempotency(store, draft); err != nil {
		t.Fatalf("project isolation: %v", err)
	}

	rollbackStore := openTaskCreationIdempotencyTestDB(t)
	if err := rollbackStore.Callback().Create().Before("gorm:create").Register("test:reject_task_creation_idempotency", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "TaskCreationIdempotency" {
			tx.AddError(errors.New("forced write failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordTaskCreationIdempotency(rollbackStore, taskCreationIdempotencyDraft()); err == nil {
		t.Fatal("expected write failure")
	}
	var count int64
	rollbackStore.Model(&TaskCreationIdempotency{}).Count(&count)
	if count != 0 {
		t.Fatalf("failed transaction persisted %d records", count)
	}
}

func TestTaskCreationIdempotencyRejectsInvalidAndSensitiveModelFields(t *testing.T) {
	draft := taskCreationIdempotencyDraft()
	draft.IdempotencyKey = "bad key"
	if err := validateTaskCreationIdempotencyDraft(draft); err == nil {
		t.Fatal("expected invalid key rejection")
	}
	draft = taskCreationIdempotencyDraft()
	draft.AttemptIDs = []string{"same", "same"}
	if err := validateTaskCreationIdempotencyDraft(draft); err == nil {
		t.Fatal("expected duplicate attempt ID rejection")
	}
	model := reflect.TypeOf(TaskCreationIdempotency{})
	for i := 0; i < model.NumField(); i++ {
		name := strings.ToLower(model.Field(i).Name)
		for _, forbidden := range []string{"credential", "apikey", "token", "secret", "provider", "rawresponse", "responsebody", "target", "config"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("model contains forbidden field %s", model.Field(i).Name)
			}
		}
	}
}

func TestTaskCreationIdempotencyModelIndexesMatchMigration(t *testing.T) {
	store := openTaskCreationIdempotencyTestDB(t)
	for _, index := range []string{"idx_tci_scope_id", "idx_tci_idempotency", "idx_tci_task_created", "idx_tci_operator_created"} {
		if !store.Migrator().HasIndex(&TaskCreationIdempotency{}, index) {
			t.Fatalf("runtime model missing migration index %s", index)
		}
	}
}
