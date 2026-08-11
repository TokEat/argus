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

func openTaskBatchRetryIdempotencyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), time.Now().UnixNano())), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&TaskBatchRetryIdempotency{}); err != nil {
		t.Fatalf("migrate model: %v", err)
	}
	sqlDB, _ := store.DB()
	t.Cleanup(func() { _ = sqlDB.Close() })
	return store
}

func taskBatchRetryIdempotencyDraft() TaskBatchRetryIdempotencyDraft {
	return TaskBatchRetryIdempotencyDraft{
		TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "task-a", BatchID: "batch-a", OperatorID: "operator-a", Operation: "retry_task_batch_v1",
		IdempotencyKey: "key-a", RequestHash: strings.Repeat("a", 64), AttemptID: "attempt-a-2", AttemptNo: 2, ConfigVersion: 3, ConfigHash: strings.Repeat("b", 64), RuleVersion: "rules-v3",
		BeforeStatus: "Failed", AfterStatus: "Running",
	}
}

func TestRecordAndLookupTaskBatchRetryIdempotencyReplayAndConflict(t *testing.T) {
	store := openTaskBatchRetryIdempotencyTestDB(t)
	draft := taskBatchRetryIdempotencyDraft()
	first, err := RecordTaskBatchRetryIdempotencyTx(store, draft)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if first.Replayed || first.Record.ID == 0 || first.Record.IdempotencyKeyHash == draft.IdempotencyKey || !validTaskBatchRetryIdempotencyHash(first.Record.IdempotencyKeyHash) {
		t.Fatalf("unexpected first record: %#v", first)
	}
	replayDraft := draft
	replayDraft.AttemptID, replayDraft.AttemptNo = "regenerated-attempt", 3
	replayed, err := RecordTaskBatchRetryIdempotencyTx(store, replayDraft)
	if err != nil || !replayed.Replayed || replayed.Record.ID != first.Record.ID || replayed.Record.AttemptID != first.Record.AttemptID {
		t.Fatalf("unexpected replay: result=%#v err=%v", replayed, err)
	}
	_, err = LookupTaskBatchRetryIdempotencyTx(store, draft.TenantID, draft.ProjectID, draft.RootTaskID, draft.BatchID, draft.OperatorID, draft.Operation, draft.IdempotencyKey, strings.Repeat("c", 64))
	if !errors.Is(err, ErrTaskBatchRetryIdempotencyConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	missing, err := LookupTaskBatchRetryIdempotencyTx(store, draft.TenantID, draft.ProjectID, draft.RootTaskID, "batch-other", draft.OperatorID, draft.Operation, draft.IdempotencyKey, draft.RequestHash)
	if err != nil || missing.Replayed {
		t.Fatalf("batch scope should isolate lookup: %#v, %v", missing, err)
	}
}

func TestTaskBatchRetryIdempotencyValidationAndRollback(t *testing.T) {
	draft := taskBatchRetryIdempotencyDraft()
	for _, mutate := range []func(*TaskBatchRetryIdempotencyDraft){
		func(d *TaskBatchRetryIdempotencyDraft) { d.IdempotencyKey = "bad key" },
		func(d *TaskBatchRetryIdempotencyDraft) { d.RequestHash = strings.Repeat("A", 64) },
		func(d *TaskBatchRetryIdempotencyDraft) { d.AttemptNo = 0 },
		func(d *TaskBatchRetryIdempotencyDraft) { d.ConfigVersion = 0 },
		func(d *TaskBatchRetryIdempotencyDraft) { d.RuleVersion = "" },
	} {
		invalid := draft
		mutate(&invalid)
		if err := validateTaskBatchRetryIdempotencyDraft(invalid); err == nil {
			t.Fatalf("expected invalid draft rejection: %#v", invalid)
		}
	}
	store := openTaskBatchRetryIdempotencyTestDB(t)
	if err := store.Callback().Create().Before("gorm:create").Register("test:reject_task_batch_retry_idempotency", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "TaskBatchRetryIdempotency" {
			tx.AddError(errors.New("forced write failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordTaskBatchRetryIdempotencyTx(store, draft); err == nil {
		t.Fatal("expected write failure")
	}
	var count int64
	store.Model(&TaskBatchRetryIdempotency{}).Count(&count)
	if count != 0 {
		t.Fatalf("failed write persisted %d records", count)
	}
}

func TestTaskBatchRetryIdempotencyModelIsSafeAndIndexed(t *testing.T) {
	model := reflect.TypeOf(TaskBatchRetryIdempotency{})
	for i := 0; i < model.NumField(); i++ {
		name := strings.ToLower(model.Field(i).Name)
		for _, forbidden := range []string{"credential", "apikey", "token", "secret", "provider", "rawresponse", "responsebody", "targetlist", "configbody"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("model contains forbidden field %s", model.Field(i).Name)
			}
		}
	}
	store := openTaskBatchRetryIdempotencyTestDB(t)
	for _, index := range []string{"idx_tbri_scope_id", "idx_tbri_idempotency", "idx_tbri_batch_created", "idx_tbri_operator_created"} {
		if !store.Migrator().HasIndex(&TaskBatchRetryIdempotency{}, index) {
			t.Fatalf("runtime model missing migration index %s", index)
		}
	}
}
