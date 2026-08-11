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

func openAssetDiscoveryNotebookDistributionIntentTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), time.Now().UnixNano())), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&AssetDiscoveryNotebookDistributionIntent{}, &AssetDiscoveryNotebookDistributionIntentItem{}); err != nil {
		t.Fatalf("migrate intent models: %v", err)
	}
	sqlDB, _ := store.DB()
	t.Cleanup(func() { _ = sqlDB.Close() })
	return store
}

func distributionIntentDraft() AssetDiscoveryNotebookDistributionIntentDraft {
	return AssetDiscoveryNotebookDistributionIntentDraft{SchemaVersion: AssetDiscoveryNotebookDistributionIntentSchemaVersion, PreviewSchemaVersion: AssetDiscoveryNotebookDistributionPreviewSchemaVersion, ConfigVersion: 1, TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "task-a", OperatorID: "operator-a", IdempotencyKey: "key-a", PlanHash: strings.Repeat("a", 64), TaskStatus: "active", ConfigHash: strings.Repeat("b", 64), RuleVersion: "rules-1", Selected: 2, Fresh: 1, Duplicate: 1, ScopeAdded: 1, SeedTargetsAdded: 1, BatchCount: 1}
}
func distributionIntentItems() []AssetDiscoveryNotebookDistributionIntentItemSnapshot {
	return []AssetDiscoveryNotebookDistributionIntentItemSnapshot{{NotebookItemID: 2, NormalizedTarget: "https://two.invalid", TargetHash: strings.Repeat("2", 64), Disposition: "duplicate"}, {NotebookItemID: 1, NormalizedTarget: "https://one.invalid", TargetHash: strings.Repeat("1", 64), Disposition: "new"}}
}

func TestRecordAssetDiscoveryNotebookDistributionIntentReplayAndConflict(t *testing.T) {
	store := openAssetDiscoveryNotebookDistributionIntentTestDB(t)
	draft, items := distributionIntentDraft(), distributionIntentItems()
	first, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if first.Replayed || first.Intent.ID == 0 || len(first.Items) != 2 || first.Items[0].NotebookItemID != 1 || first.Items[0].Position != 0 {
		t.Fatalf("unexpected first record: %#v", first)
	}
	if first.Intent.IdempotencyKeyHash == draft.IdempotencyKey || !validHash(first.Intent.IdempotencyKeyHash) {
		t.Fatalf("raw idempotency key was not safely reduced: %q", first.Intent.IdempotencyKeyHash)
	}
	replayed, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, []AssetDiscoveryNotebookDistributionIntentItemSnapshot{items[1], items[0]})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replayed.Replayed || replayed.Intent.ID != first.Intent.ID {
		t.Fatalf("unexpected replay: %#v", replayed)
	}
	draft.PlanHash = strings.Repeat("c", 64)
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items); err != ErrAssetDiscoveryNotebookDistributionIdempotencyConflict {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestRecordAssetDiscoveryNotebookDistributionIntentIsolationAndValidation(t *testing.T) {
	store := openAssetDiscoveryNotebookDistributionIntentTestDB(t)
	draft, items := distributionIntentDraft(), distributionIntentItems()
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items); err != nil {
		t.Fatal(err)
	}
	draft.OperatorID = "operator-b"
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items); err != nil {
		t.Fatalf("actor isolation: %v", err)
	}
	draft.OperatorID = "operator-a"
	draft.IdempotencyKey = "key-b"
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items); err != nil {
		t.Fatalf("key isolation: %v", err)
	}
	draft.IdempotencyKey = "bad key"
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items); err == nil {
		t.Fatal("expected bad key rejection")
	}
	draft.IdempotencyKey = "key-c"
	items[1].TargetHash = "bad"
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items); err == nil {
		t.Fatal("expected bad item hash rejection")
	}
	draft, items = distributionIntentDraft(), distributionIntentItems()
	draft.IdempotencyKey = "key-c"
	draft.Selected, draft.Fresh, draft.Duplicate = 0, 0, 0
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, nil); err == nil {
		t.Fatal("expected empty selection rejection")
	}
	draft, items = distributionIntentDraft(), distributionIntentItems()
	draft.IdempotencyKey = "key-d"
	draft.SchemaVersion = "unknown/v1"
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items); err == nil {
		t.Fatal("expected unknown schema rejection")
	}
	draft, items = distributionIntentDraft(), distributionIntentItems()
	draft.IdempotencyKey = "key-e"
	draft.RuleVersion = ""
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items); err != nil {
		t.Fatalf("empty effective rule version must remain recordable: %v", err)
	}
}

func TestRecordAssetDiscoveryNotebookDistributionIntentRollsBackItems(t *testing.T) {
	store := openAssetDiscoveryNotebookDistributionIntentTestDB(t)
	draft, items := distributionIntentDraft(), distributionIntentItems()
	if err := store.Callback().Create().Before("gorm:create").Register("test:reject_distribution_item", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "AssetDiscoveryNotebookDistributionIntentItem" {
			tx.AddError(errors.New("forced item failure"))
		}
	}); err != nil {
		t.Fatalf("register item failure hook: %v", err)
	}
	if _, err := RecordAssetDiscoveryNotebookDistributionIntent(store, draft, items); err == nil {
		t.Fatal("expected forced item write rejection")
	}
	var intents, storedItems int64
	store.Model(&AssetDiscoveryNotebookDistributionIntent{}).Count(&intents)
	store.Model(&AssetDiscoveryNotebookDistributionIntentItem{}).Count(&storedItems)
	if intents != 0 || storedItems != 0 {
		t.Fatalf("invalid item input persisted records: intents=%d items=%d", intents, storedItems)
	}
}

func TestAssetDiscoveryNotebookDistributionIntentModelsHaveNoSensitiveProviderFields(t *testing.T) {
	for _, model := range []reflect.Type{reflect.TypeOf(AssetDiscoveryNotebookDistributionIntent{}), reflect.TypeOf(AssetDiscoveryNotebookDistributionIntentItem{})} {
		for i := 0; i < model.NumField(); i++ {
			name := strings.ToLower(model.Field(i).Name)
			for _, forbidden := range []string{"credential", "apikey", "token", "secret", "provider", "rawresponse", "responsebody", "expression"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s contains forbidden field %s", model.Name(), model.Field(i).Name)
				}
			}
		}
	}
	if reflect.TypeOf(AssetDiscoveryNotebookDistributionIntent{}).Field(1).Type.Kind() != reflect.String {
		t.Fatal("distribution intent schema version must remain a stable string")
	}
}

func TestAssetDiscoveryNotebookDistributionIntentModelIndexesMatchMigration(t *testing.T) {
	store := openAssetDiscoveryNotebookDistributionIntentTestDB(t)
	for _, index := range []string{
		"idx_addi_scope_id", "idx_addi_idempotency", "idx_addi_task_created", "idx_addi_operator_created", "idx_addi_status_created",
		"idx_addii_scope_id", "idx_addii_intent_position", "idx_addii_intent_notebook_item", "idx_addii_intent_target_hash", "idx_addii_notebook_item", "idx_addii_target_hash",
	} {
		model := interface{}(&AssetDiscoveryNotebookDistributionIntent{})
		if strings.HasPrefix(index, "idx_addii_") {
			model = &AssetDiscoveryNotebookDistributionIntentItem{}
		}
		if !store.Migrator().HasIndex(model, index) {
			t.Fatalf("runtime model missing migration index %s", index)
		}
	}
}
