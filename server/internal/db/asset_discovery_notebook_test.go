package db

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func openAssetDiscoveryNotebookTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()), time.Now().UnixNano())
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&AssetDiscoveryNotebookItem{}, &AssetDiscoveryNotebookSource{}); err != nil {
		t.Fatalf("migrate asset discovery notebook models: %v", err)
	}
	sqlDB, err := store.DB()
	if err != nil {
		t.Fatalf("access sqlite connection: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return store
}

func TestAssetDiscoveryNotebookModelsEnforceScopedUniqueKeys(t *testing.T) {
	store := openAssetDiscoveryNotebookTestDB(t)
	now := time.Now().UTC()
	item := AssetDiscoveryNotebookItem{
		TenantID:         "tenant-a",
		ProjectID:        "project-a",
		NormalizedTarget: "https://example.invalid:443",
		TargetHash:       strings.Repeat("a", 64),
		CreatedBy:        "operator-a",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := store.Create(&item).Error; err != nil {
		t.Fatalf("create notebook item: %v", err)
	}
	duplicateItem := item
	duplicateItem.ID = 0
	if err := store.Create(&duplicateItem).Error; err == nil {
		t.Fatal("expected target hash to be unique within a tenant and project")
	}
	otherProjectItem := item
	otherProjectItem.ID = 0
	otherProjectItem.ProjectID = "project-b"
	if err := store.Create(&otherProjectItem).Error; err != nil {
		t.Fatalf("same target hash in another project should be allowed: %v", err)
	}

	source := AssetDiscoveryNotebookSource{
		TenantID:       item.TenantID,
		ProjectID:      item.ProjectID,
		NotebookItemID: item.ID,
		SnapshotID:     11,
		SnapshotItemID: 22,
		AuditID:        33,
		ArchivedBy:     "operator-a",
		ArchivedAt:     now,
	}
	if err := store.Create(&source).Error; err != nil {
		t.Fatalf("create notebook source: %v", err)
	}
	duplicateSource := source
	duplicateSource.ID = 0
	duplicateSource.NotebookItemID = otherProjectItem.ID
	if err := store.Create(&duplicateSource).Error; err == nil {
		t.Fatal("expected snapshot item source to be unique within a tenant and project")
	}
	otherSnapshotSource := source
	otherSnapshotSource.ID = 0
	otherSnapshotSource.SnapshotItemID++
	if err := store.Create(&otherSnapshotSource).Error; err != nil {
		t.Fatalf("another snapshot item source should be allowed: %v", err)
	}
}

func TestAssetDiscoveryNotebookModelsHaveNoSensitiveProviderFields(t *testing.T) {
	for _, model := range []reflect.Type{
		reflect.TypeOf(AssetDiscoveryNotebookItem{}),
		reflect.TypeOf(AssetDiscoveryNotebookSource{}),
	} {
		for index := 0; index < model.NumField(); index++ {
			name := strings.ToLower(model.Field(index).Name)
			for _, forbidden := range []string{"credential", "apikey", "token", "secret", "rawresponse", "responsebody", "expression"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s contains forbidden provider field %s", model.Name(), model.Field(index).Name)
				}
			}
		}
	}
}
