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

func openAssetDiscoverySnapshotTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()), time.Now().UnixNano())
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&AssetDiscoverySnapshot{}, &AssetDiscoverySnapshotItem{}); err != nil {
		t.Fatalf("migrate asset discovery snapshot models: %v", err)
	}
	sqlDB, err := store.DB()
	if err != nil {
		t.Fatalf("access sqlite connection: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return store
}

func TestAssetDiscoverySnapshotModelsEnforceImmutableKeys(t *testing.T) {
	store := openAssetDiscoverySnapshotTestDB(t)
	now := time.Now().UTC()
	snapshot := AssetDiscoverySnapshot{
		SchemaVersion: AssetDiscoverySnapshotSchemaVersion,
		TenantID:      "tenant-a",
		ProjectID:     "project-a",
		AuditID:       41,
		Provider:      "fofa",
		Expression:    `domain="example.invalid"`,
		QueryHash:     strings.Repeat("a", 64),
		ConfigVersion: 3,
		ConfigHash:    strings.Repeat("b", 64),
		CreatedBy:     "operator-a",
		CreatedAt:     now,
	}
	if err := store.Create(&snapshot).Error; err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	duplicateAudit := snapshot
	duplicateAudit.ID = 0
	duplicateAudit.ProjectID = "project-b"
	if err := store.Create(&duplicateAudit).Error; err == nil {
		t.Fatal("expected one immutable snapshot per audit")
	}

	item := AssetDiscoverySnapshotItem{
		TenantID:         snapshot.TenantID,
		ProjectID:        snapshot.ProjectID,
		SnapshotID:       snapshot.ID,
		NormalizedTarget: "https://example.invalid:443",
		TargetHash:       strings.Repeat("c", 64),
		Port:             443,
		Protocol:         "https",
		Source:           "fofa",
		ObservedAt:       now,
		CreatedAt:        now,
	}
	if err := store.Create(&item).Error; err != nil {
		t.Fatalf("create snapshot item: %v", err)
	}
	duplicateTarget := item
	duplicateTarget.ID = 0
	duplicateTarget.Position = 1
	if err := store.Create(&duplicateTarget).Error; err == nil {
		t.Fatal("expected normalized target hash to be unique within a snapshot")
	}
	otherSnapshotTarget := item
	otherSnapshotTarget.ID = 0
	otherSnapshotTarget.SnapshotID = snapshot.ID + 1
	if err := store.Create(&otherSnapshotTarget).Error; err != nil {
		t.Fatalf("same target hash in another snapshot should be allowed: %v", err)
	}
}

func TestAssetDiscoverySnapshotModelsHaveNoProviderSecretOrRawResponseFields(t *testing.T) {
	for _, model := range []reflect.Type{
		reflect.TypeOf(AssetDiscoverySnapshot{}),
		reflect.TypeOf(AssetDiscoverySnapshotItem{}),
	} {
		for index := 0; index < model.NumField(); index++ {
			name := strings.ToLower(model.Field(index).Name)
			for _, forbidden := range []string{"credential", "apikey", "token", "secret", "rawresponse", "responsebody"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s contains forbidden provider field %s", model.Name(), model.Field(index).Name)
				}
			}
		}
	}
}
