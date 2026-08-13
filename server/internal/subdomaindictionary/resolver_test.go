package subdomaindictionary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestLoadValuesBindsExactProjectRevisionAndSurvivesSoftDelete(t *testing.T) {
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&db.SubdomainDictionary{}, &db.SubdomainDictionaryRevision{}); err != nil {
		t.Fatal(err)
	}
	dictionary := db.SubdomainDictionary{ID: "dict-1", TenantID: "tenant-a", ProjectID: "project-a", Name: "labels", CreatedBy: "user-a"}
	if err := store.Create(&dictionary).Error; err != nil {
		t.Fatal(err)
	}
	valuesJSON, _ := json.Marshal([]string{"api", "dev"})
	revision := db.SubdomainDictionaryRevision{
		TenantID: dictionary.TenantID, ProjectID: dictionary.ProjectID, DictionaryID: dictionary.ID,
		Revision: 1, SHA256: hash(valuesJSON), ItemCount: 2, ValuesJSON: string(valuesJSON), CreatedBy: "user-a",
	}
	if err := store.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}
	policy := scanpolicy.Policy{Subdomains: scanpolicy.SubdomainPolicy{Wordlists: []scanpolicy.DictionaryRef{{ID: dictionary.ID, Revision: 1, SHA256: revision.SHA256, Count: 2}}}}
	got, err := LoadValues(store, policy, "tenant-a", "project-a", true)
	if err != nil || strings.Join(got, ",") != "api,dev" {
		t.Fatalf("load active values = %v err=%v", got, err)
	}
	if _, err := LoadValues(store, policy, "tenant-a", "project-b", true); err == nil {
		t.Fatal("cross-project dictionary resolution succeeded")
	}
	if err := store.Delete(&dictionary).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := LoadValues(store, policy, "tenant-a", "project-a", true); err == nil {
		t.Fatal("soft-deleted dictionary accepted for a new policy")
	}
	if got, err := LoadValues(store, policy, "tenant-a", "project-a", false); err != nil || len(got) != 2 {
		t.Fatalf("historical revision did not survive soft delete: %v err=%v", got, err)
	}
}

func TestLoadValuesRejectsMetadataOrContentDrift(t *testing.T) {
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&db.SubdomainDictionary{}, &db.SubdomainDictionaryRevision{}); err != nil {
		t.Fatal(err)
	}
	dictionary := db.SubdomainDictionary{ID: "dict-drift", TenantID: "tenant-a", ProjectID: "project-a", Name: "labels", CreatedBy: "user-a"}
	if err := store.Create(&dictionary).Error; err != nil {
		t.Fatal(err)
	}
	encoded := []byte(`["dev"]`)
	revision := db.SubdomainDictionaryRevision{TenantID: "tenant-a", ProjectID: "project-a", DictionaryID: dictionary.ID, Revision: 1, SHA256: hash(encoded), ItemCount: 1, ValuesJSON: string(encoded), CreatedBy: "user-a"}
	if err := store.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}
	policy := scanpolicy.Policy{Subdomains: scanpolicy.SubdomainPolicy{Wordlists: []scanpolicy.DictionaryRef{{ID: dictionary.ID, Revision: 1, SHA256: strings.Repeat("f", 64), Count: 1}}}}
	if _, err := LoadValues(store, policy, "tenant-a", "project-a", true); err == nil || !strings.Contains(err.Error(), "metadata changed") {
		t.Fatalf("expected metadata drift rejection, got %v", err)
	}

	policy.Subdomains.Wordlists[0].SHA256 = revision.SHA256
	if err := store.Model(&db.SubdomainDictionaryRevision{}).Where("id = ?", revision.ID).Update("values_json", `["prod"]`).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := LoadValues(store, policy, "tenant-a", "project-a", true); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected content drift rejection, got %v", err)
	}
}
