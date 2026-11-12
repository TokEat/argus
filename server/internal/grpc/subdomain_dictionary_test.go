package grpc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestConfigWithSubdomainDictionarySealsHistoricalRevisionAtClaim(t *testing.T) {
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&db.SubdomainDictionary{}, &db.SubdomainDictionaryRevision{}); err != nil {
		t.Fatal(err)
	}
	dictionary := db.SubdomainDictionary{ID: "dict-claim", TenantID: "tenant-a", ProjectID: "project-a", Name: "labels", CreatedBy: "user-a"}
	if err := store.Create(&dictionary).Error; err != nil {
		t.Fatal(err)
	}
	valuesJSON := []byte(`["api","dev"]`)
	sum := sha256.Sum256(valuesJSON)
	revision := db.SubdomainDictionaryRevision{
		TenantID: dictionary.TenantID, ProjectID: dictionary.ProjectID, DictionaryID: dictionary.ID,
		Revision: 1, SHA256: hex.EncodeToString(sum[:]), ItemCount: 2, ValuesJSON: string(valuesJSON), CreatedBy: "user-a",
	}
	if err := store.Create(&revision).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(&dictionary).Error; err != nil {
		t.Fatal(err)
	}
	ref := scanpolicy.DictionaryRef{ID: dictionary.ID, Revision: 1, SHA256: revision.SHA256, Count: 2}
	config, err := json.Marshal(map[string]interface{}{
		"NoSubdomainBruteForce":    false,
		"SubdomainBruteforceDepth": 4,
		"SubdomainDictionaryRefs":  []scanpolicy.DictionaryRef{ref},
		"SubdomainDictionaryWords": []string{},
		"SubdomainWordListFile":    "config/subdomains.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := configWithSubdomainDictionary(store, db.SubTask{TenantID: "tenant-a", ProjectID: "project-a"}, config)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		SubdomainBruteforceDepth int
		SubdomainDictionaryWords []string
	}
	if err := json.Unmarshal(sealed, &got); err != nil {
		t.Fatal(err)
	}
	if got.SubdomainBruteforceDepth != 4 || len(got.SubdomainDictionaryWords) != 2 || got.SubdomainDictionaryWords[0] != "api" || got.SubdomainDictionaryWords[1] != "dev" {
		t.Fatalf("unexpected sealed claim config: %+v", got)
	}
}

func TestConfigWithSubdomainDictionaryFailsClosedWhenBruteforceIsDisabled(t *testing.T) {
	config := []byte(`{"NoSubdomainBruteForce":true,"SubdomainDictionaryRefs":[{"id":"dict","revision":1,"sha256":"` + strings.Repeat("a", 64) + `","count":1}]}`)
	if _, err := configWithSubdomainDictionary(nil, db.SubTask{}, config); err == nil {
		t.Fatal("dictionary-bound config was accepted while bruteforce was disabled")
	}
}
