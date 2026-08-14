package db

import (
	"os"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestPrepareShiroActiveFingerprintMigrationPreservesTenantConflict(t *testing.T) {
	store, err := gorm.Open(sqlite.Open("file:seed-conflict?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&Arsenal{}); err != nil {
		t.Fatal(err)
	}
	active := readSeedFixture(t, "../../../scanner/common/config/active-fingerprints/shiro-detect.yaml", "active_fingerprint", "shiro-detect.yaml")
	workflow := readSeedFixture(t, "../../../scanner/common/config/workflow.yaml", "workflow", "workflow.yaml")
	if got := arsenalContentMD5(active); got != activeShiroProbeMD5 {
		t.Fatalf("active Shiro built-in hash drifted: got %s", got)
	}
	if got := arsenalContentMD5(workflow); got != activeShiroWorkflowMD5 {
		t.Fatalf("workflow built-in hash drifted: got %s", got)
	}
	custom := active
	custom.ID = BuildTenantArsenalID("default", "active_fingerprint", custom.FileName)
	custom.Content += "\n# tenant customization\n"
	if err := store.Create(&custom).Error; err != nil {
		t.Fatal(err)
	}
	other := Arsenal{ID: "other", TenantID: "default", Type: "poc", FileName: "other.yaml", Content: "id: other"}
	filtered, err := prepareShiroActiveFingerprintMigration(store, []Arsenal{active, workflow, other})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].ID != "other" {
		t.Fatalf("expected Shiro migration artifacts skipped while unrelated seed remains, got %+v", filtered)
	}
	var preserved Arsenal
	if err := store.First(&preserved, "id = ?", custom.ID).Error; err != nil || preserved.Content != custom.Content {
		t.Fatalf("custom active fingerprint was not preserved: %+v err=%v", preserved, err)
	}
}

func TestPrepareShiroActiveFingerprintMigrationUpgradesPreviousBuiltIn(t *testing.T) {
	store, err := gorm.Open(sqlite.Open("file:seed-upgrade?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&Arsenal{}); err != nil {
		t.Fatal(err)
	}
	active := readSeedFixture(t, "../../../scanner/common/config/active-fingerprints/shiro-detect.yaml", "active_fingerprint", "shiro-detect.yaml")
	workflow := readSeedFixture(t, "../../../scanner/common/config/workflow.yaml", "workflow", "workflow.yaml")
	previous := active
	previous.ID = BuildTenantArsenalID("default", "active_fingerprint", previous.FileName)
	previous.Content = strings.Replace(previous.Content, "    argus-behavior-kind: cookie\n", "", 1)
	if got := arsenalContentMD5(previous); got != previousShiroProbeMD5 {
		t.Fatalf("previous active Shiro built-in hash drifted: got %s", got)
	}
	if err := store.Create(&previous).Error; err != nil {
		t.Fatal(err)
	}
	filtered, err := prepareShiroActiveFingerprintMigration(store, []Arsenal{active, workflow})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected previous built-in to be eligible for upgrade, got %+v", filtered)
	}
}

func readSeedFixture(t *testing.T, path, typ, fileName string) Arsenal {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return Arsenal{ID: BuildTenantArsenalID("default", typ, fileName), TenantID: "default", Type: typ, FileName: fileName, Content: string(content), State: "Approved", Version: 1}
}
