package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestInitializeEXPWorkspaceAllowsLocalOnlyInDevelopment(t *testing.T) {
	database, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "exp.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&db.Exp{}, &db.ExpRevision{}, &db.ExpDependency{}, &db.ExpAsset{}, &db.ExpAssetRef{}, &db.ExpTestCase{}, &db.ExpRun{}, &db.ExpAudit{}, &db.ExpRiskWaiver{}); err != nil {
		t.Fatal(err)
	}
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer runtime.Close()
	t.Setenv("ARGUS_EXP_STORE_MODE", "local")
	t.Setenv("ARGUS_EXP_LOCAL_ROOT", t.TempDir())
	t.Setenv("ARGUS_YAKSHA_URL", runtime.URL)
	if _, err := initializeEXPWorkspace(context.Background(), database, true); err != nil {
		t.Fatalf("development LocalStore initialization failed: %v", err)
	}
	if _, err := initializeEXPWorkspace(context.Background(), database, false); err == nil || !strings.Contains(err.Error(), "only allowed with --dev") {
		t.Fatalf("production LocalStore should fail closed, got %v", err)
	}
}

func TestInitializeEXPWorkspaceProductionDefaultsToRequiredMinIO(t *testing.T) {
	database, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "exp.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ARGUS_EXP_STORE_MODE", "ARGUS_EXP_MINIO_ENDPOINT", "ARGUS_EXP_MINIO_BUCKET", "ARGUS_EXP_MINIO_ACCESS_KEY", "ARGUS_EXP_MINIO_SECRET_KEY"} {
		t.Setenv(key, "")
	}
	if _, err := initializeEXPWorkspace(context.Background(), database, false); err == nil || !strings.Contains(err.Error(), "S3 endpoint") {
		t.Fatalf("production should require MinIO configuration, got %v", err)
	}
}

func TestDevelopmentEXPSeedIsExplicitAndDevelopmentOnly(t *testing.T) {
	t.Setenv("ARGUS_EXP_LAB_SEED", "true")
	if _, err := seedDevelopmentEXPWorkspace(context.Background(), nil, false); err == nil || !strings.Contains(err.Error(), "only allowed with --dev") {
		t.Fatalf("production lab seed should fail closed, got %v", err)
	}
	t.Setenv("ARGUS_EXP_LAB_SEED", "false")
	if result, err := seedDevelopmentEXPWorkspace(context.Background(), nil, true); err != nil || result != nil {
		t.Fatalf("disabled lab seed result=%v err=%v", result, err)
	}
}
