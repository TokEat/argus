package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

type exportedPocAsset struct {
	RelativePath string
	Content      string
	ContentHash  string
	Enabled      bool
}

func (exportedPocAsset) TableName() string { return "poc_assets" }

type exportedConfigAsset struct {
	RelativePath string
	Content      string
	ContentHash  string
	Enabled      bool
}

func (exportedConfigAsset) TableName() string { return "config_assets" }

type exportedPoc struct {
	Name     string
	FileName string
	Content  string
	Enabled  bool
}

func (exportedPoc) TableName() string { return "pocs" }

func TestBuildArsenalSQLiteDBIncludesPocAssets(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "poc_asset", "helpers/payloads/demo.txt"),
		TenantID: "default",
		Type:     "poc_asset",
		FileName: "helpers/payloads/demo.txt",
		Content:  "payload\n",
		Hash:     "asset-hash",
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed poc asset: %v", err)
	}

	dbPath, _, err := buildArsenalSQLiteDB("default")
	if err != nil {
		t.Fatalf("build arsenal sqlite db: %v", err)
	}
	defer os.Remove(dbPath)

	sdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open exported db: %v", err)
	}

	var asset exportedPocAsset
	if err := sdb.Where("relative_path = ?", "helpers/payloads/demo.txt").First(&asset).Error; err != nil {
		t.Fatalf("expected exported poc asset: %v", err)
	}
	if asset.Content != "payload\n" || asset.ContentHash != "asset-hash" || !asset.Enabled {
		t.Fatalf("unexpected exported poc asset: %+v", asset)
	}
}

func TestArsenalDBEndpointsDownloadMaterializablePackage(t *testing.T) {
	store := setupAITestDB(t)
	seedArsenalExportRules(t, store)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	withTenant := func(fn gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set("tenant", "default")
			fn(c)
		}
	}
	router.GET("/api/v1/arsenals/db/hash", withTenant(getArsenalDBHash))
	router.GET("/api/v1/arsenals/db", withTenant(getArsenalDB))

	server := httptest.NewServer(router)
	defer server.Close()

	hashResp, err := http.Get(server.URL + "/api/v1/arsenals/db/hash")
	if err != nil {
		t.Fatalf("GET /arsenals/db/hash: %v", err)
	}
	defer hashResp.Body.Close()
	if hashResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected hash status %d", hashResp.StatusCode)
	}
	var hashBody struct {
		Hash         string `json:"hash"`
		RuleVersion  string `json:"rule_version"`
		ArsenalCount int    `json:"arsenal_count"`
	}
	if err := json.NewDecoder(hashResp.Body).Decode(&hashBody); err != nil {
		t.Fatalf("decode hash response: %v", err)
	}
	if hashBody.Hash == "" || hashBody.ArsenalCount < 7 {
		t.Fatalf("unexpected hash response: %+v", hashBody)
	}

	dbResp, err := http.Get(server.URL + "/api/v1/arsenals/db")
	if err != nil {
		t.Fatalf("GET /arsenals/db: %v", err)
	}
	defer dbResp.Body.Close()
	if dbResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected db status %d", dbResp.StatusCode)
	}
	if dbResp.Header.Get("X-Arsenal-Hash") == "" {
		t.Fatalf("expected X-Arsenal-Hash header")
	}
	dbData, err := io.ReadAll(dbResp.Body)
	if err != nil {
		t.Fatalf("read db response body: %v", err)
	}
	if len(dbData) == 0 {
		t.Fatalf("expected non-empty sqlite db response")
	}

	dbPath := filepath.Join(t.TempDir(), "arsenal.db")
	if err := os.WriteFile(dbPath, dbData, 0o644); err != nil {
		t.Fatalf("write downloaded db: %v", err)
	}
	sdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open downloaded db: %v", err)
	}

	var poc exportedPoc
	if err := sdb.Where("file_name = ?", "http-demo.yaml").First(&poc).Error; err != nil {
		t.Fatalf("expected exported poc in downloaded db: %v", err)
	}
	if poc.Content == "" || !poc.Enabled {
		t.Fatalf("unexpected exported poc: %+v", poc)
	}

	var asset exportedPocAsset
	if err := sdb.Where("relative_path = ?", "helpers/payloads/http-demo.txt").First(&asset).Error; err != nil {
		t.Fatalf("expected exported poc asset in downloaded db: %v", err)
	}
	if asset.Content != "asset payload\n" || !asset.Enabled {
		t.Fatalf("unexpected downloaded poc asset: %+v", asset)
	}

	var dictAsset exportedConfigAsset
	if err := sdb.Where("relative_path = ?", "dict/mysql.txt").First(&dictAsset).Error; err != nil {
		t.Fatalf("expected exported dict config asset in downloaded db: %v", err)
	}
	if dictAsset.Content != "root:root\n" || !dictAsset.Enabled {
		t.Fatalf("unexpected downloaded dict config asset: %+v", dictAsset)
	}

	var subdomainAsset exportedConfigAsset
	if err := sdb.Where("relative_path = ?", "subdomains.txt").First(&subdomainAsset).Error; err != nil {
		t.Fatalf("expected exported subdomains config asset in downloaded db: %v", err)
	}
	if subdomainAsset.Content != "www\napi\n" || !subdomainAsset.Enabled {
		t.Fatalf("unexpected downloaded subdomains config asset: %+v", subdomainAsset)
	}
}

func seedArsenalExportRules(t *testing.T, store *gorm.DB) {
	t.Helper()
	pocID := db.BuildTenantArsenalID("default", "poc", "http-demo.yaml")
	rows := []db.Arsenal{
		{
			ID:       db.BuildTenantArsenalID("default", "finger", "finger.yaml"),
			TenantID: "default",
			Type:     "finger",
			FileName: "finger.yaml",
			Content:  "HTTPProduct:\n  - 'body=\"http-product\"'\n",
			Hash:     "finger-hash",
			State:    "Approved",
			Version:  1,
		},
		{
			ID:       db.BuildTenantArsenalID("default", "workflow", "workflow.yaml"),
			TenantID: "default",
			Type:     "workflow",
			FileName: "workflow.yaml",
			Content:  "HTTPProduct:\n  type: [root]\n  pocs: [http-demo.yaml]\n",
			Hash:     "workflow-hash",
			State:    "Approved",
			Version:  1,
		},
		{
			ID:       db.BuildTenantArsenalID("default", "dir", "dir.yaml"),
			TenantID: "default",
			Type:     "dir",
			FileName: "dir.yaml",
			Content:  "HTTPProduct:\n  - /demo\n",
			Hash:     "dir-hash",
			State:    "Approved",
			Version:  1,
		},
		{
			ID:       pocID,
			TenantID: "default",
			Type:     "poc",
			FileName: "http-demo.yaml",
			Content:  "id: http-demo\ninfo:\n  name: HTTP Demo\n  author: test\n  severity: info\nrequests: []\n",
			Hash:     "poc-hash",
			State:    "Approved",
			Version:  1,
		},
		{
			ID:       db.BuildTenantArsenalID("default", "poc_asset", "helpers/payloads/http-demo.txt"),
			TenantID: "default",
			Type:     "poc_asset",
			FileName: "helpers/payloads/http-demo.txt",
			Content:  "asset payload\n",
			Hash:     "asset-hash",
			State:    "Approved",
			Version:  1,
		},
		{
			ID:       db.BuildTenantArsenalID("default", "config_asset", "dict/mysql.txt"),
			TenantID: "default",
			Type:     "config_asset",
			FileName: "dict/mysql.txt",
			Content:  "root:root\n",
			Hash:     "dict-hash",
			State:    "Approved",
			Version:  1,
		},
		{
			ID:       db.BuildTenantArsenalID("default", "config_asset", "subdomains.txt"),
			TenantID: "default",
			Type:     "config_asset",
			FileName: "subdomains.txt",
			Content:  "www\napi\n",
			Hash:     "subdomains-hash",
			State:    "Approved",
			Version:  1,
		},
	}
	if err := store.Create(&rows).Error; err != nil {
		t.Fatalf("seed arsenals: %v", err)
	}
	if err := store.Create(&db.FingerprintRule{
		TenantID:    "default",
		ArtifactID:  rows[0].ID,
		ProductName: "HTTPProduct",
		RuleExpr:    `body="http-product"`,
		Enabled:     true,
	}).Error; err != nil {
		t.Fatalf("seed fingerprint rule: %v", err)
	}
	if err := store.Create(&db.WorkflowRule{
		TenantID:    "default",
		ArtifactID:  rows[1].ID,
		ProductName: "HTTPProduct",
		PocName:     "http-demo.yaml",
		MatchType:   "root",
		Enabled:     true,
	}).Error; err != nil {
		t.Fatalf("seed workflow rule: %v", err)
	}
	if err := store.Create(&db.DirRule{
		TenantID:    "default",
		ArtifactID:  rows[2].ID,
		ProductName: "HTTPProduct",
		Path:        "/demo",
		Enabled:     true,
	}).Error; err != nil {
		t.Fatalf("seed dir rule: %v", err)
	}
	if err := store.Create(&db.PocRule{
		TenantID:    "default",
		ArtifactID:  pocID,
		Name:        "http-demo",
		SourceFile:  "http-demo.yaml",
		ContentHash: "poc-hash",
		Severity:    "info",
		Enabled:     true,
	}).Error; err != nil {
		t.Fatalf("seed poc rule: %v", err)
	}
}
