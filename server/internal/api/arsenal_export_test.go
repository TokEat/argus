package api

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
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
	Name           string
	FileName       string
	Content        string
	ExecutionClass string
	RiskLevel      string
	Enabled        bool
}

func (exportedPoc) TableName() string { return "pocs" }

type exportedActiveFingerprint struct {
	Name         string
	FileName     string
	ProductName  string
	Content      string
	ContentHash  string
	AutoEligible bool
	Enabled      bool
}

func (exportedActiveFingerprint) TableName() string { return "active_fingerprints" }

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

	dbPath, _, _, err := buildArsenalSQLiteDB("default")
	if err != nil {
		t.Fatalf("build arsenal sqlite db: %v", err)
	}
	defer os.Remove(dbPath)

	sdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open exported db: %v", err)
	}
	sqlDB, err := sdb.DB()
	if err != nil {
		t.Fatalf("unwrap exported sqlite DB: %v", err)
	}
	defer sqlDB.Close()

	var asset exportedPocAsset
	if err := sdb.Where("relative_path = ?", "helpers/payloads/demo.txt").First(&asset).Error; err != nil {
		t.Fatalf("expected exported poc asset: %v", err)
	}
	if asset.Content != "payload\n" || asset.ContentHash != "asset-hash" || !asset.Enabled {
		t.Fatalf("unexpected exported poc asset: %+v", asset)
	}
}

func TestAgentSyncArsenalTypesExcludeAPIConfig(t *testing.T) {
	for _, typ := range agentSyncArsenalTypes() {
		if typ == "apiconfig" {
			t.Fatalf("agent arsenal DB sync must not include apiconfig secrets")
		}
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
	if dbResp.Header.Get("X-Arsenal-SHA256") == "" {
		t.Fatalf("expected X-Arsenal-SHA256 header")
	}
	dbData, err := io.ReadAll(dbResp.Body)
	if err != nil {
		t.Fatalf("read db response body: %v", err)
	}
	if len(dbData) == 0 {
		t.Fatalf("expected non-empty sqlite db response")
	}
	if got, want := dbResp.Header.Get("X-Arsenal-Hash"), fmt.Sprintf("%x", md5.Sum(dbData)); got != want {
		t.Fatalf("X-Arsenal-Hash = %q, want downloaded DB MD5 %q", got, want)
	}
	if got, want := dbResp.Header.Get("X-Arsenal-SHA256"), fmt.Sprintf("%x", sha256.Sum256(dbData)); got != want {
		t.Fatalf("X-Arsenal-SHA256 = %q, want downloaded DB SHA-256 %q", got, want)
	}

	dbPath := filepath.Join(t.TempDir(), "arsenal.db")
	if err := os.WriteFile(dbPath, dbData, 0o644); err != nil {
		t.Fatalf("write downloaded db: %v", err)
	}
	sdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open downloaded db: %v", err)
	}
	sqlDB, err := sdb.DB()
	if err != nil {
		t.Fatalf("get downloaded db handle: %v", err)
	}
	defer sqlDB.Close()

	var poc exportedPoc
	if err := sdb.Where("file_name = ?", "http-demo.yaml").First(&poc).Error; err != nil {
		t.Fatalf("expected exported poc in downloaded db: %v", err)
	}
	if poc.Content == "" || !poc.Enabled {
		t.Fatalf("unexpected exported poc: %+v", poc)
	}
	if poc.ExecutionClass != db.PocExecutionClassVerification || poc.RiskLevel != db.PocRiskLevelHigh {
		t.Fatalf("expected POC governance metadata in exported arsenal: %+v", poc)
	}
	var active exportedActiveFingerprint
	if err := sdb.Where("file_name = ?", "http-product-detect.yaml").First(&active).Error; err != nil {
		t.Fatalf("expected exported active fingerprint in downloaded db: %v", err)
	}
	if active.ProductName != "HTTPProduct" || active.Content == "" || !active.AutoEligible || !active.Enabled {
		t.Fatalf("unexpected exported active fingerprint: %+v", active)
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

func TestBuildArsenalSQLiteDBKeepsDuplicateNamePocs(t *testing.T) {
	store := setupAITestDB(t)
	mk := func(fileName string) db.Arsenal {
		return db.Arsenal{
			ID:       db.BuildTenantArsenalID("default", "poc", fileName),
			TenantID: "default", Type: "poc", FileName: fileName,
			Content: "id: nacos-version\ninfo:\n  name: Nacos Version\n  severity: info\nrequests: []\n",
			Hash:    fileName + "-hash", State: "Approved", Version: 1,
		}
	}
	pocA := mk("nacos-version.yaml")
	pocB := mk("nacos-version-nuclei-templates.yaml")
	for _, row := range []interface{}{&pocA, &pocB} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed arsenal: %v", err)
		}
	}
	// Same `id:` (Name), different source files. Both must survive export because
	// the server/agent unique key is the file name, not the id.
	for _, rule := range []db.PocRule{
		{TenantID: "default", ArtifactID: pocA.ID, Name: "nacos-version", SourceFile: "nacos-version.yaml", ContentHash: pocA.Hash, Severity: "info", Enabled: true},
		{TenantID: "default", ArtifactID: pocB.ID, Name: "nacos-version", SourceFile: "nacos-version-nuclei-templates.yaml", ContentHash: pocB.Hash, Severity: "info", Enabled: true},
	} {
		if err := store.Create(&rule).Error; err != nil {
			t.Fatalf("seed poc rule: %v", err)
		}
	}

	dbPath, _, _, err := buildArsenalSQLiteDB("default")
	if err != nil {
		t.Fatalf("build arsenal sqlite db: %v", err)
	}
	defer os.Remove(dbPath)
	sdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open exported db: %v", err)
	}
	sqlDB, err := sdb.DB()
	if err != nil {
		t.Fatalf("unwrap exported sqlite DB: %v", err)
	}
	defer sqlDB.Close()

	var fileNames []string
	if err := sdb.Model(&exportedPoc{}).Where("name = ?", "nacos-version").Pluck("file_name", &fileNames).Error; err != nil {
		t.Fatalf("query exported pocs: %v", err)
	}
	if len(fileNames) != 2 {
		t.Fatalf("exported duplicate-name pocs=%v, want both source files kept", fileNames)
	}
}

func seedArsenalExportRules(t *testing.T, store *gorm.DB) {
	t.Helper()
	pocID := db.BuildTenantArsenalID("default", "poc", "http-demo.yaml")
	activeID := db.BuildTenantArsenalID("default", "active_fingerprint", "http-product-detect.yaml")
	activeContent := "id: http-product-detect\ninfo:\n  name: HTTP Product Detect\n  severity: info\n  metadata:\n    argus-rule-kind: active-fingerprint\n    argus-product: HTTPProduct\n    argus-behavior-kind: header\n    argus-auto-profile: safe\n    max-request: 1\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    headers: {X-Argus-Probe: '{{randstr}}'}\n    matchers: [{type: status, status: [200]}]\n"
	activeHash := fmt.Sprintf("%x", md5.Sum([]byte(activeContent)))
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
			ID:       activeID,
			TenantID: "default",
			Type:     "active_fingerprint",
			FileName: "http-product-detect.yaml",
			Content:  activeContent,
			Hash:     activeHash,
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
		TenantID:       "default",
		ArtifactID:     pocID,
		Name:           "http-demo",
		SourceFile:     "http-demo.yaml",
		ContentHash:    "poc-hash",
		Severity:       "info",
		ExecutionClass: db.PocExecutionClassVerification,
		RiskLevel:      db.PocRiskLevelHigh,
		Enabled:        true,
	}).Error; err != nil {
		t.Fatalf("seed poc rule: %v", err)
	}
	if err := store.Create(&db.ActiveFingerprintRule{
		TenantID: "default", ArtifactID: activeID, SourceFile: "http-product-detect.yaml",
		Name: "http-product-detect", ProductName: "HTTPProduct", ContentHash: activeHash,
		State: "Approved", Enabled: true, ComputedAutoProfile: "safe", AutoEligible: true, MaxRequests: 1,
	}).Error; err != nil {
		t.Fatalf("seed active fingerprint rule: %v", err)
	}
}

// 修复回归：包内 Poc 唯一性落在 FileName 上，重名模板（不同文件）必须
// 全部下发；任何按 Name 的代表选择都会让另一条工作流引用到不存在的文件。
func TestAgentPocSchemaKeysUniquenessOnFileName(t *testing.T) {
	nameField, ok := reflect.TypeOf(agentPoc{}).FieldByName("Name")
	if !ok {
		t.Fatal("agentPoc.Name field missing")
	}
	if strings.Contains(nameField.Tag.Get("gorm"), "uniqueIndex") {
		t.Fatalf("agentPoc.Name must not carry uniqueIndex (duplicate template names are legitimate), tag=%q", nameField.Tag.Get("gorm"))
	}
	fileField, ok := reflect.TypeOf(agentPoc{}).FieldByName("FileName")
	if !ok {
		t.Fatal("agentPoc.FileName field missing")
	}
	if !strings.Contains(fileField.Tag.Get("gorm"), "uniqueIndex") {
		t.Fatalf("agentPoc.FileName must be uniqueIndex, tag=%q", fileField.Tag.Get("gorm"))
	}
}
