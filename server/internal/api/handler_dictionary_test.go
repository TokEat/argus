package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func seedDictionaryArsenal(t *testing.T, store *gorm.DB, tenantID, arsenalType, fileName, content string) {
	t.Helper()
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID(tenantID, arsenalType, fileName),
		TenantID: tenantID,
		Type:     arsenalType,
		FileName: fileName,
		Content:  content,
		Hash:     "fixture-hash",
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed %s/%s: %v", arsenalType, fileName, err)
	}
}

func TestNormalizeDirPaths(t *testing.T) {
	t.Run("trims and deduplicates while preserving order", func(t *testing.T) {
		got, err := normalizeDirPaths([]string{" /admin ", "/login?next=%2F", "/admin"})
		if err != nil {
			t.Fatalf("normalize paths: %v", err)
		}
		want := []string{"/admin", "/login?next=%2F"}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("normalized paths = %v, want %v", got, want)
		}
	})

	invalid := map[string][]string{
		"empty list":          nil,
		"empty path":          {"/admin", "  "},
		"relative path":       {"admin"},
		"scheme relative URL": {"//example.test/admin"},
		"absolute URL":        {"https://example.test/admin"},
		"fragment":            {"/admin#secret"},
		"control character":   {"/admin\nheader"},
		"too long":            {"/" + strings.Repeat("a", maxDirPathLength)},
	}
	for name, paths := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeDirPaths(paths); err == nil {
				t.Fatalf("normalizeDirPaths(%q) unexpectedly succeeded", paths)
			}
		})
	}

	t.Run("enforces unique path limit", func(t *testing.T) {
		paths := make([]string, 0, maxDirPathsPerProduct+1)
		for i := 0; i <= maxDirPathsPerProduct; i++ {
			paths = append(paths, fmt.Sprintf("/path-%d", i))
		}
		if _, err := normalizeDirPaths(paths); err == nil {
			t.Fatal("expected per-product path limit error")
		}
	})
}

func TestAddDirDictNormalizesAndDeduplicatesPaths(t *testing.T) {
	store := setupAITestDB(t)
	seedDictionaryArsenal(t, store, "default", "dir", "dir.yaml", "{}\n")

	ctx, recorder := newTenantContext(http.MethodPost, "/dictionaries/dir")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/dictionaries/dir", strings.NewReader(`{"product":" Demo ","paths":[" /admin ","/admin","/login?next=%2F"]}`))
	addDirDict(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("add dir status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	data, _, err := fetchAndParseDir("default")
	if err != nil {
		t.Fatalf("load saved dir: %v", err)
	}
	want := []string{"/admin", "/login?next=%2F"}
	if fmt.Sprint(data["Demo"]) != fmt.Sprint(want) {
		t.Fatalf("saved paths = %v, want %v", data["Demo"], want)
	}
}

func TestFingerprintRenameAndDeleteRejectReferencedProduct(t *testing.T) {
	for _, action := range []string{"rename", "delete"} {
		t.Run(action, func(t *testing.T) {
			store := setupAITestDB(t)
			seedDictionaryArsenal(t, store, "default", "finger", "finger.yaml", "Referenced:\n  - body=referenced\n")
			seedDictionaryArsenal(t, store, "default", "dir", "dir.yaml", "Referenced:\n  - /admin\n")
			seedDictionaryArsenal(t, store, "default", "workflow", "workflow.yaml", "Referenced:\n  type: [root]\n  pocs: []\n")

			var ctx *gin.Context
			var recorder *httptest.ResponseRecorder
			if action == "rename" {
				ctx, recorder = newTenantContext(http.MethodPut, "/dictionaries/fingerprint/Referenced")
				ctx.Request = httptest.NewRequest(http.MethodPut, "/dictionaries/fingerprint/Referenced", strings.NewReader(`{"product":"Renamed","rules":["body=referenced"]}`))
				ctx.Params = gin.Params{{Key: "product", Value: "Referenced"}}
				updateFingerprintDict(ctx)
			} else {
				ctx, recorder = newTenantContext(http.MethodDelete, "/dictionaries/fingerprint/Referenced")
				ctx.Params = gin.Params{{Key: "product", Value: "Referenced"}}
				deleteFingerprintDict(ctx)
			}

			if recorder.Code != http.StatusConflict {
				t.Fatalf("%s status=%d body=%s", action, recorder.Code, recorder.Body.String())
			}
			if body := recorder.Body.String(); !strings.Contains(body, "dir.yaml") || !strings.Contains(body, "workflow.yaml") {
				t.Fatalf("expected both reference sources, got %s", body)
			}
			data, _, err := fetchAndParseFingerprint("default")
			if err != nil {
				t.Fatalf("load fingerprint: %v", err)
			}
			if _, exists := data["Referenced"]; !exists {
				t.Fatalf("referenced product changed after rejected %s", action)
			}
		})
	}
}

func TestFingerprintReferenceCheckIsTenantScoped(t *testing.T) {
	store := setupAITestDB(t)
	seedDictionaryArsenal(t, store, "default", "finger", "finger.yaml", "Shared:\n  - body=shared\n")
	seedDictionaryArsenal(t, store, "default", "dir", "dir.yaml", "{}\n")
	seedDictionaryArsenal(t, store, "default", "workflow", "workflow.yaml", "{}\n")
	seedDictionaryArsenal(t, store, "other", "dir", "dir.yaml", "Shared:\n  - /admin\n")
	seedDictionaryArsenal(t, store, "other", "workflow", "workflow.yaml", "Shared:\n  type: [root]\n  pocs: []\n")

	ctx, recorder := newTenantContext(http.MethodPut, "/dictionaries/fingerprint/Shared")
	ctx.Request = httptest.NewRequest(http.MethodPut, "/dictionaries/fingerprint/Shared", strings.NewReader(`{"product":"Renamed","rules":["body=shared"]}`))
	ctx.Params = gin.Params{{Key: "product", Value: "Shared"}}
	updateFingerprintDict(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("tenant-scoped rename status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestDictionaryListEmptyReturnsArray(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "finger", "finger.yaml"),
		TenantID: "default",
		Type:     "finger",
		FileName: "finger.yaml",
		Content:  "{}\n",
		Hash:     "empty-finger",
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed fingerprint arsenal: %v", err)
	}
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "workflow", "workflow.yaml"),
		TenantID: "default",
		Type:     "workflow",
		FileName: "workflow.yaml",
		Content:  "{}\n",
		Hash:     "empty-workflow",
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed workflow arsenal: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/dictionaries/fingerprint", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/dictionaries/fingerprint", nil)
	getFingerprintDict(ctx)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "[]" {
		t.Fatalf("fingerprint dict response = %d %q, want 200 []", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = newTenantContextWithRole(http.MethodGet, "/dictionaries/workflow", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/dictionaries/workflow", nil)
	getWorkflowDict(ctx)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "[]" {
		t.Fatalf("workflow dict response = %d %q, want 200 []", recorder.Code, recorder.Body.String())
	}
}

func TestSaveAPIKeysConfigDoesNotBumpRuleVersionOrNotifyAgents(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.SystemConfig{Key: "rule_version", Value: "v-stable"}).Error; err != nil {
		t.Fatalf("seed rule version: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPut, "/config/api-keys", "admin", "9")
	ctx.Request = httptest.NewRequest(http.MethodPut, "/config/api-keys", strings.NewReader(`[{"provider":"quake","keys":["active-key"]}]`))
	saveApiKeysConfig(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected save API keys 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var arsenal db.Arsenal
	if err := store.First(&arsenal, "tenant_id = ? AND type = ? AND file_name = ?", "default", "apiconfig", "api-config.yaml").Error; err != nil {
		t.Fatalf("expected apiconfig arsenal: %v", err)
	}
	if !strings.Contains(arsenal.Content, "active-key") || arsenal.Hash == "" {
		t.Fatalf("unexpected apiconfig content/hash: content=%q hash=%q", arsenal.Content, arsenal.Hash)
	}
	var cfg db.SystemConfig
	if err := store.First(&cfg, "key = ?", "rule_version").Error; err != nil {
		t.Fatalf("load rule version: %v", err)
	}
	if cfg.Value != "v-stable" {
		t.Fatalf("save api-config should not bump rule_version, got %q", cfg.Value)
	}
}

func TestFingerprintDictMergesMaterializedRules(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "finger", "finger.yaml"),
		TenantID: "default",
		Type:     "finger",
		FileName: "finger.yaml",
		Content:  "{}\n",
		Hash:     "empty-finger",
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed fingerprint arsenal: %v", err)
	}
	if err := store.Create(&db.FingerprintRule{
		TenantID:    "default",
		ProductName: "StructuredProduct",
		RuleExpr:    `body="structured"`,
		Category:    "web",
		State:       "Approved",
		Enabled:     true,
	}).Error; err != nil {
		t.Fatalf("seed structured fingerprint rule: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/dictionaries/fingerprint", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/dictionaries/fingerprint", nil)
	getFingerprintDict(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("fingerprint dict response = %d %q, want 200", recorder.Code, recorder.Body.String())
	}
	var resp []FingerprintItem
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode fingerprint response: %v", err)
	}
	if len(resp) != 1 || resp[0].Product != "StructuredProduct" || len(resp[0].Rules) != 1 || resp[0].Rules[0] != `body="structured"` {
		t.Fatalf("expected materialized fingerprint rule in full dictionary, got %+v", resp)
	}
}

func TestLoadFingerprintSummaryRulesScopesTenantAndEnabledState(t *testing.T) {
	store := setupAITestDB(t)
	for _, rule := range []db.FingerprintRule{
		{TenantID: "tenant-a", ProductName: "SharedProduct", RuleExpr: `body="a"`, State: "Approved", Enabled: true},
		{TenantID: "tenant-a", ProductName: "SharedProduct", RuleExpr: `title="disabled"`, State: "Approved", Enabled: false},
		{TenantID: "tenant-b", ProductName: "SharedProduct", RuleExpr: `body="tenant-b"`, State: "Approved", Enabled: true},
	} {
		if err := store.Create(&rule).Error; err != nil {
			t.Fatalf("seed fingerprint rule: %v", err)
		}
	}
	if err := store.Model(&db.FingerprintRule{}).
		Where("tenant_id = ? AND product_name = ? AND rule_expr = ?", "tenant-a", "SharedProduct", `title="disabled"`).
		Update("enabled", false).Error; err != nil {
		t.Fatalf("disable fingerprint rule: %v", err)
	}

	rules, err := loadFingerprintSummaryRules("tenant-a", "SharedProduct", false)
	if err != nil {
		t.Fatalf("load enabled rules: %v", err)
	}
	if len(rules) != 1 || rules[0] != `body="a"` {
		t.Fatalf("enabled tenant rules = %v", rules)
	}

	allRules, err := loadFingerprintSummaryRules("tenant-a", "SharedProduct", true)
	if err != nil {
		t.Fatalf("load all rules: %v", err)
	}
	if len(allRules) != 2 || allRules[0] != `body="a"` || allRules[1] != `title="disabled"` {
		t.Fatalf("all tenant rules = %v", allRules)
	}
}

func TestWorkflowDictLiteUsesSummaryPagination(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.WorkflowProductSummary{}); err != nil {
		t.Fatalf("automigrate summary: %v", err)
	}
	if err := store.Create(&db.WorkflowProductSummary{
		TenantID:             "default",
		ProductName:          "DemoProduct",
		MatchTypes:           `["root"]`,
		PocNames:             `["demo-poc"]`,
		PocCount:             1,
		MissingPocNames:      `[]`,
		MissingPocCount:      0,
		FingerprintBound:     true,
		FingerprintRuleCount: 2,
		State:                "Approved",
		Enabled:              true,
		Version:              3,
	}).Error; err != nil {
		t.Fatalf("seed summary: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/dictionaries/workflow?lite=1&page=1&page_size=1&q=demo", "operator", "9")
	getWorkflowDict(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("workflow lite status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Items []workflowSummaryResponse `json:"items"`
		Total int64                     `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].Product != "DemoProduct" || !resp.Items[0].FingerprintBound {
		t.Fatalf("unexpected workflow lite response: %+v", resp)
	}
}

func TestWorkflowDictLiteStatsUseAllMatchingRows(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.WorkflowProductSummary{}); err != nil {
		t.Fatalf("automigrate summary: %v", err)
	}
	rows := []db.WorkflowProductSummary{
		{
			TenantID:             "default",
			ProductName:          "Alpha",
			MatchTypes:           `["root"]`,
			PocNames:             `["alpha-a","alpha-b"]`,
			PocCount:             2,
			MissingPocNames:      `[]`,
			MissingPocCount:      0,
			FingerprintBound:     true,
			FingerprintRuleCount: 4,
			State:                "Approved",
			Enabled:              true,
		},
		{
			TenantID:             "default",
			ProductName:          "Beta",
			MatchTypes:           `["root"]`,
			PocNames:             `["beta-a","beta-b","beta-c"]`,
			PocCount:             3,
			MissingPocNames:      `["beta-c"]`,
			MissingPocCount:      1,
			FingerprintBound:     false,
			FingerprintRuleCount: 0,
			State:                "Approved",
			Enabled:              true,
		},
		{
			TenantID:             "default",
			ProductName:          "Gamma",
			MatchTypes:           `["base"]`,
			PocNames:             `["gamma-a"]`,
			PocCount:             1,
			MissingPocNames:      `["gamma-a"]`,
			MissingPocCount:      1,
			FingerprintBound:     false,
			FingerprintRuleCount: 0,
			State:                "Approved",
			Enabled:              true,
		},
	}
	if err := store.Create(&rows).Error; err != nil {
		t.Fatalf("seed summaries: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/dictionaries/workflow?lite=1&page=1&page_size=1&scope=specific", "operator", "9")
	getWorkflowDict(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("workflow lite status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Items []workflowSummaryResponse    `json:"items"`
		Total int64                        `json:"total"`
		Stats workflowSummaryStatsResponse `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Items) != 1 || resp.Total != 3 {
		t.Fatalf("expected first page of 3 matching rows, got %+v", resp)
	}
	if resp.Stats.Total != 3 || resp.Stats.FingerprintMissing != 2 || resp.Stats.POCMissing != 2 || resp.Stats.TotalPOCs != 6 || resp.Stats.FingerprintRules != 4 {
		t.Fatalf("expected all-row workflow stats, got %+v", resp.Stats)
	}
}

func TestGetArsenalReturnsSingleContent(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "poc", "demo.yaml"),
		TenantID: "default",
		Type:     "poc",
		FileName: "demo.yaml",
		Content:  "id: demo\n",
		Hash:     "hash",
		State:    "Draft",
		Version:  2,
	}).Error; err != nil {
		t.Fatalf("seed arsenal: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/arsenals/poc/demo.yaml", "operator", "9")
	ctx.Params = gin.Params{{Key: "type", Value: "poc"}, {Key: "filename", Value: "demo.yaml"}}
	getArsenal(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get arsenal status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp db.Arsenal
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode arsenal: %v", err)
	}
	if resp.Content != "id: demo\n" || resp.FileName != "demo.yaml" {
		t.Fatalf("unexpected arsenal: %+v", resp)
	}
}
