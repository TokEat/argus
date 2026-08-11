package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

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
