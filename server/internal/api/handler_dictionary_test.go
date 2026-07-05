package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
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
