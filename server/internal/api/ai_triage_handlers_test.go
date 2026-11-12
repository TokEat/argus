package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	aipkg "github.com/TokEat/argus/server/internal/ai"
	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type fakeTriageHTTPClient struct {
	calls int
	raw   string
}

func (f *fakeTriageHTTPClient) CompleteJSON(ctx context.Context, cfg aipkg.Config, messages []aipkg.ChatMessage) (string, error) {
	f.calls++
	return f.raw, nil
}
func (f *fakeTriageHTTPClient) CompleteWithTools(ctx context.Context, cfg aipkg.Config, messages []aipkg.ChatMessage, tools []aipkg.ToolDefinition) (string, []aipkg.ToolCall, error) {
	return f.raw, nil, nil
}
func (f *fakeTriageHTTPClient) StreamWithTools(ctx context.Context, cfg aipkg.Config, messages []aipkg.ChatMessage, tools []aipkg.ToolDefinition, onToken func(string), onToolCall func(aipkg.ToolCall)) (string, []aipkg.ToolCall, error) {
	return f.raw, nil, nil
}

func seedTriageVuln(t *testing.T, store *gorm.DB, mutate func(*db.Vulnerability)) db.Vulnerability {
	t.Helper()
	v := db.Vulnerability{
		TenantID:   "default",
		ProjectID:  "proj-1",
		RootTaskID: "root-1",
		Target:     "http://target.local",
		Plugin:     "nacos-version",
		Severity:   "high",
		Status:     "open",
		Response:   "HTTP/1.1 200 OK\r\n\r\nbody",
	}
	if mutate != nil {
		mutate(&v)
	}
	if err := store.Create(&v).Error; err != nil {
		t.Fatalf("seed vuln: %v", err)
	}
	return v
}

func uintToStr(id uint) string {
	return strconv.FormatUint(uint64(id), 10)
}

func TestGetVulnAIReview(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AIFindingReview{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	vuln := seedTriageVuln(t, store, nil)
	if err := store.Create(&db.AIFindingReview{
		TenantID: "default", VulnerabilityID: vuln.ID, Verdict: aipkg.VerdictConfirmed,
		Confidence: 0.9, Reason: "证据充分", Model: "m", CreatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed review: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/vulns/1/ai-review", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	getVulnAIReview(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET ai-review=%d %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		AIStatus string              `json:"ai_status"`
		Reviews  []db.AIFindingReview `json:"reviews"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Reviews) != 1 || body.Reviews[0].Verdict != aipkg.VerdictConfirmed {
		t.Fatalf("unexpected reviews: %+v", body.Reviews)
	}
}

func TestGetVulnAIReviewNotFound(t *testing.T) {
	store := setupAITestDB(t)
	_ = store
	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/vulns/999/ai-review", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: "999"}}
	getVulnAIReview(ctx)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}

func TestRetriggerVulnAIReview(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AIFindingReview{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	now := time.Now()
	for _, row := range []db.SystemConfig{
		{Key: "ai_base_url", Value: "http://llm.local/v1", UpdatedAt: now},
		{Key: "ai_api_key", Value: "k", UpdatedAt: now},
		{Key: "ai_model", Value: "m", UpdatedAt: now},
	} {
		if err := store.Save(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	vuln := seedTriageVuln(t, store, nil)

	fake := &fakeTriageHTTPClient{raw: `{"verdict":"likely_false_positive","confidence":0.9,"reason":"证据不足"}`}
	old := aiTriageChatClient
	aiTriageChatClient = fake
	t.Cleanup(func() { aiTriageChatClient = old })

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/vulns/1/ai-review", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: uintToStr(vuln.ID)}}
	retriggerVulnAIReview(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST ai-review=%d %s", recorder.Code, recorder.Body.String())
	}
	if fake.calls != 1 {
		t.Fatalf("expected 1 forced LLM call, got %d", fake.calls)
	}
	var updated db.Vulnerability
	if err := store.First(&updated, vuln.ID).Error; err != nil {
		t.Fatal(err)
	}
	if updated.AIStatus != aipkg.VerdictLikelyFP || updated.Status != "open" {
		t.Fatalf("unexpected vuln after retrigger: %+v", updated)
	}
}

func TestOverrideVulnAIReviewRestoresSuppressed(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AIFindingReview{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	vuln := seedTriageVuln(t, store, func(v *db.Vulnerability) {
		v.Status = "false_positive"
		v.AIStatus = aipkg.VerdictLikelyFP
	})
	review := db.AIFindingReview{
		TenantID: "default", VulnerabilityID: vuln.ID, Verdict: aipkg.VerdictLikelyFP,
		Confidence: 0.9, Reason: "AI 判定误报", Model: "m", CreatedAt: time.Now(),
	}
	if err := store.Create(&review).Error; err != nil {
		t.Fatalf("seed review: %v", err)
	}

	body := `{"verdict":"confirmed","reason":"人工验证为真实漏洞"}`
	ctx, recorder := newTenantContextWithRole(http.MethodPatch, "/vulns/1/ai-review", "operator", "u1")
	ctx.Params = gin.Params{{Key: "id", Value: uintToStr(vuln.ID)}}
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/vulns/1/ai-review", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	overrideVulnAIReview(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("PATCH ai-review=%d %s", recorder.Code, recorder.Body.String())
	}

	var updated db.Vulnerability
	if err := store.First(&updated, vuln.ID).Error; err != nil {
		t.Fatal(err)
	}
	if updated.AIStatus != aipkg.VerdictConfirmed || updated.Status != "open" {
		t.Fatalf("override must set ai_status=confirmed and restore open, got %+v", updated)
	}
	var saved db.AIFindingReview
	if err := store.First(&saved, review.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.OverrideVerdict != aipkg.VerdictConfirmed || saved.OverriddenBy != "u1" {
		t.Fatalf("override not recorded on review: %+v", saved)
	}
	var audits int64
	store.Model(&db.TaskAudit{}).Where("action = ? AND operator_id = ?", "ai_triage_override", "u1").Count(&audits)
	if audits != 1 {
		t.Fatalf("expected 1 override audit, got %d", audits)
	}
}

func TestOverrideVulnAIReviewRejectsInvalidVerdict(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AIFindingReview{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	vuln := seedTriageVuln(t, store, nil)
	ctx, recorder := newTenantContextWithRole(http.MethodPatch, "/vulns/1/ai-review", "operator", "u1")
	ctx.Params = gin.Params{{Key: "id", Value: uintToStr(vuln.ID)}}
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/vulns/1/ai-review", strings.NewReader(`{"verdict":"bogus"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	overrideVulnAIReview(ctx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
}

func TestOverrideVulnAIReviewWithoutReview(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AIFindingReview{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	vuln := seedTriageVuln(t, store, nil)
	ctx, recorder := newTenantContextWithRole(http.MethodPatch, "/vulns/1/ai-review", "operator", "u1")
	ctx.Params = gin.Params{{Key: "id", Value: uintToStr(vuln.ID)}}
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/vulns/1/ai-review", strings.NewReader(`{"verdict":"confirmed"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	overrideVulnAIReview(ctx)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}
