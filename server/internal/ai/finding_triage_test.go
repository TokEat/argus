package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func triageTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.SystemConfig{}, &db.Vulnerability{}, &db.AIFindingReview{}, &db.TaskAudit{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return store
}

func seedTriageAIConfig(t *testing.T, store *gorm.DB) {
	t.Helper()
	now := time.Now()
	for _, row := range []db.SystemConfig{
		{Key: ConfigKeyBaseURL, Value: "http://llm.local/v1", UpdatedAt: now},
		{Key: ConfigKeyAPIKey, Value: "secret", UpdatedAt: now},
		{Key: ConfigKeyModel, Value: "test-model", UpdatedAt: now},
	} {
		if err := store.Save(&row).Error; err != nil {
			t.Fatalf("seed ai config: %v", err)
		}
	}
}

func seedVuln(t *testing.T, store *gorm.DB, mutate func(*db.Vulnerability)) db.Vulnerability {
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

func reloadVuln(t *testing.T, store *gorm.DB, id uint) db.Vulnerability {
	t.Helper()
	var v db.Vulnerability
	if err := store.First(&v, id).Error; err != nil {
		t.Fatalf("reload vuln: %v", err)
	}
	return v
}

func TestTriageRequiresConfig(t *testing.T) {
	store := triageTestDB(t)
	vuln := seedVuln(t, store, nil)
	analyzer := TriageAnalyzer{DB: store, Client: &fakeChatClient{raw: `{"verdict":"confirmed","confidence":0.9,"reason":"x"}`}}
	_, err := analyzer.Triage(context.Background(), vuln, TriageOptions{})
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("expected ErrMissingConfig, got %v", err)
	}
	if got := reloadVuln(t, store, vuln.ID).AITriagedAt; got != nil {
		t.Fatalf("ai_triaged_at should stay nil so the worker retries, got %v", got)
	}
}

func TestTriageStaticPreCheckEmptyResponse(t *testing.T) {
	store := triageTestDB(t)
	vuln := seedVuln(t, store, func(v *db.Vulnerability) { v.Response = "" })
	client := &fakeChatClient{raw: `{"verdict":"confirmed"}`}
	analyzer := TriageAnalyzer{DB: store, Client: client}
	v, err := analyzer.Triage(context.Background(), vuln, TriageOptions{})
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("static pre-check must not call LLM, calls=%d", client.calls)
	}
	if v.Verdict != VerdictUncertain {
		t.Fatalf("verdict=%s, want uncertain", v.Verdict)
	}
	updated := reloadVuln(t, store, vuln.ID)
	if updated.AITriagedAt == nil || updated.AIStatus != VerdictUncertain {
		t.Fatalf("vuln not marked triaged: %+v", updated)
	}
	var review db.AIFindingReview
	if err := store.First(&review, v.ReviewID).Error; err != nil {
		t.Fatalf("review not persisted: %v", err)
	}
	if review.Provider != verdictProviderStatic {
		t.Fatalf("provider=%s, want static", review.Provider)
	}
}

func TestTriageStaticPreCheckInfoSeverity(t *testing.T) {
	store := triageTestDB(t)
	vuln := seedVuln(t, store, func(v *db.Vulnerability) { v.Severity = "info" })
	client := &fakeChatClient{raw: `{"verdict":"confirmed"}`}
	analyzer := TriageAnalyzer{DB: store, Client: client}
	v, err := analyzer.Triage(context.Background(), vuln, TriageOptions{})
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	if client.calls != 0 || v.Verdict != VerdictUncertain {
		t.Fatalf("info severity should short-circuit to uncertain without LLM, calls=%d verdict=%s", client.calls, v.Verdict)
	}
}

func TestTriageConfirmedPersistsAndWritesAudit(t *testing.T) {
	store := triageTestDB(t)
	seedTriageAIConfig(t, store)
	vuln := seedVuln(t, store, nil)
	client := &fakeChatClient{raw: `{"verdict":"confirmed","confidence":0.93,"reason":"响应包含明确漏洞证据"}`}
	analyzer := TriageAnalyzer{DB: store, Client: client}
	v, err := analyzer.Triage(context.Background(), vuln, TriageOptions{})
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	if v.Verdict != VerdictConfirmed || v.Cached || v.ReviewID == 0 {
		t.Fatalf("unexpected verdict: %+v", v)
	}
	if client.calls != 1 {
		t.Fatalf("expected 1 LLM call, got %d", client.calls)
	}
	updated := reloadVuln(t, store, vuln.ID)
	if updated.AIStatus != VerdictConfirmed || updated.AIConfidence != 0.93 || updated.AIReason == "" || updated.AIReviewID != v.ReviewID {
		t.Fatalf("vuln AI columns not written back: %+v", updated)
	}
	if updated.Status != "open" {
		t.Fatalf("confirmed verdict must not change status, got %s", updated.Status)
	}
	var audits int64
	store.Model(&db.TaskAudit{}).Where("action = ? AND root_task_id = ?", "ai_triage", "root-1").Count(&audits)
	if audits != 1 {
		t.Fatalf("expected 1 ai_triage audit, got %d", audits)
	}
}

func TestTriageLikelyFPAutoSuppress(t *testing.T) {
	store := triageTestDB(t)
	seedTriageAIConfig(t, store)
	now := time.Now()
	if err := store.Save(&db.SystemConfig{Key: TriageConfigKeyAutoSuppress, Value: "true", UpdatedAt: now}).Error; err != nil {
		t.Fatal(err)
	}
	vuln := seedVuln(t, store, nil)
	client := &fakeChatClient{raw: `{"verdict":"likely_false_positive","confidence":0.91,"reason":"响应为正常登录页"}`}
	analyzer := TriageAnalyzer{DB: store, Client: client}
	v, err := analyzer.Triage(context.Background(), vuln, TriageOptions{})
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	if v.Verdict != VerdictLikelyFP {
		t.Fatalf("verdict=%s", v.Verdict)
	}
	updated := reloadVuln(t, store, vuln.ID)
	if updated.Status != "false_positive" {
		t.Fatalf("auto suppress should set status=false_positive, got %s", updated.Status)
	}
}

func TestTriageLikelyFPNoAutoSuppressByDefault(t *testing.T) {
	store := triageTestDB(t)
	seedTriageAIConfig(t, store)
	vuln := seedVuln(t, store, nil)
	client := &fakeChatClient{raw: `{"verdict":"likely_false_positive","confidence":0.99,"reason":"证据不足"}`}
	analyzer := TriageAnalyzer{DB: store, Client: client}
	if _, err := analyzer.Triage(context.Background(), vuln, TriageOptions{}); err != nil {
		t.Fatalf("triage: %v", err)
	}
	updated := reloadVuln(t, store, vuln.ID)
	if updated.Status != "open" {
		t.Fatalf("default must keep status open, got %s", updated.Status)
	}
	if updated.AIStatus != VerdictLikelyFP {
		t.Fatalf("ai_status should still record likely_false_positive, got %s", updated.AIStatus)
	}
}

func TestTriageCacheHitAvoidsDuplicateLLMCall(t *testing.T) {
	store := triageTestDB(t)
	seedTriageAIConfig(t, store)
	first := seedVuln(t, store, nil)
	client := &fakeChatClient{raw: `{"verdict":"confirmed","confidence":0.9,"reason":"ok"}`}
	analyzer := TriageAnalyzer{DB: store, Client: client}
	if _, err := analyzer.Triage(context.Background(), first, TriageOptions{}); err != nil {
		t.Fatalf("first triage: %v", err)
	}
	// Same target+plugin+response → same evidence hash, but a different project
	// keeps the (project_id,target,plugin) unique index satisfied.
	second := seedVuln(t, store, func(v *db.Vulnerability) { v.ProjectID = "proj-2" })
	v, err := analyzer.Triage(context.Background(), second, TriageOptions{})
	if err != nil {
		t.Fatalf("second triage: %v", err)
	}
	if !v.Cached {
		t.Fatalf("expected cached verdict, got %+v", v)
	}
	if client.calls != 1 {
		t.Fatalf("cache hit must not call LLM again, calls=%d", client.calls)
	}
	if got := reloadVuln(t, store, second.ID).AITriagedAt; got == nil {
		t.Fatalf("cached verdict should still mark the second vuln triaged")
	}
}

func TestTriageBadJSONLeavesUntriagedForRetry(t *testing.T) {
	store := triageTestDB(t)
	seedTriageAIConfig(t, store)
	vuln := seedVuln(t, store, nil)
	client := &fakeChatClient{raw: `this is not json`}
	analyzer := TriageAnalyzer{DB: store, Client: client}
	if _, err := analyzer.Triage(context.Background(), vuln, TriageOptions{}); err == nil {
		t.Fatal("expected parse error")
	}
	if got := reloadVuln(t, store, vuln.ID).AITriagedAt; got != nil {
		t.Fatalf("failed triage must leave ai_triaged_at nil for retry, got %v", got)
	}
	var reviews int64
	store.Model(&db.AIFindingReview{}).Where("vulnerability_id = ?", vuln.ID).Count(&reviews)
	if reviews != 0 {
		t.Fatalf("no review should be persisted on LLM failure, got %d", reviews)
	}
}
