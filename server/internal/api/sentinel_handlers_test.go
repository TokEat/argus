package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/server/internal/sentinel"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func setupSentinelAPIDB(t *testing.T) *gorm.DB {
	t.Helper()
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.EgressBanEvent{}, &db.NodeBan{}); err != nil {
		t.Fatalf("migrate sentinel models: %v", err)
	}
	return store
}

func seedSentinelEvent(t *testing.T, store *gorm.DB, mutate func(*db.EgressBanEvent)) db.EgressBanEvent {
	t.Helper()
	ev := db.EgressBanEvent{
		TenantID: "default", RootTaskID: "root-1", ProjectID: "p1",
		Target: "10.0.0.1", Host: "10.0.0.1", AgentID: "agent-bad",
		SignalType: sentinel.SignalHomogeneity, Classification: sentinel.ClassBanned,
		RecommendedAction: sentinel.ActionBackoff, Status: sentinel.EventOpen,
	}
	if mutate != nil {
		mutate(&ev)
	}
	if err := store.Create(&ev).Error; err != nil {
		t.Fatalf("seed sentinel event: %v", err)
	}
	return ev
}

func TestListSentinelEvents(t *testing.T) {
	store := setupSentinelAPIDB(t)
	seedSentinelEvent(t, store, nil)
	seedSentinelEvent(t, store, func(ev *db.EgressBanEvent) {
		ev.Target = "10.0.0.2"
		ev.Status = sentinel.EventExecuted
	})
	// Other tenant must not leak in.
	seedSentinelEvent(t, store, func(ev *db.EgressBanEvent) {
		ev.TenantID = "other-tenant"
		ev.Target = "10.0.0.3"
	})

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/sentinel/events?page=1&page_size=20", "operator", "1")
	listSentinelEvents(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list events=%d %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Items []db.EgressBanEvent `json:"items"`
		Total int64               `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 2 || len(body.Items) != 2 {
		t.Fatalf("tenant scoping failed, want 2 default-tenant events, got total=%d items=%d", body.Total, len(body.Items))
	}

	// Filter by status.
	ctx2, rec2 := newTenantContextWithRole(http.MethodGet, "/sentinel/events?status=executed", "operator", "1")
	listSentinelEvents(ctx2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("filtered list=%d", rec2.Code)
	}
	var filtered struct {
		Items []db.EgressBanEvent `json:"items"`
		Total int64               `json:"total"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &filtered); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if filtered.Total != 1 || filtered.Items[0].Target != "10.0.0.2" {
		t.Fatalf("status filter failed: %+v", filtered)
	}
}

func TestExecuteSentinelEventBackoff(t *testing.T) {
	store := setupSentinelAPIDB(t)
	ev := seedSentinelEvent(t, store, nil)

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/sentinel/events/1/execute", "operator", "admin-1")
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	executeSentinelEvent(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("execute=%d %s", recorder.Code, recorder.Body.String())
	}
	var updated db.EgressBanEvent
	if err := store.First(&updated, ev.ID).Error; err != nil {
		t.Fatal(err)
	}
	if updated.Status != sentinel.EventExecuted || updated.ExecutedBy != "admin-1" {
		t.Fatalf("event not executed by admin: %+v", updated)
	}
	var ban db.NodeBan
	if err := store.Where("target = ? AND agent_id = ?", "10.0.0.1", "agent-bad").First(&ban).Error; err != nil {
		t.Fatalf("backoff must record ban memory: %v", err)
	}
}

func TestExecuteSentinelEventNotFound(t *testing.T) {
	store := setupSentinelAPIDB(t)
	_ = store
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/sentinel/events/999/execute", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: "999"}}
	executeSentinelEvent(ctx)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}

func TestExecuteSentinelEventConflictWhenNotOpen(t *testing.T) {
	store := setupSentinelAPIDB(t)
	ev := seedSentinelEvent(t, store, func(ev *db.EgressBanEvent) { ev.Status = sentinel.EventExecuted })
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/sentinel/events/1/execute", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	executeSentinelEvent(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", recorder.Code)
	}
	_ = ev
}

func TestDismissSentinelEvent(t *testing.T) {
	store := setupSentinelAPIDB(t)
	ev := seedSentinelEvent(t, store, nil)

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/sentinel/events/1/dismiss", "operator", "admin-1")
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	dismissSentinelEvent(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("dismiss=%d %s", recorder.Code, recorder.Body.String())
	}
	var updated db.EgressBanEvent
	if err := store.First(&updated, ev.ID).Error; err != nil {
		t.Fatal(err)
	}
	if updated.Status != sentinel.EventDismissed || updated.ExecutedBy != "admin-1" {
		t.Fatalf("event not dismissed: %+v", updated)
	}

	// Dismissing again → 409.
	ctx2, rec2 := newTenantContextWithRole(http.MethodPost, "/sentinel/events/1/dismiss", "operator", "1")
	ctx2.Params = gin.Params{{Key: "id", Value: "1"}}
	dismissSentinelEvent(ctx2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second dismiss expected 409, got %d", rec2.Code)
	}
}

func TestDismissSentinelEventTenantIsolated(t *testing.T) {
	store := setupSentinelAPIDB(t)
	ev := seedSentinelEvent(t, store, nil)
	// A different tenant trying to dismiss must not affect the row.
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/sentinel/events/1/dismiss", "operator", "1")
	ctx.Set("tenant", "other-tenant")
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	dismissSentinelEvent(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("cross-tenant dismiss expected 409, got %d", recorder.Code)
	}
	var reloaded db.EgressBanEvent
	if err := store.First(&reloaded, ev.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != sentinel.EventOpen {
		t.Fatalf("event must stay open after cross-tenant dismiss: %+v", reloaded)
	}
}

func TestGetSentinelConfigDefaults(t *testing.T) {
	store := setupSentinelAPIDB(t)
	_ = store
	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/sentinel/config", "operator", "1")
	getSentinelConfig(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get config=%d", recorder.Code)
	}
	var body struct {
		Enabled         bool `json:"enabled"`
		AutoExecute     bool `json:"auto_execute"`
		CooldownMinutes int  `json:"cooldown_minutes"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Enabled || body.AutoExecute || body.CooldownMinutes != 10 {
		t.Fatalf("defaults wrong: %+v (want enabled=true auto=false cooldown=10)", body)
	}
}

func TestSaveSentinelConfigRoundTrip(t *testing.T) {
	store := setupSentinelAPIDB(t)
	_ = store
	body := `{"enabled":false,"auto_execute":true,"cooldown_minutes":30}`
	ctx, recorder := newTenantContextWithRole(http.MethodPut, "/sentinel/config", "admin", "1")
	ctx.Request = httptest.NewRequest(http.MethodPut, "/sentinel/config", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	saveSentinelConfig(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("save config=%d %s", recorder.Code, recorder.Body.String())
	}
	var updated struct {
		Enabled         bool `json:"enabled"`
		AutoExecute     bool `json:"auto_execute"`
		CooldownMinutes int  `json:"cooldown_minutes"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if updated.Enabled || !updated.AutoExecute || updated.CooldownMinutes != 30 {
		t.Fatalf("config not persisted: %+v", updated)
	}
}

func TestSaveSentinelConfigRejectsBadCooldown(t *testing.T) {
	store := setupSentinelAPIDB(t)
	_ = store
	body := `{"cooldown_minutes":0}`
	ctx, recorder := newTenantContextWithRole(http.MethodPut, "/sentinel/config", "admin", "1")
	ctx.Request = httptest.NewRequest(http.MethodPut, "/sentinel/config", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	saveSentinelConfig(ctx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for cooldown<1, got %d", recorder.Code)
	}
}
