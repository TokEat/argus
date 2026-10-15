package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/expworkspace"
	"github.com/P0lar1ght/argus/server/internal/storage"
	"github.com/gin-gonic/gin"
)

func TestConfirmCopilotActionRejectsExpDraftWithoutUserAuthorization(t *testing.T) {
	store := setupAITestDB(t)
	objects, err := storage.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := expworkspace.NewService(store, objects, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldWorkspace := routerRuntime().EXPWorkspace
	routerRuntime().EXPWorkspace = service
	t.Cleanup(func() { routerRuntime().EXPWorkspace = oldWorkspace })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/ai/actions/confirm", func(c *gin.Context) {
		c.Set("tenant", "default")
		c.Set("user_id", "u1")
		c.Set("role", "operator")
		c.Set("exp_authorized", false)
		confirmCopilotAction(c)
	})
	payload, _ := json.Marshal(map[string]interface{}{"action": map[string]interface{}{
		"action_type": "create_exp_draft", "required_role": "operator",
		"params": map[string]interface{}{"name": "unauthorized-exp", "content": testYakshaExpContent},
	}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/actions/confirm", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "EXP access requires user-level authorization") {
		t.Fatalf("expected fail-closed EXP authorization error, got %d body=%s", rec.Code, rec.Body.String())
	}
	var count int64
	if err := store.Model(&db.Exp{}).Where("tenant_id = ?", "default").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unauthorized Copilot action created %d EXP rows", count)
	}
}
