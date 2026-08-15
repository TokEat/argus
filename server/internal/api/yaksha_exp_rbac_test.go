package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/expworkspace"
	"github.com/gin-gonic/gin"
)

func TestYakshaEXPRiskConfirmationErrorIsActionable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	writeEXPWorkspaceError(context, expworkspace.ErrRiskConfirmationRequired)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != expworkspace.ErrRiskConfirmationRequired.Error() {
		t.Fatalf("body=%v", body)
	}
}

func TestYakshaEXPWorkspacePermissionMatrix(t *testing.T) {
	tests := []struct{ method, path, want string }{
		{http.MethodGet, "/api/v1/exps", "operator"},
		{http.MethodPost, "/api/v1/exps/exp-1/revisions/2/runs", "operator"},
		{http.MethodGet, "/api/v1/exp-assets/dictionary/versions/1/content", "operator"},
		{http.MethodPost, "/api/v1/exps/exp-1/revisions/2/publish", "admin"},
		{http.MethodGet, "/api/v1/exps/exp-1/audits", "admin"},
		{http.MethodPut, "/api/v1/exps/exp-1/risk-waiver", "admin"},
	}
	for _, tt := range tests {
		if got := matchPermission(tt.method, tt.path); got != tt.want {
			t.Fatalf("%s %s expected %s, got %s", tt.method, tt.path, tt.want, got)
		}
	}
}

func TestYakshaEXPRiskRanking(t *testing.T) {
	if riskRank("critical") <= riskRank("high") || riskRank("high") <= riskRank("medium") || riskRank("medium") <= riskRank("low") {
		t.Fatal("EXP risk levels must be strictly ordered")
	}
}

func TestYakshaEXPResponsesExposeStructuredJSONWithoutObjectKeys(t *testing.T) {
	revision := db.ExpRevision{ExpID: "exp", Revision: 1, SourceObjectKey: "private/object/key", SourceSHA256: "hash", CLISchema: `[{"name":"target"}]`, InspectSummary: `{"status":"Succeeded"}`, ValidateSummary: `{"status":"Succeeded"}`}
	response := expRevisionResponse(revision)
	if _, ok := response["cli_schema"].([]any); !ok {
		t.Fatalf("cli_schema should be structured JSON: %#v", response["cli_schema"])
	}
	if _, exposed := response["source_object_key"]; exposed {
		t.Fatal("revision response exposed private object key")
	}
	now := time.Now().UTC()
	run := expRunResponse(db.ExpRun{ID: "run", ArtifactObjectKey: "private/run/key", ResultSummary: `{"status":"Succeeded"}`, StartedAt: now})
	if _, ok := run["result_summary"].(map[string]any); !ok {
		t.Fatalf("result_summary should be structured JSON: %#v", run["result_summary"])
	}
	if _, exposed := run["artifact_object_key"]; exposed {
		t.Fatal("run response exposed private object key")
	}
}

func TestYakshaEXPWorkspaceRequiresUserAuthorization(t *testing.T) {
	store := setupAITestDB(t)
	for _, user := range []db.User{
		{ID: 1, TenantID: "tenant-a", Username: "authorized", Role: "operator", Status: "active", ExpAuthorized: true},
		{ID: 2, TenantID: "tenant-a", Username: "plain", Role: "operator", Status: "active", ExpAuthorized: false},
	} {
		if err := store.Create(&user).Error; err != nil {
			t.Fatal(err)
		}
	}
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		userID string
		want   int
	}{{"1", http.StatusOK}, {"2", http.StatusForbidden}} {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("tenant", "tenant-a")
			c.Set("role", "operator")
			c.Set("user_id", tt.userID)
			c.Next()
		})
		router.Use(RBACMiddleware())
		router.GET("/api/v1/exps", func(c *gin.Context) { c.Status(http.StatusOK) })
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/exps", nil))
		if recorder.Code != tt.want {
			t.Fatalf("user %s status=%d want=%d body=%s", tt.userID, recorder.Code, tt.want, recorder.Body.String())
		}
	}
}
