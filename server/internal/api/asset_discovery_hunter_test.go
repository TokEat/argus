package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/assetdiscovery"
	"github.com/user/dddd-server/internal/db"
)

const testHunterAPIKey = "fake-hunter-key-for-tests"

type fakeHunterQueryProvider struct {
	result     assetdiscovery.Result
	err        error
	calls      int
	credential assetdiscovery.HunterCredential
	query      assetdiscovery.HunterQuery
}

func (f *fakeHunterQueryProvider) Search(_ context.Context, credential assetdiscovery.HunterCredential, query assetdiscovery.HunterQuery) (assetdiscovery.Result, error) {
	f.calls++
	f.credential = credential
	f.query = query
	return f.result, f.err
}

func installFakeHunterProvider(t *testing.T, provider HunterQueryProvider) {
	t.Helper()
	old := routerRuntime().AssetDiscoveryHunter
	routerRuntime().AssetDiscoveryHunter = provider
	t.Cleanup(func() { routerRuntime().AssetDiscoveryHunter = old })
}

func seedHunterProjectAndConfig(t *testing.T, projectTenant, configTenant, state string) (*db.Project, string) {
	t.Helper()
	project := &db.Project{
		ID:          "project-hunter-preview",
		TenantID:    projectTenant,
		OwnerUserID: "9",
		Name:        "Hunter preview test",
		Status:      "active",
	}
	if err := db.DB.Create(project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	content := fmt.Sprintf("hunter:\n  - %s\n", testHunterAPIKey)
	if err := db.DB.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID(configTenant, "apiconfig", "api-config.yaml"),
		TenantID: configTenant,
		Type:     "apiconfig",
		FileName: "api-config.yaml",
		Content:  content,
		Hash:     "legacy-config-hash",
		State:    state,
		Version:  8,
	}).Error; err != nil {
		t.Fatalf("seed api config: %v", err)
	}
	return project, content
}

func invokeHunterPreview(t *testing.T, projectID, body, tenant, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/hunter/query"
	ctx, recorder := newTenantContextWithRole(http.MethodPost, path, role, userID)
	ctx.Set("tenant", tenant)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	queryProjectHunterPreview(ctx)
	return recorder
}

func TestQueryProjectHunterPreviewUsesTenantCredentialAndSanitizedAudit(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project, configContent := seedHunterProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeHunterQueryProvider{result: assetdiscovery.Result{
		Provider:      "hunter",
		ProviderTotal: 5,
		SkippedRows:   1,
		Truncated:     true,
		Assets: []assetdiscovery.Asset{{
			Target: "https://preview.example.invalid:443", Domain: "preview.example.invalid", Port: 443,
			Protocol: "https", Title: "Preview", Country: "CN", City: "Shenzhen", Company: "Example", StatusCode: 200, Source: "hunter",
		}},
	}}
	installFakeHunterProvider(t, provider)

	expression := `domain="scope.example.invalid"`
	recorder := invokeHunterPreview(t, project.ID, fmt.Sprintf(`{"expression":%q,"limit":50}`, expression), "default", "operator", "9")
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 1 || provider.credential.APIKey != testHunterAPIKey || provider.query.Expression != expression || provider.query.Limit != 50 || provider.query.PageSize != 0 {
		t.Fatalf("unexpected provider invocation: calls=%d credential=%+v query=%+v", provider.calls, provider.credential, provider.query)
	}

	var response projectDiscoveryQueryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.SchemaVersion != assetDiscoveryPreviewSchema || response.ProjectID != project.ID || response.AuditID == 0 || response.Provider != "hunter" || len(response.Assets) != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
	for _, sensitive := range []string{expression, testHunterAPIKey} {
		if strings.Contains(recorder.Body.String(), sensitive) {
			t.Fatalf("response exposed sensitive value %q: %s", sensitive, recorder.Body.String())
		}
	}

	var audit db.AssetDiscoveryAudit
	if err := store.First(&audit, response.AuditID).Error; err != nil {
		t.Fatalf("load audit: %v", err)
	}
	queryDigest := sha256.Sum256([]byte(expression))
	configDigest := sha256.Sum256([]byte(strings.TrimSpace(configContent)))
	if audit.TenantID != "default" || audit.ProjectID != project.ID || audit.OperatorID != "9" || audit.Provider != "hunter" || audit.Action != "query_preview" {
		t.Fatalf("unexpected audit ownership: %+v", audit)
	}
	if audit.QueryHash != hex.EncodeToString(queryDigest[:]) || audit.ConfigHash != hex.EncodeToString(configDigest[:]) || audit.ConfigVersion != 8 {
		t.Fatalf("unexpected audit correlation fields: %+v", audit)
	}
	if audit.Status != "success" || audit.RequestedLimit != 50 || audit.ProviderTotal != 5 || audit.ReturnedCount != 1 || audit.SkippedRows != 1 || !audit.Truncated {
		t.Fatalf("unexpected audit accounting: %+v", audit)
	}
	encodedAudit, err := json.Marshal(audit)
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	for _, sensitive := range []string{expression, testHunterAPIKey, "preview.example.invalid"} {
		if strings.Contains(string(encodedAudit), sensitive) {
			t.Fatalf("audit exposed sensitive result/request value %q: %s", sensitive, encodedAudit)
		}
	}
	assertAssetDiscoverySnapshot(t, store, audit, expression, provider.result.Assets[0])
}

func TestHunterPreviewRouteAuthenticatesAndExecutesThroughRouter(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	project, _ := seedHunterProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeHunterQueryProvider{result: assetdiscovery.Result{Provider: "hunter", Assets: []assetdiscovery.Asset{}}}
	previous := *routerRuntime()
	t.Cleanup(func() { ConfigureRouterDependencies(previous) })
	router := NewRouter(RouterDependencies{AssetDiscoveryHunter: provider})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": "default", "role": "operator", "user_id": "9", "exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(currentJWTSecret())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/"+project.ID+"/asset-discovery/hunter/query", strings.NewReader(`{"expression":"domain=example.invalid"}`))
	request.Header.Set("Authorization", "Bearer "+tokenString)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || provider.calls != 1 {
		t.Fatalf("unexpected route result: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
	}
	var audit db.AssetDiscoveryAudit
	if err := db.DB.First(&audit).Error; err != nil || audit.Provider != "hunter" || audit.Status != "success" {
		t.Fatalf("unexpected route audit: audit=%+v err=%v", audit, err)
	}
}

func TestHunterPreviewRouteRejectsOversizedBodyBeforeProviderCall(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	provider := &fakeHunterQueryProvider{}
	previous := *routerRuntime()
	t.Cleanup(func() { ConfigureRouterDependencies(previous) })
	router := NewRouter(RouterDependencies{AssetDiscoveryHunter: provider})
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": "default", "role": "operator", "user_id": "9", "exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(currentJWTSecret())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-oversized/asset-discovery/hunter/query", strings.NewReader(`{"expression":"`+strings.Repeat("a", int(assetDiscoveryRequestLimit))+`"}`))
	request.Header.Set("Authorization", "Bearer "+tokenString)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge || provider.calls != 0 {
		t.Fatalf("oversized route was not bounded: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
	}
	if !isAssetDiscoveryQueryPath(strings.TrimSuffix("/api/v1/projects/project-oversized/asset-discovery/hunter/query/", "/")) {
		t.Fatal("trailing-slash Hunter path was not recognized by request limiter")
	}
}

func TestQueryProjectHunterPreviewDoesNotUseAnotherTenantsCredential(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	project, _ := seedHunterProjectAndConfig(t, "tenant-a", "tenant-b", "Approved")
	provider := &fakeHunterQueryProvider{}
	installFakeHunterProvider(t, provider)

	recorder := invokeHunterPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "tenant-a", "operator", "9")
	if recorder.Code != http.StatusServiceUnavailable || provider.calls != 0 {
		t.Fatalf("cross-tenant credential was not rejected: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
	}
	var audit db.AssetDiscoveryAudit
	if err := db.DB.First(&audit).Error; err != nil || audit.TenantID != "tenant-a" || audit.Provider != "hunter" || audit.ErrorCode != "credential_unavailable" || audit.ConfigHash != "" {
		t.Fatalf("unexpected unavailable credential audit: audit=%+v err=%v", audit, err)
	}
}

func TestQueryProjectHunterPreviewSanitizesProviderFailureAndFailsClosedOnAuditError(t *testing.T) {
	t.Run("provider error", func(t *testing.T) {
		setupAssetDiscoveryTestDB(t)
		project, _ := seedHunterProjectAndConfig(t, "default", "default", "Approved")
		provider := &fakeHunterQueryProvider{err: fmt.Errorf("upstream key=%s: %w", testHunterAPIKey, assetdiscovery.ErrHunterUnavailable)}
		installFakeHunterProvider(t, provider)

		recorder := invokeHunterPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "default", "operator", "9")
		if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), testHunterAPIKey) {
			t.Fatalf("provider error was not sanitized: status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var audit db.AssetDiscoveryAudit
		if err := db.DB.First(&audit).Error; err != nil || audit.Provider != "hunter" || audit.ErrorCode != "provider_unavailable" || audit.Status != "failed" {
			t.Fatalf("unexpected provider failure audit: audit=%+v err=%v", audit, err)
		}
	})

	t.Run("audit error", func(t *testing.T) {
		store := setupAssetDiscoveryTestDB(t)
		project, _ := seedHunterProjectAndConfig(t, "default", "default", "Approved")
		provider := &fakeHunterQueryProvider{result: assetdiscovery.Result{
			Provider: "hunter", Assets: []assetdiscovery.Asset{{Target: "https://private.example.invalid:443", Port: 443, Source: "hunter"}},
		}}
		installFakeHunterProvider(t, provider)
		if err := store.Migrator().DropTable(&db.AssetDiscoveryAudit{}); err != nil {
			t.Fatalf("drop audit table: %v", err)
		}

		recorder := invokeHunterPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "default", "operator", "9")
		if recorder.Code != http.StatusInternalServerError || provider.calls != 1 || strings.Contains(recorder.Body.String(), "private.example.invalid") {
			t.Fatalf("result escaped audit failure: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
		}
	})
}

func TestHunterPreviewRBACAndErrorClassification(t *testing.T) {
	if got := matchPermission(http.MethodPost, "/api/v1/projects/project-1/asset-discovery/hunter/query"); got != "operator" {
		t.Fatalf("permission = %q, want operator", got)
	}
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{err: assetdiscovery.ErrInvalidHunterRequest, status: http.StatusBadRequest, code: "invalid_request"},
		{err: assetdiscovery.ErrHunterRejected, status: http.StatusBadGateway, code: "provider_rejected"},
		{err: assetdiscovery.ErrInvalidHunterResponse, status: http.StatusBadGateway, code: "invalid_provider_response"},
		{err: assetdiscovery.ErrHunterUnavailable, status: http.StatusBadGateway, code: "provider_unavailable"},
		{err: context.DeadlineExceeded, status: http.StatusGatewayTimeout, code: "provider_timeout"},
	}
	for _, test := range tests {
		status, code, message := classifyHunterQueryError(errors.Join(errors.New("wrapped"), test.err))
		if status != test.status || code != test.code || strings.TrimSpace(message) == "" {
			t.Fatalf("classify %v = (%d, %q, %q), want (%d, %q, non-empty)", test.err, status, code, message, test.status, test.code)
		}
	}
}
