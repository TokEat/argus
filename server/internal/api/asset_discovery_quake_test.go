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

	"github.com/TokEat/argus/server/internal/assetdiscovery"
	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const testQuakeToken = "fake-quake-token-for-tests"

type fakeQuakeQueryProvider struct {
	result     assetdiscovery.Result
	err        error
	calls      int
	credential assetdiscovery.QuakeCredential
	query      assetdiscovery.QuakeQuery
}

func (f *fakeQuakeQueryProvider) Search(_ context.Context, credential assetdiscovery.QuakeCredential, query assetdiscovery.QuakeQuery) (assetdiscovery.Result, error) {
	f.calls++
	f.credential = credential
	f.query = query
	return f.result, f.err
}

func installFakeQuakeProvider(t *testing.T, provider QuakeQueryProvider) {
	t.Helper()
	old := routerRuntime().AssetDiscoveryQuake
	routerRuntime().AssetDiscoveryQuake = provider
	t.Cleanup(func() { routerRuntime().AssetDiscoveryQuake = old })
}

func seedQuakeProjectAndConfig(t *testing.T, projectTenant, configTenant, state string) (*db.Project, string) {
	t.Helper()
	project := &db.Project{
		ID:          "project-quake-preview",
		TenantID:    projectTenant,
		OwnerUserID: "9",
		Name:        "Quake preview test",
		Status:      "active",
	}
	if err := db.DB.Create(project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	content := fmt.Sprintf("quake:\n  - %s\n", testQuakeToken)
	if err := db.DB.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID(configTenant, "apiconfig", "api-config.yaml"),
		TenantID: configTenant,
		Type:     "apiconfig",
		FileName: "api-config.yaml",
		Content:  content,
		Hash:     "legacy-config-hash",
		State:    state,
		Version:  11,
	}).Error; err != nil {
		t.Fatalf("seed api config: %v", err)
	}
	return project, content
}

func invokeQuakePreview(t *testing.T, projectID, body, tenant, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/quake/query"
	ctx, recorder := newTenantContextWithRole(http.MethodPost, path, role, userID)
	ctx.Set("tenant", tenant)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	queryProjectQuakePreview(ctx)
	return recorder
}

func TestQueryProjectQuakePreviewUsesTenantCredentialAndSanitizedAudit(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project, configContent := seedQuakeProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeQuakeQueryProvider{result: assetdiscovery.Result{
		Provider:      "quake",
		ProviderTotal: 7,
		SkippedRows:   2,
		Truncated:     true,
		Assets: []assetdiscovery.Asset{{
			Target: "https://preview.example.invalid:443", IP: "192.0.2.10", Domain: "preview.example.invalid",
			Port: 443, Protocol: "https", Title: "Preview", Source: "quake",
		}},
	}}
	installFakeQuakeProvider(t, provider)

	expression := `domain: "scope.example.invalid"`
	recorder := invokeQuakePreview(t, project.ID, fmt.Sprintf(`{"expression":%q,"limit":50}`, expression), "default", "operator", "9")
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 1 || provider.credential.Token != testQuakeToken || provider.query.Expression != expression || provider.query.Limit != 50 {
		t.Fatalf("unexpected provider invocation: calls=%d credential=%+v query=%+v", provider.calls, provider.credential, provider.query)
	}

	var response projectDiscoveryQueryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.SchemaVersion != assetDiscoveryPreviewSchema || response.ProjectID != project.ID || response.AuditID == 0 || response.Provider != "quake" || len(response.Assets) != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
	for _, sensitive := range []string{expression, testQuakeToken} {
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
	if audit.TenantID != "default" || audit.ProjectID != project.ID || audit.OperatorID != "9" || audit.Provider != "quake" || audit.Action != "query_preview" {
		t.Fatalf("unexpected audit ownership: %+v", audit)
	}
	if audit.QueryHash != hex.EncodeToString(queryDigest[:]) || audit.ConfigHash != hex.EncodeToString(configDigest[:]) || audit.ConfigVersion != 11 {
		t.Fatalf("unexpected audit correlation fields: %+v", audit)
	}
	if audit.Status != "success" || audit.RequestedLimit != 50 || audit.ProviderTotal != 7 || audit.ReturnedCount != 1 || audit.SkippedRows != 2 || !audit.Truncated {
		t.Fatalf("unexpected audit accounting: %+v", audit)
	}
	encodedAudit, err := json.Marshal(audit)
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	for _, sensitive := range []string{expression, testQuakeToken, "preview.example.invalid"} {
		if strings.Contains(string(encodedAudit), sensitive) {
			t.Fatalf("audit exposed sensitive result/request value %q: %s", sensitive, encodedAudit)
		}
	}
	assertAssetDiscoverySnapshot(t, store, audit, expression, provider.result.Assets[0])
}

func TestQuakePreviewRouteAuthenticatesAndBoundsRequest(t *testing.T) {
	t.Run("authenticated route", func(t *testing.T) {
		setupAssetDiscoveryTestDB(t)
		project, _ := seedQuakeProjectAndConfig(t, "default", "default", "Approved")
		provider := &fakeQuakeQueryProvider{result: assetdiscovery.Result{Provider: "quake", Assets: []assetdiscovery.Asset{}}}
		previous := *routerRuntime()
		t.Cleanup(func() { ConfigureRouterDependencies(previous) })
		router := NewRouter(RouterDependencies{AssetDiscoveryQuake: provider})

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"tenant_id": "default", "role": "operator", "user_id": "9", "exp": time.Now().Add(time.Hour).Unix(),
		})
		tokenString, err := token.SignedString(currentJWTSecret())
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/"+project.ID+"/asset-discovery/quake/query", strings.NewReader(`{"expression":"domain: example.invalid"}`))
		request.Header.Set("Authorization", "Bearer "+tokenString)
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK || provider.calls != 1 {
			t.Fatalf("unexpected route result: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
		}
	})

	t.Run("oversized request", func(t *testing.T) {
		setupAssetDiscoveryTestDB(t)
		provider := &fakeQuakeQueryProvider{}
		previous := *routerRuntime()
		t.Cleanup(func() { ConfigureRouterDependencies(previous) })
		router := NewRouter(RouterDependencies{AssetDiscoveryQuake: provider})
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"tenant_id": "default", "role": "operator", "user_id": "9", "exp": time.Now().Add(time.Hour).Unix(),
		})
		tokenString, err := token.SignedString(currentJWTSecret())
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-oversized/asset-discovery/quake/query", strings.NewReader(`{"expression":"`+strings.Repeat("a", int(assetDiscoveryRequestLimit))+`"}`))
		request.Header.Set("Authorization", "Bearer "+tokenString)
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusRequestEntityTooLarge || provider.calls != 0 {
			t.Fatalf("oversized route was not bounded: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
		}
		if !isAssetDiscoveryQueryPath(strings.TrimSuffix("/api/v1/projects/project-oversized/asset-discovery/quake/query/", "/")) {
			t.Fatal("trailing-slash Quake path was not recognized by request limiter")
		}
	})
}

func TestQueryProjectQuakePreviewTenantIsolationAndFailureHandling(t *testing.T) {
	t.Run("another tenant credential", func(t *testing.T) {
		setupAssetDiscoveryTestDB(t)
		project, _ := seedQuakeProjectAndConfig(t, "tenant-a", "tenant-b", "Approved")
		provider := &fakeQuakeQueryProvider{}
		installFakeQuakeProvider(t, provider)

		recorder := invokeQuakePreview(t, project.ID, `{"expression":"domain: example.invalid"}`, "tenant-a", "operator", "9")
		if recorder.Code != http.StatusServiceUnavailable || provider.calls != 0 {
			t.Fatalf("cross-tenant credential was not rejected: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
		}
		var audit db.AssetDiscoveryAudit
		if err := db.DB.First(&audit).Error; err != nil || audit.TenantID != "tenant-a" || audit.Provider != "quake" || audit.ErrorCode != "credential_unavailable" || audit.ConfigHash != "" {
			t.Fatalf("unexpected unavailable credential audit: audit=%+v err=%v", audit, err)
		}
	})

	t.Run("provider error is sanitized", func(t *testing.T) {
		setupAssetDiscoveryTestDB(t)
		project, _ := seedQuakeProjectAndConfig(t, "default", "default", "Approved")
		provider := &fakeQuakeQueryProvider{err: fmt.Errorf("upstream token=%s: %w", testQuakeToken, assetdiscovery.ErrQuakeUnavailable)}
		installFakeQuakeProvider(t, provider)

		recorder := invokeQuakePreview(t, project.ID, `{"expression":"domain: example.invalid"}`, "default", "operator", "9")
		if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), testQuakeToken) {
			t.Fatalf("provider error was not sanitized: status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var audit db.AssetDiscoveryAudit
		if err := db.DB.First(&audit).Error; err != nil || audit.Provider != "quake" || audit.ErrorCode != "provider_unavailable" || audit.Status != "failed" {
			t.Fatalf("unexpected provider failure audit: audit=%+v err=%v", audit, err)
		}
	})

	t.Run("audit failure hides result", func(t *testing.T) {
		store := setupAssetDiscoveryTestDB(t)
		project, _ := seedQuakeProjectAndConfig(t, "default", "default", "Approved")
		provider := &fakeQuakeQueryProvider{result: assetdiscovery.Result{
			Provider: "quake", Assets: []assetdiscovery.Asset{{Target: "https://private.example.invalid:443", Port: 443, Source: "quake"}},
		}}
		installFakeQuakeProvider(t, provider)
		if err := store.Migrator().DropTable(&db.AssetDiscoveryAudit{}); err != nil {
			t.Fatalf("drop audit table: %v", err)
		}

		recorder := invokeQuakePreview(t, project.ID, `{"expression":"domain: example.invalid"}`, "default", "operator", "9")
		if recorder.Code != http.StatusInternalServerError || provider.calls != 1 || strings.Contains(recorder.Body.String(), "private.example.invalid") {
			t.Fatalf("result escaped audit failure: status=%d calls=%d body=%s", recorder.Code, provider.calls, recorder.Body.String())
		}
	})
}

func TestQuakePreviewRBACAndErrorClassification(t *testing.T) {
	if got := matchPermission(http.MethodPost, "/api/v1/projects/project-1/asset-discovery/quake/query"); got != "operator" {
		t.Fatalf("permission = %q, want operator", got)
	}
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{err: assetdiscovery.ErrInvalidQuakeRequest, status: http.StatusBadRequest, code: "invalid_request"},
		{err: assetdiscovery.ErrQuakeRejected, status: http.StatusBadGateway, code: "provider_rejected"},
		{err: assetdiscovery.ErrInvalidQuakeResponse, status: http.StatusBadGateway, code: "invalid_provider_response"},
		{err: assetdiscovery.ErrQuakeUnavailable, status: http.StatusBadGateway, code: "provider_unavailable"},
		{err: context.DeadlineExceeded, status: http.StatusGatewayTimeout, code: "provider_timeout"},
	}
	for _, test := range tests {
		status, code, message := classifyQuakeQueryError(errors.Join(errors.New("wrapped"), test.err))
		if status != test.status || code != test.code || strings.TrimSpace(message) == "" {
			t.Fatalf("classify %v = (%d, %q, %q), want (%d, %q, non-empty)", test.err, status, code, message, test.status, test.code)
		}
	}
}
