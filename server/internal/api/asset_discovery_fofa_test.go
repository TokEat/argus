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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/assetdiscovery"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

const (
	testFOFAEmail = "argus-test@example.invalid"
	testFOFAKey   = "fake-fofa-key-for-tests"
)

type fakeFOFAQueryProvider struct {
	result     assetdiscovery.Result
	err        error
	calls      int
	credential assetdiscovery.FOFACredential
	query      assetdiscovery.FOFAQuery
}

func setupAssetDiscoveryTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "asset-discovery.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(
		&db.Project{},
		&db.ProjectMember{},
		&db.Arsenal{},
		&db.AssetDiscoveryAudit{},
		&db.AssetDiscoverySnapshot{},
		&db.AssetDiscoverySnapshotItem{},
		&db.AssetDiscoveryNotebookItem{},
		&db.AssetDiscoveryNotebookSource{},
		&db.CustomRole{},
		&db.User{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := db.DB
	db.DB = store
	t.Cleanup(func() {
		db.DB = old
		sqlDB, sqlErr := store.DB()
		if sqlErr == nil {
			_ = sqlDB.Close()
		}
	})
	return store
}

func (f *fakeFOFAQueryProvider) Search(_ context.Context, credential assetdiscovery.FOFACredential, query assetdiscovery.FOFAQuery) (assetdiscovery.Result, error) {
	f.calls++
	f.credential = credential
	f.query = query
	return f.result, f.err
}

func installFakeFOFAProvider(t *testing.T, provider FOFAQueryProvider) {
	t.Helper()
	old := routerRuntime().AssetDiscoveryFOFA
	routerRuntime().AssetDiscoveryFOFA = provider
	t.Cleanup(func() { routerRuntime().AssetDiscoveryFOFA = old })
}

func seedFOFAProjectAndConfig(t *testing.T, projectTenant, configTenant, state string) (*db.Project, string) {
	t.Helper()
	store := db.DB
	project := &db.Project{
		ID:          "project-fofa-preview",
		TenantID:    projectTenant,
		OwnerUserID: "9",
		Name:        "FOFA preview test",
		Status:      "active",
	}
	if err := store.Create(project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	content := fmt.Sprintf("fofa:\n  - %s:%s\n", testFOFAEmail, testFOFAKey)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID(configTenant, "apiconfig", "api-config.yaml"),
		TenantID: configTenant,
		Type:     "apiconfig",
		FileName: "api-config.yaml",
		Content:  content,
		Hash:     "legacy-config-hash",
		State:    state,
		Version:  7,
	}).Error; err != nil {
		t.Fatalf("seed api config: %v", err)
	}
	return project, content
}

func invokeFOFAPreview(t *testing.T, projectID, body, tenant, role, userID string) (*httptest.ResponseRecorder, *gin.Context) {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/fofa/query"
	ctx, recorder := newTenantContextWithRole(http.MethodPost, path, role, userID)
	ctx.Set("tenant", tenant)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	queryProjectFOFAPreview(ctx)
	return recorder, ctx
}

func assertAssetDiscoverySnapshot(t *testing.T, store *gorm.DB, audit db.AssetDiscoveryAudit, expression string, expected assetdiscovery.Asset) {
	t.Helper()
	var snapshot db.AssetDiscoverySnapshot
	if err := store.Where("audit_id = ?", audit.ID).First(&snapshot).Error; err != nil {
		t.Fatalf("load asset discovery snapshot: %v", err)
	}
	if snapshot.SchemaVersion != db.AssetDiscoverySnapshotSchemaVersion || snapshot.TenantID != audit.TenantID ||
		snapshot.ProjectID != audit.ProjectID || snapshot.Provider != audit.Provider || snapshot.Expression != expression ||
		snapshot.QueryHash != audit.QueryHash || snapshot.ConfigVersion != audit.ConfigVersion || snapshot.ConfigHash != audit.ConfigHash ||
		snapshot.RequestedLimit != audit.RequestedLimit || snapshot.ProviderTotal != audit.ProviderTotal ||
		snapshot.ReturnedCount != audit.ReturnedCount || snapshot.SkippedRows != audit.SkippedRows ||
		snapshot.Truncated != audit.Truncated || snapshot.CreatedBy != audit.OperatorID {
		t.Fatalf("unexpected asset discovery snapshot: %+v", snapshot)
	}

	var items []db.AssetDiscoverySnapshotItem
	if err := store.Where("tenant_id = ? AND project_id = ? AND snapshot_id = ?", audit.TenantID, audit.ProjectID, snapshot.ID).
		Order("position ASC").Find(&items).Error; err != nil {
		t.Fatalf("load asset discovery snapshot items: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("snapshot items = %d, want 1", len(items))
	}
	digest := sha256.Sum256([]byte(expected.Target))
	item := items[0]
	if item.Position != 0 || item.NormalizedTarget != expected.Target || item.TargetHash != hex.EncodeToString(digest[:]) ||
		item.IP != expected.IP || item.Port != expected.Port || item.Domain != expected.Domain || item.Protocol != expected.Protocol ||
		item.Title != expected.Title || item.ICP != expected.ICP || item.Country != expected.Country || item.City != expected.City ||
		item.Company != expected.Company || item.StatusCode != expected.StatusCode || item.Source != expected.Source {
		t.Fatalf("unexpected asset discovery snapshot item: %+v", item)
	}
}

func TestQueryProjectFOFAPreviewUsesTenantCredentialAndAuditsWithoutSecrets(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project, configContent := seedFOFAProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeFOFAQueryProvider{result: assetdiscovery.Result{
		Provider:      "fofa",
		ProviderTotal: 3,
		SkippedRows:   1,
		Truncated:     true,
		Assets: []assetdiscovery.Asset{{
			Target: "https://preview.example.invalid:443", Domain: "preview.example.invalid", Port: 443, Protocol: "https", Source: "fofa",
		}},
	}}
	installFakeFOFAProvider(t, provider)

	expression := `domain="scope.example.invalid"`
	recorder, _ := invokeFOFAPreview(t, project.ID, fmt.Sprintf(`{"expression":%q,"limit":25}`, expression), "default", "operator", "9")
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 1 || provider.credential.Email != testFOFAEmail || provider.credential.Key != testFOFAKey {
		t.Fatalf("provider did not receive the selected tenant credential: calls=%d credential=%+v", provider.calls, provider.credential)
	}
	if provider.query.Expression != expression || provider.query.Limit != 25 {
		t.Fatalf("unexpected provider query: %+v", provider.query)
	}

	var response projectDiscoveryQueryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.SchemaVersion != assetDiscoveryPreviewSchema || response.ProjectID != project.ID || response.AuditID == 0 || len(response.Assets) != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
	for _, secret := range []string{expression, testFOFAEmail, testFOFAKey} {
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("response exposed sensitive query/config value %q: %s", secret, recorder.Body.String())
		}
	}

	var audit db.AssetDiscoveryAudit
	if err := store.First(&audit, response.AuditID).Error; err != nil {
		t.Fatalf("load audit: %v", err)
	}
	queryDigest := sha256.Sum256([]byte(expression))
	configDigest := sha256.Sum256([]byte(strings.TrimSpace(configContent)))
	if audit.TenantID != "default" || audit.ProjectID != project.ID || audit.OperatorID != "9" || audit.Provider != "fofa" || audit.Action != "query_preview" {
		t.Fatalf("unexpected audit ownership: %+v", audit)
	}
	if audit.QueryHash != hex.EncodeToString(queryDigest[:]) || audit.ConfigHash != hex.EncodeToString(configDigest[:]) || audit.ConfigVersion != 7 {
		t.Fatalf("unexpected audit correlation fields: %+v", audit)
	}
	if audit.Status != "success" || audit.ErrorCode != "" || audit.RequestedLimit != 25 || audit.ProviderTotal != 3 || audit.ReturnedCount != 1 || audit.SkippedRows != 1 || !audit.Truncated {
		t.Fatalf("unexpected audit accounting: %+v", audit)
	}
	encodedAudit, err := json.Marshal(audit)
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	for _, secret := range []string{expression, testFOFAEmail, testFOFAKey} {
		if strings.Contains(string(encodedAudit), secret) {
			t.Fatalf("audit exposed sensitive query/config value %q: %s", secret, encodedAudit)
		}
	}
	assertAssetDiscoverySnapshot(t, store, audit, expression, provider.result.Assets[0])
}

func TestFOFAPreviewRouteAuthenticatesAndExecutesThroughRouter(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeFOFAQueryProvider{result: assetdiscovery.Result{Provider: "fofa", Assets: []assetdiscovery.Asset{}}}
	previous := *routerRuntime()
	t.Cleanup(func() { ConfigureRouterDependencies(previous) })
	router := NewRouter(RouterDependencies{AssetDiscoveryFOFA: provider})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": "default",
		"role":      "operator",
		"user_id":   "9",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(currentJWTSecret())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/"+project.ID+"/asset-discovery/fofa/query",
		strings.NewReader(`{"expression":"domain=example.invalid"}`),
	)
	request.Header.Set("Authorization", "Bearer "+tokenString)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected router response 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls)
	}
	var audit db.AssetDiscoveryAudit
	if err := db.DB.First(&audit).Error; err != nil {
		t.Fatalf("load route audit: %v", err)
	}
	if audit.TenantID != "default" || audit.ProjectID != project.ID || audit.OperatorID != "9" || audit.Status != "success" {
		t.Fatalf("unexpected route audit: %+v", audit)
	}
}

func TestFOFAPreviewRouteRejectsOversizedBodyBeforeProviderCall(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	provider := &fakeFOFAQueryProvider{}
	previous := *routerRuntime()
	t.Cleanup(func() { ConfigureRouterDependencies(previous) })
	router := NewRouter(RouterDependencies{AssetDiscoveryFOFA: provider})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": "default",
		"role":      "operator",
		"user_id":   "9",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(currentJWTSecret())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	body := `{"expression":"` + strings.Repeat("a", int(assetDiscoveryRequestLimit)) + `"}`
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/projects/project-oversized/asset-discovery/fofa/query",
		strings.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+tokenString)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 0 {
		t.Fatalf("provider called for oversized body: %d", provider.calls)
	}
	var auditCount int64
	if err := db.DB.Model(&db.AssetDiscoveryAudit{}).Count(&auditCount).Error; err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("request rejected before project access should not be audited, got %d", auditCount)
	}
}

func TestQueryProjectFOFAPreviewRejectsCrossTenantProjectBeforeProviderCall(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "tenant-b", "tenant-a", "Approved")
	provider := &fakeFOFAQueryProvider{}
	installFakeFOFAProvider(t, provider)

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "tenant-a", "operator", "9")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 0 {
		t.Fatalf("provider called across tenant boundary: %d", provider.calls)
	}
	var auditCount int64
	if err := db.DB.Model(&db.AssetDiscoveryAudit{}).Count(&auditCount).Error; err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("inaccessible project request should not create an audit, got %d", auditCount)
	}
}

func TestQueryProjectFOFAPreviewRejectsUnassignedProjectBeforeProviderCall(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeFOFAQueryProvider{}
	installFakeFOFAProvider(t, provider)

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "default", "operator", "10")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 0 {
		t.Fatalf("provider called for an unassigned project: %d", provider.calls)
	}
	var auditCount int64
	if err := db.DB.Model(&db.AssetDiscoveryAudit{}).Count(&auditCount).Error; err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("inaccessible project request should not create an audit, got %d", auditCount)
	}
}

func TestQueryProjectFOFAPreviewDoesNotUseAnotherTenantsCredential(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "tenant-a", "tenant-b", "Approved")
	provider := &fakeFOFAQueryProvider{}
	installFakeFOFAProvider(t, provider)

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "tenant-a", "operator", "9")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 0 {
		t.Fatalf("provider should not receive another tenant's credential, calls=%d", provider.calls)
	}
	var audit db.AssetDiscoveryAudit
	if err := db.DB.First(&audit).Error; err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if audit.TenantID != "tenant-a" || audit.ProjectID != project.ID || audit.ErrorCode != "credential_unavailable" || audit.ConfigHash != "" {
		t.Fatalf("unexpected unavailable credential audit: %+v", audit)
	}
}

func TestQueryProjectFOFAPreviewRequiresApprovedCredentialConfig(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "default", "default", "Draft")
	provider := &fakeFOFAQueryProvider{}
	installFakeFOFAProvider(t, provider)

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "default", "operator", "9")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 0 {
		t.Fatalf("provider should not receive an unapproved credential, calls=%d", provider.calls)
	}
	var audit db.AssetDiscoveryAudit
	if err := db.DB.First(&audit).Error; err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if audit.ErrorCode != "credential_unavailable" || audit.ConfigVersion != 0 || audit.ConfigHash != "" {
		t.Fatalf("unexpected unapproved credential audit: %+v", audit)
	}
}

func TestQueryProjectFOFAPreviewSanitizesProviderErrorAndAuditsFailure(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "default", "default", "Approved")
	sensitiveError := "upstream included " + testFOFAEmail + " key=" + testFOFAKey
	provider := &fakeFOFAQueryProvider{err: fmt.Errorf("%s: %w", sensitiveError, assetdiscovery.ErrFOFAUnavailable)}
	installFakeFOFAProvider(t, provider)

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "default", "operator", "9")
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), sensitiveError) || strings.Contains(recorder.Body.String(), testFOFAKey) {
		t.Fatalf("provider error leaked into response: %s", recorder.Body.String())
	}
	var audit db.AssetDiscoveryAudit
	if err := db.DB.First(&audit).Error; err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if audit.Status != "failed" || audit.ErrorCode != "provider_unavailable" || audit.ReturnedCount != 0 {
		t.Fatalf("unexpected provider failure audit: %+v", audit)
	}
}

func TestQueryProjectFOFAPreviewFailsClosedWhenAuditCannotBeSaved(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeFOFAQueryProvider{result: assetdiscovery.Result{
		Provider: "fofa",
		Assets:   []assetdiscovery.Asset{{Target: "https://preview.example.invalid:443", Port: 443, Source: "fofa"}},
	}}
	installFakeFOFAProvider(t, provider)
	if err := store.Migrator().DropTable(&db.AssetDiscoveryAudit{}); err != nil {
		t.Fatalf("drop audit table: %v", err)
	}

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=example.invalid"}`, "default", "operator", "9")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 1 {
		t.Fatalf("expected provider call before audit persistence failure, got %d", provider.calls)
	}
	if strings.Contains(recorder.Body.String(), "preview.example.invalid") {
		t.Fatalf("result returned without an audit record: %s", recorder.Body.String())
	}
}

func TestQueryProjectFOFAPreviewRejectsInvalidBodyAndRecordsOnlyHash(t *testing.T) {
	setupAssetDiscoveryTestDB(t)
	project, _ := seedFOFAProjectAndConfig(t, "default", "default", "Approved")
	provider := &fakeFOFAQueryProvider{}
	installFakeFOFAProvider(t, provider)

	recorder, _ := invokeFOFAPreview(t, project.ID, `{"expression":"domain=example.invalid","unknown":true}`, "default", "operator", "9")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 0 {
		t.Fatalf("provider called for invalid request: %d", provider.calls)
	}
	var audit db.AssetDiscoveryAudit
	if err := db.DB.First(&audit).Error; err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if audit.ErrorCode != "invalid_request" || audit.QueryHash == "" {
		t.Fatalf("unexpected invalid request audit: %+v", audit)
	}
}

func TestFOFAPreviewRBACRequiresOperator(t *testing.T) {
	if got := matchPermission(http.MethodPost, "/api/v1/projects/project-1/asset-discovery/fofa/query"); got != "operator" {
		t.Fatalf("permission = %q, want operator", got)
	}
	for _, role := range []string{"viewer", "operator", "admin"} {
		t.Run(role, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("tenant", "tenant-a")
				c.Set("role", role)
				c.Next()
			})
			router.Use(RBACMiddleware())
			called := false
			router.POST("/api/v1/projects/:id/asset-discovery/fofa/query", func(c *gin.Context) {
				called = true
				c.Status(http.StatusNoContent)
			})

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/projects/project-1/asset-discovery/fofa/query", nil))
			if role == "viewer" {
				if recorder.Code != http.StatusForbidden || called {
					t.Fatalf("viewer should be blocked: status=%d called=%v", recorder.Code, called)
				}
				return
			}
			if recorder.Code != http.StatusNoContent || !called {
				t.Fatalf("%s should pass RBAC: status=%d called=%v", role, recorder.Code, called)
			}
		})
	}
}

func TestClassifyFOFAQueryError(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{err: assetdiscovery.ErrInvalidFOFARequest, status: http.StatusBadRequest, code: "invalid_request"},
		{err: assetdiscovery.ErrFOFARejected, status: http.StatusBadGateway, code: "provider_rejected"},
		{err: assetdiscovery.ErrInvalidFOFAResponse, status: http.StatusBadGateway, code: "invalid_provider_response"},
		{err: assetdiscovery.ErrFOFAUnavailable, status: http.StatusBadGateway, code: "provider_unavailable"},
		{err: context.DeadlineExceeded, status: http.StatusGatewayTimeout, code: "provider_timeout"},
	}
	for _, test := range tests {
		status, code, message := classifyFOFAQueryError(errors.Join(errors.New("wrapped"), test.err))
		if status != test.status || code != test.code || strings.TrimSpace(message) == "" {
			t.Fatalf("classify %v = (%d, %q, %q), want (%d, %q, non-empty)", test.err, status, code, message, test.status, test.code)
		}
	}
}
