package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

func seedAssetDiscoveryHistoryProject(t *testing.T, store *gorm.DB, id, tenantID, ownerID string) db.Project {
	t.Helper()
	project := db.Project{ID: id, TenantID: tenantID, OwnerUserID: ownerID, Name: id, Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed history project: %v", err)
	}
	return project
}

func seedAssetDiscoveryHistorySnapshot(t *testing.T, store *gorm.DB, tenantID, projectID, provider, expression string, createdAt time.Time, targets ...string) db.AssetDiscoverySnapshot {
	t.Helper()
	audit := db.AssetDiscoveryAudit{
		TenantID:       tenantID,
		ProjectID:      projectID,
		Provider:       provider,
		Action:         "query_preview",
		OperatorID:     "9",
		QueryHash:      strings.Repeat("a", 64),
		ConfigVersion:  7,
		ConfigHash:     strings.Repeat("b", 64),
		RequestedLimit: 100,
		ProviderTotal:  len(targets) + 10,
		ReturnedCount:  len(targets),
		Status:         "success",
		CreatedAt:      createdAt,
	}
	if err := store.Create(&audit).Error; err != nil {
		t.Fatalf("seed history audit: %v", err)
	}
	snapshot := db.AssetDiscoverySnapshot{
		SchemaVersion:  db.AssetDiscoverySnapshotSchemaVersion,
		TenantID:       tenantID,
		ProjectID:      projectID,
		AuditID:        audit.ID,
		Provider:       provider,
		Expression:     expression,
		QueryHash:      audit.QueryHash,
		ConfigVersion:  audit.ConfigVersion,
		ConfigHash:     audit.ConfigHash,
		RequestedLimit: audit.RequestedLimit,
		ProviderTotal:  audit.ProviderTotal,
		ReturnedCount:  audit.ReturnedCount,
		CreatedBy:      audit.OperatorID,
		CreatedAt:      createdAt,
	}
	if err := store.Create(&snapshot).Error; err != nil {
		t.Fatalf("seed history snapshot: %v", err)
	}
	items := make([]db.AssetDiscoverySnapshotItem, 0, len(targets))
	for position, target := range targets {
		items = append(items, db.AssetDiscoverySnapshotItem{
			TenantID:         tenantID,
			ProjectID:        projectID,
			SnapshotID:       snapshot.ID,
			Position:         position,
			NormalizedTarget: target,
			TargetHash:       strings.Repeat(string(rune('c'+position)), 64),
			Domain:           "asset.example.invalid",
			Port:             443,
			Protocol:         "https",
			Source:           provider,
			ObservedAt:       createdAt.Add(time.Duration(position) * time.Second),
			CreatedAt:        createdAt,
		})
	}
	if len(items) > 0 {
		if err := store.Create(&items).Error; err != nil {
			t.Fatalf("seed history snapshot items: %v", err)
		}
	}
	return snapshot
}

func invokeAssetDiscoveryHistory(t *testing.T, projectID, rawQuery, tenantID, role, userID string) (*httptest.ResponseRecorder, *gin.Context) {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/queries"
	if rawQuery != "" {
		path += "?" + rawQuery
	}
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, role, userID)
	ctx.Set("tenant", tenantID)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}}
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)
	listProjectDiscoveryQueries(ctx)
	return recorder, ctx
}

func invokeAssetDiscoveryHistoryDetail(t *testing.T, projectID, snapshotID, rawQuery, tenantID, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/queries/" + snapshotID
	if rawQuery != "" {
		path += "?" + rawQuery
	}
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, role, userID)
	ctx.Set("tenant", tenantID)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}, {Key: "snapshot_id", Value: snapshotID}}
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)
	getProjectDiscoveryQuery(ctx)
	return recorder
}

func TestListProjectDiscoveryQueriesScopesFiltersAndPaginates(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-history", "default", "9")
	otherProject := seedAssetDiscoveryHistoryProject(t, store, "project-history-other", "default", "9")
	base := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	older := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "domain=older.example.invalid", base, "https://older.example.invalid:443")
	seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "hunter", "domain=hunter.example.invalid", base.Add(time.Minute), "https://hunter.example.invalid:443")
	seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "domain=newer.example.invalid", base.Add(2*time.Minute), "https://newer.example.invalid:443")
	seedAssetDiscoveryHistorySnapshot(t, store, "default", otherProject.ID, "fofa", "domain=other-project.invalid", base.Add(3*time.Minute), "https://other-project.invalid:443")
	seedAssetDiscoveryHistorySnapshot(t, store, "tenant-b", project.ID, "fofa", "domain=other-tenant.invalid", base.Add(4*time.Minute), "https://other-tenant.invalid:443")

	recorder, _ := invokeAssetDiscoveryHistory(t, project.ID, "provider=fofa&page=2&page_size=1", "default", "viewer", "9")
	if recorder.Code != http.StatusOK {
		t.Fatalf("history status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("history cache control = %q, want no-store", recorder.Header().Get("Cache-Control"))
	}
	var response assetDiscoveryQueryHistoryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode history response: %v", err)
	}
	if response.SchemaVersion != assetDiscoveryHistorySchema || response.ProjectID != project.ID || response.Total != 2 ||
		response.Page != 2 || response.PageSize != 1 || response.HasMore || len(response.Items) != 1 || response.Items[0].ID != older.ID {
		t.Fatalf("unexpected history response: %+v", response)
	}
	encoded := recorder.Body.String()
	for _, private := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64), "other-project.invalid", "other-tenant.invalid", "target_hash", "config_hash", "query_hash"} {
		if strings.Contains(encoded, private) {
			t.Fatalf("history response exposed private field/value %q: %s", private, encoded)
		}
	}

	invalid, _ := invokeAssetDiscoveryHistory(t, project.ID, "provider=fofa%25", "default", "viewer", "9")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid provider status = %d, want 400", invalid.Code)
	}
	unauthorized, _ := invokeAssetDiscoveryHistory(t, project.ID, "", "default", "viewer", "10")
	if unauthorized.Code != http.StatusForbidden || strings.Contains(unauthorized.Body.String(), "older.example.invalid") {
		t.Fatalf("unauthorized history status = %d, body=%s", unauthorized.Code, unauthorized.Body.String())
	}
}

func TestGetProjectDiscoveryQueryScopesAndPaginatesAssets(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-history-detail", "default", "9")
	otherProject := seedAssetDiscoveryHistoryProject(t, store, "project-history-detail-other", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(
		t, store, "default", project.ID, "quake", "domain: detail.example.invalid", time.Now().UTC(),
		"https://one.example.invalid:443", "https://two.example.invalid:443", "https://three.example.invalid:443",
	)

	recorder := invokeAssetDiscoveryHistoryDetail(t, project.ID, strconv.FormatUint(uint64(snapshot.ID), 10), "page=2&page_size=2", "default", "viewer", "9")
	if recorder.Code != http.StatusOK {
		t.Fatalf("history detail status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("history detail cache control = %q, want no-store", recorder.Header().Get("Cache-Control"))
	}
	var response assetDiscoveryQueryDetailResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode history detail response: %v", err)
	}
	if response.SchemaVersion != assetDiscoveryHistorySchema || response.ProjectID != project.ID || response.Query.ID != snapshot.ID ||
		response.Total != 3 || response.Page != 2 || response.PageSize != 2 || response.HasMore || len(response.Assets) != 1 ||
		response.Assets[0].Position != 2 || response.Assets[0].Target != "https://three.example.invalid:443" {
		t.Fatalf("unexpected history detail response: %+v", response)
	}
	encoded := recorder.Body.String()
	for _, private := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64), "target_hash", "config_hash", "query_hash"} {
		if strings.Contains(encoded, private) {
			t.Fatalf("history detail exposed private field/value %q: %s", private, encoded)
		}
	}

	crossProject := invokeAssetDiscoveryHistoryDetail(t, otherProject.ID, strconv.FormatUint(uint64(snapshot.ID), 10), "", "default", "viewer", "9")
	if crossProject.Code != http.StatusNotFound {
		t.Fatalf("cross-project detail status = %d, want 404", crossProject.Code)
	}
	crossTenant := invokeAssetDiscoveryHistoryDetail(t, project.ID, strconv.FormatUint(uint64(snapshot.ID), 10), "", "tenant-b", "viewer", "9")
	if crossTenant.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant detail status = %d, want 403", crossTenant.Code)
	}
	invalidID := invokeAssetDiscoveryHistoryDetail(t, project.ID, "not-a-number", "", "default", "viewer", "9")
	if invalidID.Code != http.StatusBadRequest {
		t.Fatalf("invalid detail id status = %d, want 400", invalidID.Code)
	}
}

func TestAssetDiscoveryHistoryRoutesAuthenticateAndAllowViewer(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-history-route", "default", "9")
	seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "domain=route.example.invalid", time.Now().UTC())
	previous := *routerRuntime()
	t.Cleanup(func() { ConfigureRouterDependencies(previous) })
	router := NewRouter(RouterDependencies{})
	path := "/api/v1/projects/" + project.ID + "/asset-discovery/queries"

	unauthenticated := httptest.NewRecorder()
	router.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, path, nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated history status = %d, want 401", unauthenticated.Code)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": "default",
		"role":      "viewer",
		"user_id":   "9",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(currentJWTSecret())
	if err != nil {
		t.Fatalf("sign viewer token: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+tokenString)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("viewer history route status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if got := matchPermission(http.MethodGet, path); got != "viewer" {
		t.Fatalf("history list permission = %q, want viewer", got)
	}
	detailPath := path + "/1"
	if got := matchPermission(http.MethodGet, detailPath); got != "viewer" {
		t.Fatalf("history detail permission = %q, want viewer", got)
	}
}

func TestAssetDiscoveryHistoryPaginationRejectsOverflow(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	if _, ok := boundedPaginationOffset(maxInt, assetDiscoveryHistoryMaxPageSize); ok {
		t.Fatal("overflowing asset discovery history offset was accepted")
	}
	if offset, ok := boundedPaginationOffset(2, assetDiscoveryHistoryMaxPageSize); !ok || offset != assetDiscoveryHistoryMaxPageSize {
		t.Fatalf("normal asset discovery history offset = %d, ok=%v", offset, ok)
	}
}
