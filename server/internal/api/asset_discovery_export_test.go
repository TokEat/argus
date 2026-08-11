package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

func invokeAssetDiscoveryExport(t *testing.T, projectID, snapshotID, tenantID, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/queries/" + snapshotID + "/export"
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, role, userID)
	ctx.Set("tenant", tenantID)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}, {Key: "snapshot_id", Value: snapshotID}}
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)
	exportProjectDiscoveryQuery(ctx)
	return recorder
}

func decodeAssetDiscoveryCSV(t *testing.T, content []byte) [][]string {
	t.Helper()
	if !bytes.HasPrefix(content, []byte{0xef, 0xbb, 0xbf}) {
		t.Fatal("asset discovery CSV is missing UTF-8 BOM")
	}
	records, err := csv.NewReader(bytes.NewReader(content[3:])).ReadAll()
	if err != nil {
		t.Fatalf("decode asset discovery CSV: %v", err)
	}
	return records
}

func TestExportProjectDiscoveryQueryProducesSafeAuditedCSV(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-export", "default", "9")
	createdAt := time.Date(2026, 8, 10, 2, 0, 0, 0, time.UTC)
	snapshot := seedAssetDiscoveryHistorySnapshot(
		t, store, "default", project.ID, "fofa", `title="private query"`, createdAt,
		"https://first.example.invalid:443", "https://second.example.invalid:443",
	)
	if err := store.Model(&db.AssetDiscoverySnapshotItem{}).
		Where("snapshot_id = ? AND position = ?", snapshot.ID, 0).
		Updates(map[string]any{"position": 2, "title": "=HYPERLINK(\"https://example.invalid\",\"中文\")\nvalue", "company": " \t@SUM(1,1)"}).Error; err != nil {
		t.Fatalf("update formula-like export fields: %v", err)
	}
	if err := store.Model(&db.AssetDiscoverySnapshotItem{}).
		Where("snapshot_id = ? AND position = ?", snapshot.ID, 1).
		Updates(map[string]any{"position": 0, "title": "quoted, \"value\""}).Error; err != nil {
		t.Fatalf("update ordered export fields: %v", err)
	}

	recorder := invokeAssetDiscoveryExport(t, project.ID, strconv.FormatUint(uint64(snapshot.ID), 10), "default", "viewer", "9")
	if recorder.Code != http.StatusOK {
		t.Fatalf("export status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/csv; charset=utf-8" {
		t.Fatalf("export content type = %q", got)
	}
	if got := recorder.Header().Get("Content-Disposition"); got != fmt.Sprintf(`attachment; filename="argus-asset-discovery-%d.csv"`, snapshot.ID) {
		t.Fatalf("export disposition = %q", got)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("export security headers = %#v", recorder.Header())
	}

	records := decodeAssetDiscoveryCSV(t, recorder.Body.Bytes())
	if len(records) != 3 || len(records[0]) != 17 {
		t.Fatalf("unexpected CSV shape: rows=%d header=%v", len(records), records[0])
	}
	if records[1][3] != "0" || records[1][4] != "https://second.example.invalid:443" || records[1][9] != `quoted, "value"` {
		t.Fatalf("CSV rows are not stably ordered/decoded: %v", records[1])
	}
	if records[2][3] != "2" || records[2][9] != `'=HYPERLINK("https://example.invalid","中文")
value` || records[2][13] != "' \t@SUM(1,1)" {
		t.Fatalf("CSV formula protection failed: %v", records[2])
	}
	encoded := recorder.Body.String()
	for _, private := range []string{snapshot.Expression, snapshot.QueryHash, snapshot.ConfigHash, "query_hash", "config_hash", "target_hash"} {
		if strings.Contains(encoded, private) {
			t.Fatalf("CSV exposed private field/value %q", private)
		}
	}

	var audit db.AssetDiscoveryAudit
	if err := store.Where("tenant_id = ? AND project_id = ? AND action = ?", "default", project.ID, "export_snapshot").First(&audit).Error; err != nil {
		t.Fatalf("load export audit: %v", err)
	}
	if audit.OperatorID != "9" || audit.Provider != "fofa" || audit.Status != "success" || audit.ReturnedCount != 2 ||
		audit.QueryHash != snapshot.QueryHash || audit.ConfigHash != snapshot.ConfigHash {
		t.Fatalf("unexpected export audit: %+v", audit)
	}
}

func TestExportProjectDiscoveryQueryEnforcesObjectBoundaries(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-export-scope", "default", "9")
	otherProject := seedAssetDiscoveryHistoryProject(t, store, "project-export-scope-other", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "quake", "domain:scope.invalid", time.Now().UTC(), "https://secret.example.invalid:443")
	snapshotID := strconv.FormatUint(uint64(snapshot.ID), 10)

	crossProject := invokeAssetDiscoveryExport(t, otherProject.ID, snapshotID, "default", "viewer", "9")
	if crossProject.Code != http.StatusNotFound || strings.Contains(crossProject.Body.String(), "secret.example.invalid") {
		t.Fatalf("cross-project export status = %d, body=%s", crossProject.Code, crossProject.Body.String())
	}
	crossTenant := invokeAssetDiscoveryExport(t, project.ID, snapshotID, "tenant-b", "viewer", "9")
	if crossTenant.Code != http.StatusForbidden || strings.Contains(crossTenant.Body.String(), "secret.example.invalid") {
		t.Fatalf("cross-tenant export status = %d, body=%s", crossTenant.Code, crossTenant.Body.String())
	}
	unauthorized := invokeAssetDiscoveryExport(t, project.ID, snapshotID, "default", "viewer", "10")
	if unauthorized.Code != http.StatusForbidden || strings.Contains(unauthorized.Body.String(), "secret.example.invalid") {
		t.Fatalf("unassigned export status = %d, body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	invalidID := invokeAssetDiscoveryExport(t, project.ID, "not-a-number", "default", "viewer", "9")
	if invalidID.Code != http.StatusBadRequest {
		t.Fatalf("invalid export id status = %d, want 400", invalidID.Code)
	}
}

func TestExportProjectDiscoveryQueryRejectsOversizedSnapshots(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-export-limit", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "domain=limit.invalid", time.Now().UTC())
	items := make([]db.AssetDiscoverySnapshotItem, 0, assetDiscoverySnapshotItemLimit+1)
	for index := 0; index <= assetDiscoverySnapshotItemLimit; index++ {
		items = append(items, db.AssetDiscoverySnapshotItem{
			TenantID: "default", ProjectID: project.ID, SnapshotID: snapshot.ID, Position: index,
			NormalizedTarget: fmt.Sprintf("host-%d.example.invalid", index), TargetHash: fmt.Sprintf("%064x", index),
			Source: "fofa", ObservedAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
		})
	}
	if err := store.CreateInBatches(&items, 500).Error; err != nil {
		t.Fatalf("seed oversized snapshot: %v", err)
	}

	recorder := invokeAssetDiscoveryExport(t, project.ID, strconv.FormatUint(uint64(snapshot.ID), 10), "default", "viewer", "9")
	if recorder.Code != http.StatusRequestEntityTooLarge || strings.Contains(recorder.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("oversized export status = %d, headers=%v, body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	var audit db.AssetDiscoveryAudit
	if err := store.Where("action = ?", "export_snapshot").First(&audit).Error; err != nil {
		t.Fatalf("load oversized export audit: %v", err)
	}
	if audit.Status != "failed" || audit.ErrorCode != "export_limit_exceeded" || audit.ReturnedCount != 0 {
		t.Fatalf("unexpected oversized export audit: %+v", audit)
	}
}

func TestExportProjectDiscoveryQueryWithholdsFileWhenAuditFails(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-export-audit", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "hunter", "domain=audit.invalid", time.Now().UTC(), "https://audit.example.invalid:443")
	if err := store.Migrator().DropTable(&db.AssetDiscoveryAudit{}); err != nil {
		t.Fatalf("drop audit table: %v", err)
	}

	recorder := invokeAssetDiscoveryExport(t, project.ID, strconv.FormatUint(uint64(snapshot.ID), 10), "default", "viewer", "9")
	if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Header().Get("Content-Type"), "text/csv") ||
		strings.Contains(recorder.Body.String(), "audit.example.invalid") {
		t.Fatalf("audit failure export status = %d, headers=%v, body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestExportProjectDiscoveryQueryUsesRequestBudgetForProjectAccess(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-export-access-budget", "default", "9")
	path := "/projects/" + project.ID + "/asset-discovery/queries/1/export"
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, "viewer", "9")
	requestContext, cancel := context.WithCancel(context.Background())
	cancel()
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil).WithContext(requestContext)
	ctx.Params = gin.Params{{Key: "id", Value: project.ID}, {Key: "snapshot_id", Value: "1"}}

	exportProjectDiscoveryQuery(ctx)

	if recorder.Code != http.StatusGatewayTimeout || strings.Contains(recorder.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("canceled access export status = %d, headers=%v, body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestExportProjectDiscoveryQueryClassifiesSnapshotDeadline(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-export-snapshot-budget", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "quake", "domain:snapshot-budget.invalid", time.Now().UTC(), "https://snapshot-budget.example.invalid:443")
	callbackName := "test:wait_for_asset_discovery_snapshot_context"
	if err := store.Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table != "asset_discovery_snapshots" {
			return
		}
		<-tx.Statement.Context.Done()
		tx.AddError(tx.Statement.Context.Err())
	}); err != nil {
		t.Fatalf("register snapshot budget callback: %v", err)
	}
	t.Cleanup(func() { _ = store.Callback().Query().Remove(callbackName) })

	path := fmt.Sprintf("/projects/%s/asset-discovery/queries/%d/export", project.ID, snapshot.ID)
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, "viewer", "9")
	requestContext, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil).WithContext(requestContext)
	ctx.Params = gin.Params{{Key: "id", Value: project.ID}, {Key: "snapshot_id", Value: strconv.FormatUint(uint64(snapshot.ID), 10)}}
	startedAt := time.Now()

	exportProjectDiscoveryQuery(ctx)

	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("snapshot query exceeded request budget: %s", elapsed)
	}
	if recorder.Code != http.StatusGatewayTimeout || strings.Contains(recorder.Header().Get("Content-Type"), "text/csv") ||
		strings.Contains(recorder.Body.String(), "snapshot-budget.example.invalid") {
		t.Fatalf("snapshot budget export status = %d, headers=%v, body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestExportProjectDiscoveryQueryUsesRequestBudgetForSuccessAudit(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-export-audit-budget", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "domain=audit-budget.invalid", time.Now().UTC(), "https://audit-budget.example.invalid:443")
	callbackName := "test:wait_for_asset_discovery_export_context"
	if err := store.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table != "asset_discovery_audits" {
			return
		}
		<-tx.Statement.Context.Done()
		tx.AddError(tx.Statement.Context.Err())
	}); err != nil {
		t.Fatalf("register audit budget callback: %v", err)
	}
	t.Cleanup(func() { _ = store.Callback().Create().Remove(callbackName) })

	path := fmt.Sprintf("/projects/%s/asset-discovery/queries/%d/export", project.ID, snapshot.ID)
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, "viewer", "9")
	requestContext, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil).WithContext(requestContext)
	ctx.Params = gin.Params{{Key: "id", Value: project.ID}, {Key: "snapshot_id", Value: strconv.FormatUint(uint64(snapshot.ID), 10)}}
	startedAt := time.Now()

	exportProjectDiscoveryQuery(ctx)

	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("audit exceeded request budget: %s", elapsed)
	}
	if recorder.Code != http.StatusGatewayTimeout || strings.Contains(recorder.Header().Get("Content-Type"), "text/csv") ||
		strings.Contains(recorder.Body.String(), "audit-budget.example.invalid") {
		t.Fatalf("audit budget export status = %d, headers=%v, body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestAssetDiscoveryExportRouteAuthenticatesAndAllowsViewer(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "project-export-route", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "domain=route.invalid", time.Now().UTC())
	path := fmt.Sprintf("/api/v1/projects/%s/asset-discovery/queries/%d/export", project.ID, snapshot.ID)
	previous := *routerRuntime()
	t.Cleanup(func() { ConfigureRouterDependencies(previous) })
	router := NewRouter(RouterDependencies{})

	unauthenticated := httptest.NewRecorder()
	router.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, path, nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated export status = %d, want 401", unauthenticated.Code)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id": "default", "role": "viewer", "user_id": "9", "exp": time.Now().Add(time.Hour).Unix(),
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
		t.Fatalf("viewer export status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if got := matchPermission(http.MethodGet, path); got != "viewer" {
		t.Fatalf("export permission = %q, want viewer", got)
	}
}

func TestAssetDiscoveryExportBufferRejectsEncodedOutputOverLimit(t *testing.T) {
	buffer := &assetDiscoveryExportBuffer{limit: 4}
	if _, err := buffer.Write([]byte("1234")); err != nil {
		t.Fatalf("write at export byte limit: %v", err)
	}
	if _, err := buffer.Write([]byte("5")); !errors.Is(err, errAssetDiscoveryExportLimit) {
		t.Fatalf("write beyond export byte limit error = %v", err)
	}
}
