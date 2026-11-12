package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

func invokeNotebookArchive(t *testing.T, projectID string, snapshotID uint, body, tenant, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/queries/" + strconv.FormatUint(uint64(snapshotID), 10) + "/notebook-items"
	ctx, recorder := newTenantContextWithRole(http.MethodPost, path, role, userID)
	ctx.Set("tenant", tenant)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}, {Key: "snapshot_id", Value: strconv.FormatUint(uint64(snapshotID), 10)}}
	ctx.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	archiveProjectDiscoveryNotebookItems(ctx)
	return recorder
}

func invokeNotebookList(t *testing.T, projectID, query, tenant, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/notebook-items" + query
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, role, userID)
	ctx.Set("tenant", tenant)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}}
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)
	listProjectDiscoveryNotebookItems(ctx)
	return recorder
}

func TestAssetDiscoveryNotebookArchiveDeduplicatesLinksAndListsSafeFields(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "notebook-project", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "secret query", time.Now(), "https://one.example.invalid:443")
	var source db.AssetDiscoverySnapshotItem
	if err := store.Where("snapshot_id = ?", snapshot.ID).First(&source).Error; err != nil {
		t.Fatal(err)
	}
	body := `{"item_ids":[` + strconv.FormatUint(uint64(source.ID), 10) + `]}`
	for _, want := range []struct{ created, linked, already int }{{1, 1, 0}, {0, 0, 1}} {
		r := invokeNotebookArchive(t, project.ID, snapshot.ID, body, "default", "operator", "9")
		if r.Code != http.StatusOK {
			t.Fatalf("archive status=%d body=%s", r.Code, r.Body.String())
		}
		var response assetDiscoveryNotebookArchiveResponse
		if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.CreatedCount != want.created || response.LinkedSourceCount != want.linked || response.AlreadyArchivedCount != want.already || response.TotalCount != 1 {
			t.Fatalf("response=%+v", response)
		}
	}
	r := invokeNotebookList(t, project.ID, "", "default", "viewer", "9")
	if r.Code != http.StatusOK {
		t.Fatalf("viewer list=%d %s", r.Code, r.Body.String())
	}
	for _, forbidden := range []string{"target_hash", "query_hash", "config_hash", "secret query"} {
		if strings.Contains(r.Body.String(), forbidden) {
			t.Fatalf("list leaked %q: %s", forbidden, r.Body.String())
		}
	}
	var list assetDiscoveryNotebookListResponse
	if err := json.Unmarshal(r.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || len(list.Items) != 1 || list.Items[0].SourceCount != 1 || list.Items[0].Target != source.NormalizedTarget {
		t.Fatalf("list=%+v", list)
	}
	var audits []db.AssetDiscoveryAudit
	if err := store.Where("action = ?", "notebook_archive").Find(&audits).Error; err != nil || len(audits) != 2 || audits[0].Status != "success" {
		t.Fatalf("audits=%+v err=%v", audits, err)
	}
}

func TestAssetDiscoveryNotebookArchiveDeduplicatesTargetAcrossSnapshotsAndEnforcesBoundaries(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "notebook-boundary", "default", "9")
	first := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "a", time.Now(), "https://same.example.invalid:443")
	second := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "hunter", "b", time.Now().Add(time.Second), "https://same.example.invalid:443")
	for _, snapshot := range []db.AssetDiscoverySnapshot{first, second} {
		var item db.AssetDiscoverySnapshotItem
		_ = store.Where("snapshot_id = ?", snapshot.ID).First(&item).Error
		if r := invokeNotebookArchive(t, project.ID, snapshot.ID, `{"item_ids":[`+strconv.FormatUint(uint64(item.ID), 10)+`]}`, "default", "operator", "9"); r.Code != http.StatusOK {
			t.Fatalf("archive=%d %s", r.Code, r.Body.String())
		}
	}
	var itemCount, sourceCount int64
	store.Model(&db.AssetDiscoveryNotebookItem{}).Count(&itemCount)
	store.Model(&db.AssetDiscoveryNotebookSource{}).Count(&sourceCount)
	if itemCount != 1 || sourceCount != 2 {
		t.Fatalf("items=%d sources=%d", itemCount, sourceCount)
	}
	var secondItem db.AssetDiscoverySnapshotItem
	if err := store.Where("snapshot_id = ?", second.ID).First(&secondItem).Error; err != nil {
		t.Fatal(err)
	}
	if r := invokeNotebookArchive(t, project.ID, first.ID, `{"item_ids":[`+strconv.FormatUint(uint64(secondItem.ID), 10)+`]}`, "default", "operator", "9"); r.Code != http.StatusNotFound {
		t.Fatalf("cross-snapshot item status=%d", r.Code)
	}
	unassigned := seedAssetDiscoveryHistoryProject(t, store, "unassigned", "default", "10")
	unassignedSnapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", unassigned.ID, "fofa", "u", time.Now(), "https://unassigned.example.invalid")
	if r := invokeNotebookArchive(t, unassigned.ID, unassignedSnapshot.ID, `{"item_ids":[1]}`, "default", "operator", "9"); r.Code != http.StatusForbidden {
		t.Fatalf("unassigned project status=%d", r.Code)
	}
	foreign := seedAssetDiscoveryHistoryProject(t, store, "foreign", "tenant-b", "9")
	foreignSnap := seedAssetDiscoveryHistorySnapshot(t, store, "tenant-b", foreign.ID, "fofa", "x", time.Now(), "https://foreign.example.invalid")
	if r := invokeNotebookArchive(t, project.ID, foreignSnap.ID, `{"item_ids":[1]}`, "default", "operator", "9"); r.Code != http.StatusNotFound {
		t.Fatalf("cross snapshot status=%d", r.Code)
	}
	if r := invokeNotebookArchive(t, foreign.ID, foreignSnap.ID, `{"item_ids":[1]}`, "default", "operator", "9"); r.Code != http.StatusForbidden {
		t.Fatalf("cross tenant status=%d", r.Code)
	}
	project.Status = "archived"
	if err := store.Save(&project).Error; err != nil {
		t.Fatal(err)
	}
	if r := invokeNotebookArchive(t, project.ID, first.ID, `{"item_ids":[1]}`, "default", "operator", "9"); r.Code != http.StatusConflict {
		t.Fatalf("archived status=%d", r.Code)
	}
	if r := invokeNotebookList(t, project.ID, "", "default", "viewer", "9"); r.Code != http.StatusOK {
		t.Fatalf("archived project list status=%d body=%s", r.Code, r.Body.String())
	}
}

func TestAssetDiscoveryNotebookValidationLimitAndAuditRollback(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "notebook-validation", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "q", time.Now(), "https://one.example.invalid")
	var source db.AssetDiscoverySnapshotItem
	_ = store.Where("snapshot_id = ?", snapshot.ID).First(&source).Error
	valid := `{"item_ids":[` + strconv.FormatUint(uint64(source.ID), 10) + `]}`
	for _, body := range []string{`{"item_ids":[]}`, `{"item_ids":[` + strconv.FormatUint(uint64(source.ID), 10) + `,` + strconv.FormatUint(uint64(source.ID), 10) + `]}`, `{"item_ids":[` + strconv.FormatUint(uint64(source.ID), 10) + `],"extra":true}`, valid + ` {}`} {
		if r := invokeNotebookArchive(t, project.ID, snapshot.ID, body, "default", "operator", "9"); r.Code != http.StatusBadRequest {
			t.Fatalf("invalid %q status=%d", body, r.Code)
		}
	}
	overse := `{"item_ids":[` + strings.TrimRight(strings.Repeat("1,", 101), ",") + `]}`
	if r := invokeNotebookArchive(t, project.ID, snapshot.ID, overse, "default", "operator", "9"); r.Code != http.StatusBadRequest {
		t.Fatalf("101 ids status=%d", r.Code)
	}
	big := `{"item_ids":[1],"pad":"` + strings.Repeat("a", int(assetDiscoveryRequestLimit)) + `"}`
	if r := invokeNotebookArchive(t, project.ID, snapshot.ID, big, "default", "operator", "9"); r.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status=%d", r.Code)
	}
	callback := "test:notebook-audit-update-failure"
	if err := store.Callback().Update().Before("gorm:update").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table == "asset_discovery_audits" {
			tx.AddError(gorm.ErrInvalidDB)
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer store.Callback().Update().Remove(callback)
	if r := invokeNotebookArchive(t, project.ID, snapshot.ID, valid, "default", "operator", "9"); r.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure status=%d %s", r.Code, r.Body.String())
	}
	var itemCount, sourceCount, auditCount int64
	store.Model(&db.AssetDiscoveryNotebookItem{}).Count(&itemCount)
	store.Model(&db.AssetDiscoveryNotebookSource{}).Count(&sourceCount)
	store.Model(&db.AssetDiscoveryAudit{}).Where("action = ?", "notebook_archive").Count(&auditCount)
	if itemCount != 0 || sourceCount != 0 || auditCount != 0 {
		t.Fatalf("audit failure left items=%d sources=%d audits=%d", itemCount, sourceCount, auditCount)
	}
}

func TestAssetDiscoveryNotebookRoutesUseRealRouterRBAC(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	seedAssetDiscoveryHistoryProject(t, store, "p", "default", "9")
	if matchPermission(http.MethodGet, "/api/v1/projects/p/asset-discovery/notebook-items") != "viewer" || matchPermission(http.MethodPost, "/api/v1/projects/p/asset-discovery/queries/1/notebook-items") != "operator" {
		t.Fatal("notebook route contract mismatch")
	}
	router := NewRouter(RouterDependencies{})
	unauthenticated := httptest.NewRecorder()
	router.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/asset-discovery/notebook-items", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list=%d", unauthenticated.Code)
	}
	for _, tt := range []struct {
		method, role, path string
		want               int
	}{{http.MethodGet, "viewer", "/api/v1/projects/p/asset-discovery/notebook-items", http.StatusOK}, {http.MethodPost, "viewer", "/api/v1/projects/p/asset-discovery/queries/1/notebook-items", http.StatusForbidden}, {http.MethodPost, "operator", "/api/v1/projects/p/asset-discovery/queries/1/notebook-items", http.StatusBadRequest}} {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"tenant_id": "default", "role": tt.role, "user_id": "9", "exp": time.Now().Add(time.Hour).Unix()})
		signed, err := token.SignedString(currentJWTSecret())
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(tt.method, tt.path, nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Fatalf("%s %s=%d body=%s", tt.method, tt.role, rec.Code, rec.Body.String())
		}
	}
}

func TestAssetDiscoveryNotebookArchiveRejectsProjectLimit(t *testing.T) {
	store := setupAssetDiscoveryTestDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "notebook-limit", "default", "9")
	snapshot := seedAssetDiscoveryHistorySnapshot(t, store, "default", project.ID, "fofa", "q", time.Now(), "https://new.example.invalid")
	var source db.AssetDiscoverySnapshotItem
	if err := store.Where("snapshot_id = ?", snapshot.ID).First(&source).Error; err != nil {
		t.Fatal(err)
	}
	items := make([]db.AssetDiscoveryNotebookItem, assetDiscoveryNotebookProjectMaxItems)
	for i := range items {
		items[i] = db.AssetDiscoveryNotebookItem{TenantID: "default", ProjectID: project.ID, NormalizedTarget: "https://existing-" + strconv.Itoa(i) + ".example.invalid", TargetHash: strings.Repeat("a", 60) + strconv.FormatInt(int64(i), 4), CreatedBy: "9"}
	}
	if err := store.CreateInBatches(&items, 500).Error; err != nil {
		t.Fatalf("seed limit items: %v", err)
	}
	r := invokeNotebookArchive(t, project.ID, snapshot.ID, `{"item_ids":[`+strconv.FormatUint(uint64(source.ID), 10)+`]}`, "default", "operator", "9")
	if r.Code != http.StatusConflict {
		t.Fatalf("limit status=%d body=%s", r.Code, r.Body.String())
	}
	var sourceCount, auditCount int64
	store.Model(&db.AssetDiscoveryNotebookSource{}).Count(&sourceCount)
	store.Model(&db.AssetDiscoveryAudit{}).Where("action = ?", "notebook_archive").Count(&auditCount)
	if sourceCount != 0 || auditCount != 0 {
		t.Fatalf("limit failure mutated sources=%d audits=%d", sourceCount, auditCount)
	}
}
