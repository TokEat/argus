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

func setupNotebookOperationsDB(t *testing.T) *gorm.DB {
	t.Helper()
	store := setupAssetDiscoveryTestDB(t)
	if err := store.AutoMigrate(&db.AssetDiscoveryNotebookTag{}, &db.AssetDiscoveryNotebookItemTag{}); err != nil {
		t.Fatalf("migrate notebook operations tables: %v", err)
	}
	return store
}

func seedNotebookOperationItem(t *testing.T, store *gorm.DB, tenant, projectID, target string) db.AssetDiscoveryNotebookItem {
	t.Helper()
	item := db.AssetDiscoveryNotebookItem{TenantID: tenant, ProjectID: projectID, NormalizedTarget: target, TargetHash: notebookDistributionTargetHash(target)}
	if err := store.Create(&item).Error; err != nil {
		t.Fatalf("seed notebook item: %v", err)
	}
	return item
}

func invokeNotebookOperation(t *testing.T, method, projectID string, itemID uint, suffix, body, tenant, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/notebook-items/" + strconv.FormatUint(uint64(itemID), 10) + suffix
	ctx, recorder := newTenantContextWithRole(method, path, role, userID)
	ctx.Set("tenant", tenant)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}, {Key: "item_id", Value: strconv.FormatUint(uint64(itemID), 10)}}
	ctx.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	switch suffix {
	case "/remove":
		removeProjectDiscoveryNotebookItem(ctx)
	case "/restore":
		restoreProjectDiscoveryNotebookItem(ctx)
	default:
		patchProjectDiscoveryNotebookItem(ctx)
	}
	ctx.Writer.WriteHeaderNow()
	return recorder
}

func invokeProjectNotebookOperationList(t *testing.T, projectID, query, tenant, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/projects/" + projectID + "/asset-discovery/notebook-items" + query
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, role, userID)
	ctx.Set("tenant", tenant)
	ctx.Params = gin.Params{{Key: "id", Value: projectID}}
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)
	listProjectDiscoveryNotebookItemsOperations(ctx)
	return recorder
}

func invokeTenantNotebookOperationList(t *testing.T, query, tenant, role, userID string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/asset-discovery/notebook-items" + query
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, role, userID)
	ctx.Set("tenant", tenant)
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)
	listTenantDiscoveryNotebookItems(ctx)
	return recorder
}

func TestNotebookOperationsPatchRemoveRestoreFiltersAndAudit(t *testing.T) {
	store := setupNotebookOperationsDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "notebook-operations", "default", "9")
	item := seedNotebookOperationItem(t, store, "default", project.ID, "https://operations.example.invalid")
	patch := invokeNotebookOperation(t, http.MethodPatch, project.ID, item.ID, "", `{"tags":[" Priority ","priority","Blue "],"note":"reviewed by operator"}`, "default", "operator", "9")
	if patch.Code != http.StatusNoContent {
		t.Fatalf("patch=%d %s", patch.Code, patch.Body.String())
	}
	var saved db.AssetDiscoveryNotebookItem
	if err := store.First(&saved, item.ID).Error; err != nil || saved.Note != "reviewed by operator" || saved.UpdatedBy != "9" {
		t.Fatalf("patched item=%+v err=%v", saved, err)
	}
	var names []string
	if err := store.Table("asset_discovery_notebook_tags").Order("name").Pluck("name", &names).Error; err != nil || strings.Join(names, ",") != "blue,priority" {
		t.Fatalf("tags=%v err=%v", names, err)
	}
	assertNotebookOperationAudit(t, store, "notebook_update", project.ID, "9", item.ID, 1)
	filtered := invokeProjectNotebookOperationList(t, project.ID, "?q=OPERATIONS&tag=priority", "default", "viewer", "9")
	var filteredResponse notebookOperationList
	if err := json.Unmarshal(filtered.Body.Bytes(), &filteredResponse); filtered.Code != http.StatusOK || err != nil || filteredResponse.ProjectID != project.ID || filteredResponse.Total != 1 || len(filteredResponse.Items) != 1 || len(filteredResponse.Items[0].Tags) != 2 {
		t.Fatalf("filtered list=%d response=%+v err=%v", filtered.Code, filteredResponse, err)
	}

	remove := invokeNotebookOperation(t, http.MethodPost, project.ID, item.ID, "/remove", "", "default", "operator", "9")
	if remove.Code != http.StatusNoContent {
		t.Fatalf("remove=%d %s", remove.Code, remove.Body.String())
	}
	for query, want := range map[string]int{"": 0, "?state=removed": 1, "?state=all": 1} {
		r := invokeProjectNotebookOperationList(t, project.ID, query, "default", "viewer", "9")
		if r.Code != http.StatusOK {
			t.Fatalf("list %q=%d %s", query, r.Code, r.Body.String())
		}
		var response notebookOperationList
		if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil || response.Total != int64(want) || len(response.Items) != want {
			t.Fatalf("list %q response=%+v err=%v", query, response, err)
		}
	}
	assertNotebookOperationAudit(t, store, "notebook_remove", project.ID, "9", item.ID, 1)
	restore := invokeNotebookOperation(t, http.MethodPost, project.ID, item.ID, "/restore", "", "default", "operator", "9")
	if restore.Code != http.StatusNoContent {
		t.Fatalf("restore=%d %s", restore.Code, restore.Body.String())
	}
	r := invokeProjectNotebookOperationList(t, project.ID, "", "default", "viewer", "9")
	var response notebookOperationList
	if err := json.Unmarshal(r.Body.Bytes(), &response); r.Code != http.StatusOK || err != nil || response.Total != 1 || response.Items[0].RemovedAt != nil || response.Items[0].Tags == nil || response.Items[0].FirstArchivedAt.IsZero() || response.Items[0].LastArchivedAt.IsZero() {
		t.Fatalf("restored list=%d response=%+v err=%v", r.Code, response, err)
	}
	assertNotebookOperationAudit(t, store, "notebook_restore", project.ID, "9", item.ID, 1)
}

func TestNotebookOperationsTenantListScopesAccessibleProjects(t *testing.T) {
	store := setupNotebookOperationsDB(t)
	owned := seedAssetDiscoveryHistoryProject(t, store, "notebook-owned", "default", "9")
	member := seedAssetDiscoveryHistoryProject(t, store, "notebook-member", "default", "10")
	hidden := seedAssetDiscoveryHistoryProject(t, store, "notebook-hidden", "default", "10")
	foreign := seedAssetDiscoveryHistoryProject(t, store, "notebook-foreign", "tenant-b", "9")
	if err := store.Create(&db.ProjectMember{TenantID: "default", ProjectID: member.ID, UserID: "9", Role: "viewer"}).Error; err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct{ tenant, project, target string }{{"default", owned.ID, "https://owned.example.invalid"}, {"default", member.ID, "https://member.example.invalid"}, {"default", hidden.ID, "https://hidden.example.invalid"}, {"tenant-b", foreign.ID, "https://foreign.example.invalid"}} {
		seedNotebookOperationItem(t, store, x.tenant, x.project, x.target)
	}
	r := invokeTenantNotebookOperationList(t, "", "default", "viewer", "9")
	if r.Code != http.StatusOK || strings.Contains(r.Body.String(), "hidden.example") || strings.Contains(r.Body.String(), "foreign.example") || !strings.Contains(r.Body.String(), "owned.example") || !strings.Contains(r.Body.String(), "member.example") {
		t.Fatalf("tenant list=%d %s", r.Code, r.Body.String())
	}
}

func TestNotebookOperationsRejectUnauthorizedInvalidAndForeignItemsWithoutAudit(t *testing.T) {
	store := setupNotebookOperationsDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "notebook-boundary-operations", "default", "9")
	other := seedAssetDiscoveryHistoryProject(t, store, "notebook-other-operations", "default", "9")
	item := seedNotebookOperationItem(t, store, "default", project.ID, "https://valid.example.invalid")
	foreignProjectItem := seedNotebookOperationItem(t, store, "default", other.ID, "https://other.example.invalid")
	foreignTenantItem := seedNotebookOperationItem(t, store, "tenant-b", project.ID, "https://tenant-b.example.invalid")

	for _, id := range []uint{foreignProjectItem.ID, foreignTenantItem.ID} {
		r := invokeNotebookOperation(t, http.MethodPost, project.ID, id, "/remove", "", "default", "operator", "9")
		if r.Code != http.StatusNotFound {
			t.Fatalf("foreign item %d=%d %s", id, r.Code, r.Body.String())
		}
	}
	for _, query := range []string{"?state=bogus", "?q=" + strings.Repeat("q", 257), "?tag=" + strings.Repeat("t", 65)} {
		if r := invokeProjectNotebookOperationList(t, project.ID, query, "default", "viewer", "9"); r.Code != http.StatusBadRequest {
			t.Fatalf("invalid list %q=%d", query, r.Code)
		}
	}
	for _, body := range []string{`{}`, `{"unknown":true}`, `{"note":"` + strings.Repeat("n", 4097) + `"}`, `{"tags":[" "]}`, `{"tags":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u"]}`, `{"note":"ok"} {}`} {
		if r := invokeNotebookOperation(t, http.MethodPatch, project.ID, item.ID, "", body, "default", "operator", "9"); r.Code != http.StatusBadRequest {
			t.Fatalf("invalid patch %q=%d %s", body, r.Code, r.Body.String())
		}
	}
	assertNotebookOperationAudit(t, store, "", "", "", 0, 0)

	router := NewRouter(RouterDependencies{})
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"tenant_id": "default", "role": "viewer", "user_id": "9", "exp": time.Now().Add(time.Hour).Unix()})
	signed, err := token.SignedString(currentJWTSecret())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/projects/"+project.ID+"/asset-discovery/notebook-items/"+strconv.FormatUint(uint64(item.ID), 10), strings.NewReader(`{"note":"blocked"}`))
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer patch=%d %s", rec.Code, rec.Body.String())
	}
	assertNotebookOperationAudit(t, store, "", "", "", 0, 0)
}

func TestNotebookOperationsRollBackWhenAuditCreateFails(t *testing.T) {
	store := setupNotebookOperationsDB(t)
	project := seedAssetDiscoveryHistoryProject(t, store, "notebook-audit-rollback-operations", "default", "9")
	item := seedNotebookOperationItem(t, store, "default", project.ID, "https://rollback.example.invalid")
	const callback = "test:notebook-operation-audit-create-failure"
	if err := store.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table == "asset_discovery_audits" {
			tx.AddError(gorm.ErrInvalidDB)
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Callback().Create().Remove(callback) })
	r := invokeNotebookOperation(t, http.MethodPatch, project.ID, item.ID, "", `{"tags":["rollback"],"note":"must not persist"}`, "default", "operator", "9")
	if r.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure=%d %s", r.Code, r.Body.String())
	}
	var reloaded db.AssetDiscoveryNotebookItem
	if err := store.First(&reloaded, item.ID).Error; err != nil || reloaded.Note != "" {
		t.Fatalf("reloaded=%+v err=%v", reloaded, err)
	}
	var links, audits int64
	store.Model(&db.AssetDiscoveryNotebookItemTag{}).Count(&links)
	store.Model(&db.AssetDiscoveryAudit{}).Count(&audits)
	if links != 0 || audits != 0 {
		t.Fatalf("rollback left links=%d audits=%d", links, audits)
	}
}

func assertNotebookOperationAudit(t *testing.T, store *gorm.DB, action, projectID, userID string, itemID uint, want int64) {
	t.Helper()
	q := store.Model(&db.AssetDiscoveryAudit{})
	if action != "" {
		q = q.Where("action=? AND project_id=? AND operator_id=?", action, projectID, userID)
	}
	var count int64
	if err := q.Count(&count).Error; err != nil || count != want {
		t.Fatalf("audit action=%q count=%d want=%d err=%v", action, count, want, err)
	}
	if want == 1 {
		var audit db.AssetDiscoveryAudit
		if err := q.First(&audit).Error; err != nil {
			t.Fatalf("load audit action=%q: %v", action, err)
		}
		if audit.NotebookItemID == nil || *audit.NotebookItemID != itemID || len(audit.QueryHash) != 64 || len(audit.ConfigHash) != 64 {
			t.Fatalf("audit is not safely correlated to notebook item: %+v", audit)
		}
	}
}
