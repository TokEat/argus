package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupResultsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.Project{}, &db.Vulnerability{}, &db.FingerprintHit{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := db.DB
	db.DB = store
	t.Cleanup(func() {
		db.DB = old
	})
	return store
}

func TestGetVulnReturnsEvidenceBundleScopedToProject(t *testing.T) {
	store := setupResultsTestDB(t)
	now := time.Now()
	if err := store.Create(&[]db.Project{
		{ID: "project-1", TenantID: "default", Name: "P1", Status: "active"},
		{ID: "project-2", TenantID: "default", Name: "P2", Status: "active"},
	}).Error; err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	vuln := db.Vulnerability{
		TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1",
		Target: "http://h:8080/admin", Plugin: "poc-sqli", Severity: "critical",
		Request:   "POST /admin HTTP/1.1\r\nHost: h\r\n\r\nid=1'",
		Response:  "HTTP/1.1 500\r\n\r\nSQL error",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := store.Create(&vuln).Error; err != nil {
		t.Fatalf("seed vuln: %v", err)
	}

	// 本项目可读且带证据包。
	ctx, recorder := newTenantContext(http.MethodGet, "/vulns/"+fmt.Sprint(vuln.ID)+"?project_id=project-1")
	ctx.Params = gin.Params{{Key: "id", Value: fmt.Sprint(vuln.ID)}}
	getVuln(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected vuln detail, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var got db.Vulnerability
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode vuln detail: %v", err)
	}
	if got.Request != vuln.Request || got.Response != vuln.Response || got.Severity != "critical" {
		t.Fatalf("evidence bundle incomplete: %+v", got)
	}

	// 跨项目访问返回 404（project 收敛）。
	ctx, recorder = newTenantContext(http.MethodGet, "/vulns/"+fmt.Sprint(vuln.ID)+"?project_id=project-2")
	ctx.Params = gin.Params{{Key: "id", Value: fmt.Sprint(vuln.ID)}}
	getVuln(ctx)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected cross-project 404, got %d", recorder.Code)
	}
}

func TestGetFingerprintsListAppliesSearchFilter(t *testing.T) {
	store := setupResultsTestDB(t)
	now := time.Now()
	if err := store.Create(&[]db.Project{
		{ID: "project-1", TenantID: "default", Name: "P1", Status: "active"},
	}).Error; err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	hits := []db.FingerprintHit{
		{TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1", Target: "http://h:8080", ProductName: "Shiro", RuleName: "r1", CreatedAt: now, UpdatedAt: now},
		{TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1", Target: "http://h:8080/login", ProductName: "Shiro", RuleName: "r2", CreatedAt: now, UpdatedAt: now},
		{TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1", Target: "http://h:8080", ProductName: "Nginx", RuleName: "r3", CreatedAt: now, UpdatedAt: now},
	}
	if err := store.Create(&hits).Error; err != nil {
		t.Fatalf("seed fingerprints: %v", err)
	}

	// 按产品名搜索。
	ctx, recorder := newTenantContext(http.MethodGet, "/fingerprints?project_id=project-1&search=Shiro")
	getFingerprints(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected fingerprints list, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Items []db.FingerprintHit `json:"items"`
		Total int64               `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode fingerprints: %v", err)
	}
	if resp.Total != 2 || len(resp.Items) != 2 {
		t.Fatalf("unexpected product search result: %+v", resp)
	}

	// 按 target 搜索。
	ctx, recorder = newTenantContext(http.MethodGet, "/fingerprints?project_id=project-1&search=login")
	getFingerprints(ctx)
	resp = struct {
		Items []db.FingerprintHit `json:"items"`
		Total int64               `json:"total"`
	}{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode target search: %v", err)
	}
	if resp.Total != 1 || resp.Items[0].RuleName != "r2" {
		t.Fatalf("unexpected target search result: %+v", resp)
	}
}
