package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupContentFindingsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.Project{}, &db.CrawlSiteCandidate{}, &db.SensitiveFinding{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := db.DB
	db.DB = store
	t.Cleanup(func() {
		db.DB = old
	})
	return store
}

func TestListCrawlSiteCandidatesFiltersBySiteType(t *testing.T) {
	store := setupContentFindingsTestDB(t)
	now := time.Now()
	if err := store.Create(&[]db.Project{
		{ID: "project-1", TenantID: "default", Name: "P1", Status: "active"},
		{ID: "project-2", TenantID: "default", Name: "P2", Status: "active"},
	}).Error; err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	candidates := []db.CrawlSiteCandidate{
		{TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1", URL: "http://h:8080/app1", SiteType: "path_app", AIStatus: "confirmed", DedupeHash: "h1", CreatedAt: now, UpdatedAt: now},
		{TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1", URL: "http://h:8080/internal", SiteType: "hidden_path", AIStatus: "pending", DedupeHash: "h2", CreatedAt: now, UpdatedAt: now},
		{TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1", URL: "http://h:8081/", SiteType: "", AIStatus: "confirmed", DedupeHash: "h3", CreatedAt: now, UpdatedAt: now},
		{TenantID: "default", ProjectID: "project-2", TaskID: "t2", RootTaskID: "t2", URL: "http://other:9000/app9", SiteType: "path_app", AIStatus: "confirmed", DedupeHash: "h4", CreatedAt: now, UpdatedAt: now},
	}
	if err := store.Create(&candidates).Error; err != nil {
		t.Fatalf("seed candidates: %v", err)
	}

	// site_type=path_app 只命中 project-1 的 path_app 行（project-2 被项目范围隔离）。
	ctx, recorder := newTenantContext(http.MethodGet, "/crawl-site-candidates?project_id=project-1&site_type=path_app")
	listCrawlSiteCandidates(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged crawl candidates, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Items    []db.CrawlSiteCandidate `json:"items"`
		Total    int64                   `json:"total"`
		PageSize int                     `json:"page_size"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode crawl response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].SiteType != "path_app" || resp.Items[0].URL != "http://h:8080/app1" {
		t.Fatalf("unexpected site_type filter result: %+v", resp)
	}

	// 不带 site_type 时 project-1 共 3 条。
	ctx, recorder = newTenantContext(http.MethodGet, "/crawl-site-candidates?project_id=project-1")
	listCrawlSiteCandidates(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected unfiltered crawl candidates, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	resp = struct {
		Items    []db.CrawlSiteCandidate `json:"items"`
		Total    int64                   `json:"total"`
		PageSize int                     `json:"page_size"`
	}{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode unfiltered crawl response: %v", err)
	}
	if resp.Total != 3 || len(resp.Items) != 3 {
		t.Fatalf("unexpected unfiltered result: total=%d items=%d", resp.Total, len(resp.Items))
	}

	// site_type=hidden_path 只命中 1 条。
	ctx, recorder = newTenantContext(http.MethodGet, "/crawl-site-candidates?project_id=project-1&site_type=hidden_path")
	listCrawlSiteCandidates(ctx)
	resp = struct {
		Items    []db.CrawlSiteCandidate `json:"items"`
		Total    int64                   `json:"total"`
		PageSize int                     `json:"page_size"`
	}{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode hidden_path response: %v", err)
	}
	if resp.Total != 1 || resp.Items[0].SiteType != "hidden_path" {
		t.Fatalf("unexpected hidden_path result: %+v", resp)
	}
}

func TestListSensitiveFindingsFiltersByKind(t *testing.T) {
	store := setupContentFindingsTestDB(t)
	now := time.Now()
	if err := store.Create(&[]db.Project{
		{ID: "project-1", TenantID: "default", Name: "P1", Status: "active"},
	}).Error; err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	findings := []db.SensitiveFinding{
		{TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1", Host: "h", Kind: "apikey", Value: "AKIAIOSFODNN7EXAMPLE", AIStatus: "confirmed", DedupeHash: "s1", CreatedAt: now, UpdatedAt: now},
		{TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1", Host: "h", Kind: "username", Value: "zhang.wei", AIStatus: "pending", DedupeHash: "s2", CreatedAt: now, UpdatedAt: now},
		{TenantID: "default", ProjectID: "project-1", TaskID: "t1", RootTaskID: "t1", Host: "h", Kind: "email", Value: "a@b.c", AIStatus: "confirmed", DedupeHash: "s3", CreatedAt: now, UpdatedAt: now},
	}
	if err := store.Create(&findings).Error; err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/sensitive-findings?project_id=project-1&kind=username")
	listSensitiveFindings(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged sensitive findings, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Items []db.SensitiveFinding `json:"items"`
		Total int64                 `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode sensitive response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].Kind != "username" || resp.Items[0].Value != "zhang.wei" {
		t.Fatalf("unexpected kind filter result: %+v", resp)
	}
}
