package api

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

// newProjectDataContext 建一个带 tenant-a/user-a 身份的可复用 gin 上下文。
func newProjectDataContext(method, target string, body io.Reader, contentType string) (*gin.Context, *httptest.ResponseRecorder) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(method, target, body)
	if contentType != "" {
		c.Request.Header.Set("Content-Type", contentType)
	}
	c.Set("tenant", "tenant-a")
	c.Set("user_id", "user-a")
	c.Set("role", "admin")
	return c, recorder
}

// buildTestBundle 按导出 envelope 的**有序**形状构造 gzip JSON（meta 先于数据，
// 与真实导出一致；map 直转会把键按字典序排乱导致 new 模式拿不到 project）。
func buildTestBundle(t *testing.T, project interface{}, sections map[string]interface{}) []byte {
	t.Helper()
	return buildTestBundleVersioned(t, projectDataExportFormatVersion, project, sections)
}

func buildTestBundleVersioned(t *testing.T, version int, project interface{}, sections map[string]interface{}) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	if _, err := fmt.Fprintf(gz, `{"format_version":%d,"exported_at":%q,"project":`, version, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	if err := enc.Encode(project); err != nil {
		t.Fatalf("encode project: %v", err)
	}
	for _, k := range []string{"assets", "vulnerabilities", "fingerprint_hits", "domains"} {
		if v, ok := sections[k]; ok {
			if _, err := gz.Write([]byte(",\"" + k + "\":")); err != nil {
				t.Fatalf("write key: %v", err)
			}
			if err := enc.Encode(v); err != nil {
				t.Fatalf("encode %s: %v", k, err)
			}
		}
	}
	if _, err := gz.Write([]byte("}")); err != nil {
		t.Fatalf("close envelope: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func multipartFileBody(t *testing.T, field, filename string, data []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return &buf, w.FormDataContentType()
}

type exportBundleForTest struct {
	FormatVersion   int                 `json:"format_version"`
	Project         map[string]string   `json:"project"`
	Assets          []db.Asset          `json:"assets"`
	Vulnerabilities []db.Vulnerability  `json:"vulnerabilities"`
	FingerprintHits []db.FingerprintHit `json:"fingerprint_hits"`
	Domains         []db.Domain         `json:"domains"`
}

func TestExportProjectDataScopesAndFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)

	project := db.Project{ID: "pd-export", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "Export Me"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	assets := []db.Asset{
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "https://a.example", Protocol: "Web", Title: "a"},
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "1.1.1.1:80", Protocol: "PortScan", Port: 80},
		{TenantID: "tenant-b", ProjectID: "foreign", Target: "https://secret.example", Protocol: "Web"},
	}
	vulns := []db.Vulnerability{
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "https://a.example", Plugin: "p1", Severity: "high"},
		{TenantID: "tenant-b", ProjectID: "foreign", Target: "https://x.example", Plugin: "px", Severity: "low"},
	}
	fps := []db.FingerprintHit{
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "https://a.example", ProductName: "nginx"},
	}
	domains := []db.Domain{
		{TenantID: "tenant-a", ProjectID: project.ID, Name: "a.example"},
	}
	for _, rows := range []interface{}{&assets, &vulns, &fps, &domains} {
		if err := store.Create(rows).Error; err != nil {
			t.Fatal(err)
		}
	}

	c, recorder := newProjectDataContext("GET", "/projects/"+project.ID+"/export", nil, "")
	c.Params = gin.Params{{Key: "id", Value: project.ID}}
	exportProjectData(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if ct := recorder.Header().Get("Content-Type"); ct != "application/gzip" {
		t.Fatalf("content-type=%q", ct)
	}
	if cd := recorder.Header().Get("Content-Disposition"); cd == "" {
		t.Fatalf("missing content-disposition")
	}

	gzr, err := gzip.NewReader(recorder.Body)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	var bundle exportBundleForTest
	if err := json.NewDecoder(gzr).Decode(&bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if bundle.FormatVersion != projectDataExportFormatVersion {
		t.Fatalf("format_version=%d", bundle.FormatVersion)
	}
	if bundle.Project["name"] != "Export Me" {
		t.Fatalf("project meta=%v", bundle.Project)
	}
	if len(bundle.Assets) != 2 || len(bundle.Vulnerabilities) != 1 || len(bundle.FingerprintHits) != 1 || len(bundle.Domains) != 1 {
		t.Fatalf("counts assets=%d vulns=%d fps=%d domains=%d", len(bundle.Assets), len(bundle.Vulnerabilities), len(bundle.FingerprintHits), len(bundle.Domains))
	}
	for _, a := range bundle.Assets {
		if a.TenantID != "tenant-a" || a.ProjectID != project.ID {
			t.Fatalf("asset scope leaked: %+v", a)
		}
	}
	for _, v := range bundle.Vulnerabilities {
		if v.TenantID != "tenant-a" || v.Plugin != "p1" {
			t.Fatalf("vuln scope leaked: %+v", v)
		}
	}
}

func TestImportProjectDataNewMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)

	// 文件里故意带外来 tenant / 项目 / 自增 ID，导入后必须被重定。
	bundle := buildTestBundle(t,
		map[string]string{"name": "Round Trip", "description": "d", "tags": `["x"]`},
		map[string]interface{}{
			"assets": []db.Asset{
				{ID: 99, TenantID: "tenant-evil", ProjectID: "proj-evil", Target: "https://a.example", Protocol: "Web", Title: "a"},
				{ID: 100, TenantID: "tenant-evil", ProjectID: "proj-evil", Target: "1.1.1.1:80", Protocol: "PortScan", Port: 80},
			},
			"vulnerabilities": []db.Vulnerability{
				{ID: 7, TenantID: "tenant-evil", ProjectID: "proj-evil", Target: "https://a.example", Plugin: "p1", Severity: "high"},
			},
			"fingerprint_hits": []db.FingerprintHit{
				{ID: 5, TenantID: "tenant-evil", ProjectID: "proj-evil", Target: "https://a.example", ProductName: "nginx"},
			},
			"domains": []db.Domain{
				{ID: 3, TenantID: "tenant-evil", ProjectID: "proj-evil", Name: "a.example"},
			},
		})
	body, contentType := multipartFileBody(t, "file", "rt.argus.json.gz", bundle)

	c, recorder := newProjectDataContext("POST", "/projects/import?mode=new", body, contentType)
	importProjectData(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result projectDataImportResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Mode != "new" || result.ProjectID == "" {
		t.Fatalf("result=%+v", result)
	}
	if result.Counts["assets"].Inserted != 2 || result.Counts["assets"].Updated != 0 {
		t.Fatalf("asset counts=%+v", result.Counts["assets"])
	}
	if result.Counts["vulnerabilities"].Inserted != 1 || result.Counts["fingerprint_hits"].Inserted != 1 || result.Counts["domains"].Inserted != 1 {
		t.Fatalf("counts=%+v", result.Counts)
	}

	var proj db.Project
	if err := store.Where("id = ?", result.ProjectID).First(&proj).Error; err != nil {
		t.Fatalf("project not created: %v", err)
	}
	if proj.TenantID != "tenant-a" || proj.OwnerUserID != "user-a" {
		t.Fatalf("project scope=%+v", proj)
	}
	if proj.Name != "Round Trip (导入)" {
		t.Fatalf("project name=%q", proj.Name)
	}

	var assets []db.Asset
	if err := store.Where("project_id = ?", result.ProjectID).Find(&assets).Error; err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 {
		t.Fatalf("assets=%d", len(assets))
	}
	for _, a := range assets {
		if a.TenantID != "tenant-a" || a.ProjectID != result.ProjectID {
			t.Fatalf("asset not rescoped: %+v", a)
		}
		if a.ID == 99 || a.ID == 100 {
			t.Fatalf("asset ID not regenerated: %+v", a)
		}
	}
	var member db.ProjectMember
	if err := store.Where("project_id = ? AND user_id = ?", result.ProjectID, "user-a").First(&member).Error; err != nil {
		t.Fatalf("owner membership missing: %v", err)
	}
	if member.Role != "owner" {
		t.Fatalf("member role=%q", member.Role)
	}
}

func TestImportProjectDataMergeModeIdempotent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)

	project := db.Project{ID: "pd-merge", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "Merge Target"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}

	bundle := buildTestBundle(t,
		map[string]string{"name": "Merge Target"},
		map[string]interface{}{
			"assets": []db.Asset{
				{TenantID: "tenant-a", ProjectID: project.ID, Target: "https://a.example", Protocol: "Web", Title: "v1"},
			},
			"vulnerabilities": []db.Vulnerability{
				{TenantID: "tenant-a", ProjectID: project.ID, Target: "https://a.example", Plugin: "p1", Severity: "high"},
			},
		})

	importOnce := func() projectDataImportResult {
		body, contentType := multipartFileBody(t, "file", "m.argus.json.gz", bundle)
		c, recorder := newProjectDataContext("POST", "/projects/import?mode=merge&project_id="+project.ID, body, contentType)
		importProjectData(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var r projectDataImportResult
		if err := json.Unmarshal(recorder.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}

	first := importOnce()
	if first.ProjectID != project.ID {
		t.Fatalf("merge target=%q want %q", first.ProjectID, project.ID)
	}
	if first.Counts["assets"].Inserted != 1 || first.Counts["assets"].Updated != 0 {
		t.Fatalf("first asset counts=%+v", first.Counts["assets"])
	}

	second := importOnce()
	if second.Counts["assets"].Inserted != 0 || second.Counts["assets"].Updated != 1 {
		t.Fatalf("second asset counts=%+v (want idempotent upsert)", second.Counts["assets"])
	}

	var assetCount int64
	if err := store.Model(&db.Asset{}).Where("project_id = ?", project.ID).Count(&assetCount).Error; err != nil {
		t.Fatal(err)
	}
	if assetCount != 1 {
		t.Fatalf("dup assets=%d want 1", assetCount)
	}
}

func TestImportProjectDataRejectsBadInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupAITestDB(t)

	// 坏 gzip
	body, ct := multipartFileBody(t, "file", "bad.gz", []byte("not gzip at all"))
	c, recorder := newProjectDataContext("POST", "/projects/import?mode=new", body, ct)
	importProjectData(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bad gzip status=%d", recorder.Code)
	}

	// 不支持的 format_version
	badVersion := buildTestBundleVersioned(t, 999, map[string]string{"name": "x"}, map[string]interface{}{
		"assets": []db.Asset{},
	})
	body, ct = multipartFileBody(t, "file", "v.argus.json.gz", badVersion)
	c, recorder = newProjectDataContext("POST", "/projects/import?mode=new", body, ct)
	importProjectData(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bad version status=%d", recorder.Code)
	}

	// 缺 mode
	body, ct = multipartFileBody(t, "file", "x.argus.json.gz", badVersion)
	c, recorder = newProjectDataContext("POST", "/projects/import", body, ct)
	importProjectData(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("missing mode status=%d", recorder.Code)
	}

	// merge 缺 project_id
	c, recorder = newProjectDataContext("POST", "/projects/import?mode=merge", body, ct)
	importProjectData(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("merge missing project status=%d", recorder.Code)
	}
}

func TestImportProjectDataMergeForbiddenForNonOwner(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)

	project := db.Project{ID: "pd-owned-by-other", TenantID: "tenant-a", OwnerUserID: "user-other", Name: "Other"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	bundle := buildTestBundle(t, map[string]string{"name": "Other"}, map[string]interface{}{
		"assets": []db.Asset{{TenantID: "tenant-a", ProjectID: project.ID, Target: "https://a.example", Protocol: "Web"}},
	})
	body, ct := multipartFileBody(t, "file", "m.argus.json.gz", bundle)

	c, recorder := newProjectDataContext("POST", "/projects/import?mode=merge&project_id="+project.ID, body, ct)
	c.Set("role", "viewer") // user-a 不是 owner，也不是 admin
	importProjectData(c)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestProjectDataMatchPermission(t *testing.T) {
	if got := matchPermission("GET", "/api/v1/projects/p1/export"); got != "viewer" {
		t.Fatalf("export perm=%q want viewer", got)
	}
	if got := matchPermission("POST", "/api/v1/projects/import"); got != "operator" {
		t.Fatalf("import perm=%q want operator", got)
	}
	if got := matchPermission("GET", "/api/v1/domains"); got != "viewer" {
		t.Fatalf("domains perm=%q want viewer", got)
	}
}

func TestGetDomainsProjectScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)

	project := db.Project{ID: "pd-domains", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "Domains"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&[]db.Domain{
		{TenantID: "tenant-a", ProjectID: project.ID, Name: "a.example"},
		{TenantID: "tenant-a", ProjectID: project.ID, Name: "b.example"},
		{TenantID: "tenant-b", ProjectID: "foreign", Name: "secret.example"},
	}).Error; err != nil {
		t.Fatal(err)
	}

	c, recorder := newProjectDataContext("GET", "/domains?project_id="+project.ID, nil, "")
	c.Set("role", "viewer")
	getDomains(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var page struct {
		Items []db.Domain `json:"items"`
		Total int64       `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("domains page=%+v", page)
	}
	for _, d := range page.Items {
		if d.TenantID != "tenant-a" || d.Name == "secret.example" {
			t.Fatalf("domain leaked: %+v", d)
		}
	}
}
