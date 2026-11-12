package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// assetFilterFixture 种一个项目 + root/attempt + 3 条资产（web×2、host_port×1）
// + 2 条同任务指纹命中 + 1 条跨租户指纹（用于验证子查询租户/项目作用域）。
func assetFilterFixture(t *testing.T) (store *gorm.DB, projectID, rootID string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store = setupAITestDB(t)
	projectID = "afp"
	rootID = "af-root"
	project := db.Project{ID: projectID, TenantID: "tenant-a", OwnerUserID: "user-a", Name: "AF"}
	root := db.RootTask{ID: rootID, TenantID: "tenant-a", ProjectID: projectID, UserID: "user-a", Status: "Finished"}
	attempt := db.SubTask{ID: "af-attempt", TenantID: "tenant-a", ProjectID: projectID, RootTaskID: rootID, Status: "Finished"}
	for _, row := range []interface{}{&project, &root, &attempt} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	assets := []db.Asset{
		{TenantID: "tenant-a", ProjectID: projectID, TaskID: attempt.ID, RootTaskID: rootID, Target: "https://a.example", Protocol: "Web", Title: "Admin Console", Service: "nginx"},
		{TenantID: "tenant-a", ProjectID: projectID, TaskID: attempt.ID, RootTaskID: rootID, Target: "https://b.example", Protocol: "Web", Title: "Travel Blog", Service: "apache"},
		{TenantID: "tenant-a", ProjectID: projectID, TaskID: attempt.ID, RootTaskID: rootID, Target: "192.0.2.20:22", Protocol: "PortScan", Port: 22, Service: "ssh"},
		{TenantID: "tenant-b", ProjectID: "foreign", TaskID: "foreign-task", Target: "https://secret.example", Protocol: "Web"},
	}
	if err := store.Create(&assets).Error; err != nil {
		t.Fatalf("seed assets: %v", err)
	}
	fps := []db.FingerprintHit{
		{TenantID: "tenant-a", ProjectID: projectID, TaskID: attempt.ID, RootTaskID: rootID, Target: "https://a.example", ProductName: "Apache-Shiro", RuleName: "r-shiro"},
		{TenantID: "tenant-a", ProjectID: projectID, TaskID: attempt.ID, RootTaskID: rootID, Target: "https://b.example", ProductName: "WordPress", RuleName: "r-wp"},
		{TenantID: "tenant-b", ProjectID: "foreign", TaskID: "foreign-task", Target: "https://a.example", ProductName: "EvilForeign", RuleName: "r-evil"},
	}
	if err := store.Create(&fps).Error; err != nil {
		t.Fatalf("seed fingerprints: %v", err)
	}
	return store, projectID, rootID
}

func assetPageForTest(t *testing.T, recorder *httptest.ResponseRecorder) resultPageForTest[db.Asset] {
	t.Helper()
	if recorder.Code != 200 {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var page resultPageForTest[db.Asset]
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode asset page: %v", err)
	}
	return page
}

func assetTargets(page resultPageForTest[db.Asset]) []string {
	out := make([]string, 0, len(page.Items))
	for _, item := range page.Items {
		out = append(out, item.Target)
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestGetAssetsMultiColumnSearch(t *testing.T) {
	_, projectID, _ := assetFilterFixture(t)
	base := "/assets?project_id=" + projectID

	// 标题命中（仅 B 标题含 "Travel"，目标里不含）。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&search=Travel", getAssets)); page.Total != 1 || page.Items[0].Target != "https://b.example" {
		t.Fatalf("search=Travel wrong: %+v", page)
	}
	// 服务命中（仅 A 服务为 nginx）。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&search=nginx", getAssets)); page.Total != 1 || page.Items[0].Target != "https://a.example" {
		t.Fatalf("search=nginx wrong: %+v", page)
	}
	// 目标命中（仅 C 目标含 IP）。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&search=192.0.2.20", getAssets)); page.Total != 1 || page.Items[0].Target != "192.0.2.20:22" {
		t.Fatalf("search=192.0.2.20 wrong: %+v", page)
	}
	// 无命中。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&search=definitely-not-exist", getAssets)); page.Total != 0 {
		t.Fatalf("empty search should be 0: %+v", page)
	}
}

func TestGetAssetsServiceAndTitleFilter(t *testing.T) {
	_, projectID, _ := assetFilterFixture(t)
	base := "/assets?project_id=" + projectID

	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&service=ssh", getAssets)); page.Total != 1 || page.Items[0].Target != "192.0.2.20:22" {
		t.Fatalf("service=ssh wrong: %+v", page)
	}
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&service=nginx,apache", getAssets)); page.Total != 2 {
		t.Fatalf("service=nginx,apache wrong: %+v", page)
	}
	// 仅排除：除 apache 外全留（A + C）。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&service=!apache", getAssets)); page.Total != 2 || containsString(assetTargets(page), "https://b.example") {
		t.Fatalf("service=!apache wrong: %+v", page)
	}
	// 标题排除：除 "Travel Blog" 外全留（A + C）。空格须 URL 编码。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&title=!Travel%20Blog", getAssets)); page.Total != 2 || containsString(assetTargets(page), "https://b.example") {
		t.Fatalf("title=!Travel Blog wrong: %+v", page)
	}
	// 服务包含 + 标题排除组合：nginx/apache 里去掉 Travel Blog → 仅 A。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&service=nginx,apache&title=!Travel%20Blog", getAssets)); page.Total != 1 || page.Items[0].Target != "https://a.example" {
		t.Fatalf("service+title combo wrong: %+v", page)
	}
}

func TestGetAssetsFingerprintFilter(t *testing.T) {
	_, projectID, rootID := assetFilterFixture(t)
	base := "/assets?project_id=" + projectID

	// 包含：仅命中 Apache-Shiro 的资产 A。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&fingerprint=Apache-Shiro", getAssets)); page.Total != 1 || page.Items[0].Target != "https://a.example" {
		t.Fatalf("fingerprint=Apache-Shiro wrong: %+v", page)
	}
	// 多值包含：A + B。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&fingerprint=Apache-Shiro,WordPress", getAssets)); page.Total != 2 {
		t.Fatalf("fingerprint include both wrong: %+v", page)
	}
	// 排除 WordPress：A + C。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&fingerprint=!WordPress", getAssets)); page.Total != 2 || containsString(assetTargets(page), "https://b.example") {
		t.Fatalf("fingerprint=!WordPress wrong: %+v", page)
	}
	// 跨租户指纹产品（tenant-b 的 EvilForeign）：子查询被 tenant/project 作用域挡掉 → 0。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, base+"&fingerprint=EvilForeign", getAssets)); page.Total != 0 {
		t.Fatalf("fingerprint=EvilForeign must be scoped out: %+v", page)
	}
	// 与任务作用域组合：有效任务 → A；不存在任务 → 0。
	if page := assetPageForTest(t, invokeTaskResultHandler(t, "/assets?project_id="+projectID+"&task_id="+rootID+"&fingerprint=Apache-Shiro", getAssets)); page.Total != 1 {
		t.Fatalf("fingerprint with valid task wrong: %+v", page)
	}
	if page := assetPageForTest(t, invokeTaskResultHandler(t, "/assets?project_id="+projectID+"&task_id=missing&fingerprint=Apache-Shiro", getAssets)); page.Total != 0 {
		t.Fatalf("fingerprint with missing task should be 0: %+v", page)
	}
}

type assetFacetsForTest struct {
	Services []struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	} `json:"services"`
	Fingerprints []struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	} `json:"fingerprints"`
}

func invokeAssetFacetsHandler(t *testing.T, taskID, query string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("GET", "/tasks/"+taskID+"/assets/facets?"+query, nil)
	c.Set("tenant", "tenant-a")
	c.Set("user_id", "user-a")
	c.Set("role", "operator")
	c.Params = gin.Params{{Key: "id", Value: taskID}}
	getAssetFacets(c)
	return recorder
}

func facetValues(items []struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Value)
	}
	return out
}

func TestGetAssetFacets(t *testing.T) {
	_, projectID, rootID := assetFilterFixture(t)

	recorder := invokeAssetFacetsHandler(t, rootID, "project_id="+projectID)
	if recorder.Code != 200 {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var facets assetFacetsForTest
	if err := json.Unmarshal(recorder.Body.Bytes(), &facets); err != nil {
		t.Fatalf("decode facets: %v", err)
	}
	services := facetValues(facets.Services)
	for _, want := range []string{"nginx", "apache", "ssh"} {
		if !containsString(services, want) {
			t.Fatalf("services missing %q: %v", want, services)
		}
	}
	fingerprints := facetValues(facets.Fingerprints)
	for _, want := range []string{"Apache-Shiro", "WordPress"} {
		if !containsString(fingerprints, want) {
			t.Fatalf("fingerprints missing %q: %v", want, fingerprints)
		}
	}
	if containsString(fingerprints, "EvilForeign") {
		t.Fatalf("tenant-b fingerprint leaked into facets: %v", fingerprints)
	}

	// kind=web 视图：服务下拉只剩 web 资产的服务（去掉 ssh）。
	webRecorder := invokeAssetFacetsHandler(t, rootID, "project_id="+projectID+"&kind=web")
	var webFacets assetFacetsForTest
	if err := json.Unmarshal(webRecorder.Body.Bytes(), &webFacets); err != nil {
		t.Fatalf("decode web facets: %v", err)
	}
	if webRecorder.Code != 200 || containsString(facetValues(webFacets.Services), "ssh") || len(webFacets.Services) != 2 {
		t.Fatalf("kind=web facets wrong: %s", webRecorder.Body.String())
	}

	// 不存在任务：空数组而非 null。
	emptyRecorder := invokeAssetFacetsHandler(t, "missing", "project_id="+projectID)
	if emptyRecorder.Code != 200 {
		t.Fatalf("status=%d body=%s", emptyRecorder.Code, emptyRecorder.Body.String())
	}
	if !strings.Contains(emptyRecorder.Body.String(), `"services":[]`) || !strings.Contains(emptyRecorder.Body.String(), `"fingerprints":[]`) {
		t.Fatalf("empty facets should serialize as [], got %s", emptyRecorder.Body.String())
	}

	// 未知 kind：400。
	badRecorder := invokeAssetFacetsHandler(t, rootID, "project_id="+projectID+"&kind=nope")
	if badRecorder.Code != 400 {
		t.Fatalf("unknown kind should be 400, got %d", badRecorder.Code)
	}
}
