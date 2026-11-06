package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

type vulnFacetsForTest struct {
	Plugins []struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	} `json:"plugins"`
	Statuses []struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	} `json:"statuses"`
	AIStatuses []struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	} `json:"ai_statuses"`
	Hosts []struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	} `json:"hosts"`
	Ports []struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	} `json:"ports"`
}

func invokeVulnFacetsHandler(t *testing.T, taskID, query string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("GET", "/tasks/"+taskID+"/vulns/facets?"+query, nil)
	c.Set("tenant", "tenant-a")
	c.Set("user_id", "user-a")
	c.Set("role", "operator")
	c.Params = gin.Params{{Key: "id", Value: taskID}}
	getVulnFacets(c)
	return recorder
}

// TestVulnFilterSortAndFacets 覆盖 getVulns 的 plugin/ai_status/status 过滤、
// 多列排序白名单与 getVulnFacets 的 distinct 计数/租户隔离。
func TestVulnFilterSortAndFacets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)
	now := time.Now().UTC()

	project := db.Project{ID: "project-vf", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "VF"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	root := db.RootTask{ID: "task-vf", TenantID: "tenant-a", ProjectID: project.ID, UserID: "user-a", Status: "Finished"}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	sub := db.SubTask{ID: "attempt-vf", TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: root.ID, BatchID: "batch-vf", Status: "Finished"}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed sub: %v", err)
	}
	vulns := []db.Vulnerability{
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "b.example", Plugin: "poc-xss", Severity: "High", Status: "open", AIStatus: "confirmed", CreatedAt: now.Add(-3 * time.Hour)},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "a.example", Plugin: "poc-xss", Severity: "Low", Status: "open", CreatedAt: now.Add(-2 * time.Hour)},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "c.example", Plugin: "poc-rce", Severity: "Critical", Status: "ignored", AIStatus: "likely_false_positive", CreatedAt: now.Add(-1 * time.Hour)},
		// 其他租户：不应出现在任何过滤/facets 结果中（用独占插件名验证租户隔离）。
		{TenantID: "tenant-b", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "z.example", Plugin: "poc-zz-tenantb", Severity: "High", Status: "open"},
	}
	if err := store.Create(&vulns).Error; err != nil {
		t.Fatalf("seed vulns: %v", err)
	}

	// plugin 精确过滤（大小写敏感）：poc-rce 只命中 1 条；多值 IN。
	rec := invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&task_id="+root.ID+"&plugin=poc-rce", getVulns)
	var page resultPageForTest[db.Vulnerability]
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].Plugin != "poc-rce" {
		t.Fatalf("plugin=poc-rce wrong: status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&task_id="+root.ID+"&plugin=poc-xss,poc-rce", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 3 {
		t.Fatalf("plugin multi-include wrong: status=%d total=%d", rec.Code, page.Total)
	}
	rec = invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&task_id="+root.ID+"&plugin=!poc-xss", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].Plugin != "poc-rce" {
		t.Fatalf("plugin exclude wrong: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// status / ai_status 过滤。
	rec = invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&task_id="+root.ID+"&status=ignored", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].Status != "ignored" {
		t.Fatalf("status=ignored wrong: status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&task_id="+root.ID+"&ai_status=confirmed", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].AIStatus != "confirmed" {
		t.Fatalf("ai_status=confirmed wrong: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 组合过滤：plugin + status。
	rec = invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&task_id="+root.ID+"&plugin=poc-xss&status=open", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 2 {
		t.Fatalf("combined filter wrong: status=%d total=%d", rec.Code, page.Total)
	}

	// 多列排序白名单：target asc → a.example 在前；plugin asc → poc-rce 在前；未知列回退默认不报错。
	rec = invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&task_id="+root.ID+"&sort=target&order=asc", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 3 || page.Items[0].Target != "a.example" {
		t.Fatalf("sort=target asc wrong: status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&task_id="+root.ID+"&sort=plugin&order=asc", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Items[0].Plugin != "poc-rce" {
		t.Fatalf("sort=plugin asc wrong: status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&task_id="+root.ID+"&sort=not_a_column&order=asc", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 3 {
		t.Fatalf("unknown sort column should fall back gracefully: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// facets：distinct 计数、空 ai_status 不计入、租户隔离。
	rec = invokeVulnFacetsHandler(t, root.ID, "project_id="+project.ID)
	if rec.Code != 200 {
		t.Fatalf("facets status=%d body=%s", rec.Code, rec.Body.String())
	}
	var facets vulnFacetsForTest
	if err := json.Unmarshal(rec.Body.Bytes(), &facets); err != nil {
		t.Fatalf("decode facets: %v", err)
	}
	if len(facets.Plugins) != 2 || facets.Plugins[0].Value != "poc-xss" || facets.Plugins[0].Count != 2 {
		t.Fatalf("facets plugins wrong: %+v", facets.Plugins)
	}
	if len(facets.Statuses) != 2 {
		t.Fatalf("facets statuses wrong: %+v", facets.Statuses)
	}
	if len(facets.AIStatuses) != 2 {
		t.Fatalf("facets ai_statuses should exclude empty value: %+v", facets.AIStatuses)
	}

	// facets 的 severity 视图联动：info 视图下无匹配 → 空插件列表。
	rec = invokeVulnFacetsHandler(t, root.ID, "project_id="+project.ID+"&severity=info")
	if rec.Code != 200 {
		t.Fatalf("facets severity view status=%d", rec.Code)
	}
	facets = vulnFacetsForTest{}
	if err := json.Unmarshal(rec.Body.Bytes(), &facets); err != nil {
		t.Fatalf("decode scoped facets: %v", err)
	}
	if len(facets.Plugins) != 0 {
		t.Fatalf("facets should honor severity view: %+v", facets.Plugins)
	}
}

func decodeVulnPage(t *testing.T, rec *httptest.ResponseRecorder, page *resultPageForTest[db.Vulnerability]) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), page); err != nil {
		t.Fatalf("decode vuln page: %v body=%s", err, rec.Body.String())
	}
}

// TestVulnHostPortFilterAndMultiColumnSearch 覆盖 host/port 精确过滤、
// 跨列自由文本搜索（target/plugin/description/host）以及 facets 的 hosts/ports 维度。
func TestVulnHostPortFilterAndMultiColumnSearch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)
	now := time.Now().UTC()

	project := db.Project{ID: "project-hp", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "HP"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	root := db.RootTask{ID: "task-hp", TenantID: "tenant-a", ProjectID: project.ID, UserID: "user-a", Status: "Finished"}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	sub := db.SubTask{ID: "attempt-hp", TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: root.ID, BatchID: "batch-hp", Status: "Finished"}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed sub: %v", err)
	}
	vulns := []db.Vulnerability{
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "http://1.2.3.4:8080/login", Host: "1.2.3.4", Port: 8080, Plugin: "cve-2024-1111", Severity: "High", Status: "open", Description: "reflected xss in login", CreatedAt: now},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "http://1.2.3.4:443", Host: "1.2.3.4", Port: 443, Plugin: "poc-generic", Severity: "Low", Status: "open", Description: "tls weak config", CreatedAt: now},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "ssh://5.6.7.8:22", Host: "5.6.7.8", Port: 22, Plugin: "poc-ssh", Severity: "Medium", Status: "open", Description: "weak password", CreatedAt: now},
		// 其他租户：host/port 与搜索都不应泄漏。
		{TenantID: "tenant-b", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "http://9.9.9.9:8080", Host: "9.9.9.9", Port: 8080, Plugin: "poc-zz-tenantb", Severity: "High", Status: "open"},
	}
	if err := store.Create(&vulns).Error; err != nil {
		t.Fatalf("seed vulns: %v", err)
	}
	base := "/vulns?project_id=" + project.ID + "&task_id=" + root.ID
	var page resultPageForTest[db.Vulnerability]

	// host 精确过滤：单值 / 多值 IN。
	rec := invokeTaskResultHandler(t, base+"&host=1.2.3.4", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 2 {
		t.Fatalf("host=1.2.3.4 wrong: status=%d total=%d body=%s", rec.Code, page.Total, rec.Body.String())
	}
	rec = invokeTaskResultHandler(t, base+"&host=1.2.3.4,5.6.7.8", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 3 {
		t.Fatalf("host multi wrong: status=%d total=%d", rec.Code, page.Total)
	}

	// port 精确过滤：单值 / 多值 IN。
	rec = invokeTaskResultHandler(t, base+"&port=8080", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].Port != 8080 {
		t.Fatalf("port=8080 wrong: status=%d total=%d body=%s", rec.Code, page.Total, rec.Body.String())
	}
	rec = invokeTaskResultHandler(t, base+"&port=8080,443", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 2 {
		t.Fatalf("port multi wrong: status=%d total=%d", rec.Code, page.Total)
	}

	// host + port 组合收敛到单条。
	rec = invokeTaskResultHandler(t, base+"&host=1.2.3.4&port=8080", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].Plugin != "cve-2024-1111" {
		t.Fatalf("host+port wrong: status=%d total=%d body=%s", rec.Code, page.Total, rec.Body.String())
	}

	// 跨列自由文本搜索：plugin(CVE) / description / host。
	rec = invokeTaskResultHandler(t, base+"&search=cve-2024-1111", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].Plugin != "cve-2024-1111" {
		t.Fatalf("search plugin wrong: status=%d total=%d body=%s", rec.Code, page.Total, rec.Body.String())
	}
	rec = invokeTaskResultHandler(t, base+"&search=weak+password", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].Plugin != "poc-ssh" {
		t.Fatalf("search description wrong: status=%d total=%d body=%s", rec.Code, page.Total, rec.Body.String())
	}
	rec = invokeTaskResultHandler(t, base+"&search=5.6.7.8", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].Host != "5.6.7.8" {
		t.Fatalf("search host wrong: status=%d total=%d body=%s", rec.Code, page.Total, rec.Body.String())
	}

	// 搜索与其它过滤 AND 组合：host 限定下再搜索。
	rec = invokeTaskResultHandler(t, base+"&host=1.2.3.4&search=tls", getVulns)
	decodeVulnPage(t, rec, &page)
	if rec.Code != 200 || page.Total != 1 || page.Items[0].Plugin != "poc-generic" {
		t.Fatalf("search+host combined wrong: status=%d total=%d body=%s", rec.Code, page.Total, rec.Body.String())
	}

	// facets：hosts/ports 维度 + 租户隔离。
	recf := invokeVulnFacetsHandler(t, root.ID, "project_id="+project.ID)
	if recf.Code != 200 {
		t.Fatalf("facets status=%d body=%s", recf.Code, recf.Body.String())
	}
	var facets vulnFacetsForTest
	if err := json.Unmarshal(recf.Body.Bytes(), &facets); err != nil {
		t.Fatalf("decode facets: %v", err)
	}
	hostCounts := map[string]int64{}
	for _, h := range facets.Hosts {
		hostCounts[h.Value] = h.Count
	}
	if hostCounts["1.2.3.4"] != 2 || hostCounts["5.6.7.8"] != 1 {
		t.Fatalf("facets hosts wrong: %+v", facets.Hosts)
	}
	if _, leak := hostCounts["9.9.9.9"]; leak {
		t.Fatalf("facets hosts must not leak tenant-b: %+v", facets.Hosts)
	}
	portCounts := map[string]int64{}
	for _, p := range facets.Ports {
		portCounts[p.Value] = p.Count
	}
	if portCounts["8080"] != 1 || portCounts["443"] != 1 || portCounts["22"] != 1 {
		t.Fatalf("facets ports wrong: %+v", facets.Ports)
	}

	// facets 的 search 口径与列表一致：搜索收敛后 hosts 维度随之收敛。
	recf = invokeVulnFacetsHandler(t, root.ID, "project_id="+project.ID+"&search=tls")
	if recf.Code != 200 {
		t.Fatalf("facets search status=%d", recf.Code)
	}
	facets = vulnFacetsForTest{}
	if err := json.Unmarshal(recf.Body.Bytes(), &facets); err != nil {
		t.Fatalf("decode scoped facets: %v", err)
	}
	if len(facets.Hosts) != 1 || facets.Hosts[0].Value != "1.2.3.4" {
		t.Fatalf("facets hosts should honor search: %+v", facets.Hosts)
	}
}
