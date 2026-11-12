package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

type fingerprintGroupPageForTest struct {
	Items []struct {
		ProductName string `json:"ProductName"`
		TargetCount int64  `json:"TargetCount"`
		Targets     []struct {
			Target   string `json:"Target"`
			RuleName string `json:"RuleName"`
		} `json:"Targets"`
	} `json:"items"`
	Total int64 `json:"total"`
	Stats struct {
		TotalHits       int64 `json:"total_hits"`
		DistinctTargets int64 `json:"distinct_targets"`
	} `json:"stats"`
}

func TestFingerprintGroupSearchAndStats(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)
	now := time.Now().UTC()

	project := db.Project{ID: "project-a", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "Project A"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	fingerprints := []db.FingerprintHit{
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "http://api.example.invalid", ProductName: "nginx", RuleName: "r-nginx-1", CreatedAt: now, UpdatedAt: now},
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "http://cdn.example.invalid", ProductName: "nginx", RuleName: "r-nginx-2", CreatedAt: now, UpdatedAt: now},
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "http://app.example.invalid", ProductName: "Apache-Tomcat", RuleName: "r-tomcat", CreatedAt: now, UpdatedAt: now},
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "http://other.example.invalid", ProductName: "IIS", RuleName: "r-iis", CreatedAt: now, UpdatedAt: now},
	}
	if err := store.Create(&fingerprints).Error; err != nil {
		t.Fatalf("seed fingerprints: %v", err)
	}

	// 无搜索：3 个产品、命中总数 4、去重目标 4。
	recorder := invokeTaskResultHandler(t, "/fingerprints?group_by=product&project_id="+project.ID, getFingerprints)
	var page fingerprintGroupPageForTest
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode fingerprint group page: %v", err)
	}
	if recorder.Code != 200 || page.Total != 3 || page.Stats.TotalHits != 4 || page.Stats.DistinctTargets != 4 {
		t.Fatalf("unfiltered groups wrong: status=%d total=%d stats=%+v body=%s", recorder.Code, page.Total, page.Stats, recorder.Body.String())
	}

	// 按产品名搜索：命中 nginx，仅 1 个产品、TargetCount=2、命中/目标统计随之收敛。
	recorder = invokeTaskResultHandler(t, "/fingerprints?group_by=product&project_id="+project.ID+"&search=nginx", getFingerprints)
	page = fingerprintGroupPageForTest{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode searched fingerprint group page: %v", err)
	}
	if recorder.Code != 200 || page.Total != 1 || page.Stats.TotalHits != 2 || page.Stats.DistinctTargets != 2 {
		t.Fatalf("search=nginx groups wrong: status=%d total=%d stats=%+v body=%s", recorder.Code, page.Total, page.Stats, recorder.Body.String())
	}
	if len(page.Items) != 1 || page.Items[0].ProductName != "nginx" || page.Items[0].TargetCount != 2 {
		t.Fatalf("search=nginx group content wrong: %+v", page.Items)
	}

	// 无匹配搜索：0 产品且统计归零。
	recorder = invokeTaskResultHandler(t, "/fingerprints?group_by=product&project_id="+project.ID+"&search=definitely-not-exist", getFingerprints)
	page = fingerprintGroupPageForTest{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode empty fingerprint group page: %v", err)
	}
	if recorder.Code != 200 || page.Total != 0 || page.Stats.TotalHits != 0 || page.Stats.DistinctTargets != 0 {
		t.Fatalf("empty search should zero out groups and stats: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestAssetAndVulnSearchFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)

	project := db.Project{ID: "project-b", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "Project B"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	assets := []db.Asset{
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "http://api.example.invalid", Protocol: "Web"},
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "ssh://10.0.0.1:22", Protocol: "PortScan"},
	}
	if err := store.Create(&assets).Error; err != nil {
		t.Fatalf("seed assets: %v", err)
	}
	vulns := []db.Vulnerability{
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "http://api.example.invalid", Plugin: "poc-web", Severity: "High"},
		{TenantID: "tenant-a", ProjectID: project.ID, Target: "ssh://10.0.0.1:22", Plugin: "poc-ssh", Severity: "Low"},
	}
	if err := store.Create(&vulns).Error; err != nil {
		t.Fatalf("seed vulnerabilities: %v", err)
	}

	assetRecorder := invokeTaskResultHandler(t, "/assets?project_id="+project.ID+"&search=api.example", getAssets)
	var assetPage resultPageForTest[db.Asset]
	if err := json.Unmarshal(assetRecorder.Body.Bytes(), &assetPage); err != nil {
		t.Fatalf("decode asset page: %v", err)
	}
	if assetRecorder.Code != 200 || assetPage.Total != 1 || assetPage.Items[0].Target != "http://api.example.invalid" {
		t.Fatalf("asset search=api.example wrong: status=%d body=%s", assetRecorder.Code, assetRecorder.Body.String())
	}

	vulnRecorder := invokeTaskResultHandler(t, "/vulns?project_id="+project.ID+"&search=10.0.0.1", getVulns)
	var vulnPage resultPageForTest[db.Vulnerability]
	if err := json.Unmarshal(vulnRecorder.Body.Bytes(), &vulnPage); err != nil {
		t.Fatalf("decode vuln page: %v", err)
	}
	if vulnRecorder.Code != 200 || vulnPage.Total != 1 || vulnPage.Items[0].Plugin != "poc-ssh" {
		t.Fatalf("vuln search=10.0.0.1 wrong: status=%d body=%s", vulnRecorder.Code, vulnRecorder.Body.String())
	}

	// 搜索与任务隔离：带一个不存在的 task_id 时即使 search 命中也不返回。
	assetScoped := invokeTaskResultHandler(t, "/assets?project_id="+project.ID+"&task_id=task-missing&search=api.example", getAssets)
	var assetScopedPage resultPageForTest[db.Asset]
	if err := json.Unmarshal(assetScoped.Body.Bytes(), &assetScopedPage); err != nil {
		t.Fatalf("decode scoped asset page: %v", err)
	}
	if assetScoped.Code != 200 || assetScopedPage.Total != 0 {
		t.Fatalf("asset search must compose with task scope: status=%d body=%s", assetScoped.Code, assetScoped.Body.String())
	}
}
