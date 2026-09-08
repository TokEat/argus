package api

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func TestAssetKindForProtocol(t *testing.T) {
	cases := map[string]string{
		"Web":           assetKindWeb,
		"Domain-Bind":   assetKindWeb,
		"PortScan":      assetKindHostPort,
		"Protocol":      assetKindHostPort,
		"ProtocolCheck": assetKindHostPort,
		"Nmap":          assetKindHostPort,
		"IPAlive":       assetKindHostPort,
		"Fofa":          assetKindHostPort,
		"Hunter":        assetKindHostPort,
		"Quake":         assetKindHostPort,
		"Domain":        assetKindDomain,
		"DNS-SubFinder": assetKindDomain,
		"DNS-Brute":     assetKindDomain,
		"CDN-Domain":    assetKindDomain,
		"RealIP":        assetKindResolution,
		"https":         assetKindOther,
		"":              assetKindOther,
	}
	for protocol, want := range cases {
		if got := assetKindForProtocol(protocol); got != want {
			t.Fatalf("assetKindForProtocol(%q)=%q want %q", protocol, got, want)
		}
	}
}

func TestApplyAssetKindFilterRejectsUnknownKind(t *testing.T) {
	_, err := applyAssetKindFilter(nil, "not-a-kind")
	if !errors.Is(err, errUnknownAssetKind) {
		t.Fatalf("err=%v want %v", err, errUnknownAssetKind)
	}
}

func TestParseRealIPAsset(t *testing.T) {
	domain, ips := parseRealIPAsset("fallback.test", `{"type":"RealIP","domain":"assoc.test","ips":["198.51.100.9","198.51.100.9"," 203.0.113.7 "]}`)
	if domain != "assoc.test" || len(ips) != 2 || ips[0] != "198.51.100.9" || ips[1] != "203.0.113.7" {
		t.Fatalf("parsed domain=%q ips=%v", domain, ips)
	}
	fallback, empty := parseRealIPAsset("only-target.test", `{}`)
	if fallback != "only-target.test" || len(empty) != 0 {
		t.Fatalf("fallback domain=%q ips=%v", fallback, empty)
	}
}

func TestCollectAssetResultStatsIgnoresListOrdering(t *testing.T) {
	store := setupAITestDB(t)
	assets := []db.Asset{
		{TenantID: "tenant-a", ProjectID: "p", TaskID: "t", Target: "https://a.example", Protocol: "Web"},
		{TenantID: "tenant-a", ProjectID: "p", TaskID: "t", Target: "1.1.1.1:80", Protocol: "PortScan", Port: 80},
	}
	if err := store.Create(&assets).Error; err != nil {
		t.Fatal(err)
	}
	stats, err := collectAssetResultStats(store.Where("tenant_id = ?", "tenant-a").Order("created_at desc"))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 2 || stats.Web != 1 || stats.HostPort != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestGetAssetsFiltersByKindAndReturnsScopedStats(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)
	project := db.Project{ID: "kind-project", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "kinds"}
	root := db.RootTask{ID: "kind-root", TenantID: "tenant-a", ProjectID: project.ID, UserID: "user-a", Status: "Finished"}
	attempt := db.SubTask{ID: "kind-attempt", TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: root.ID, Status: "Finished"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	assets := []db.Asset{
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID, Target: "https://web.example", Protocol: "Web", Title: "site"},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID, Target: "https://bind.example", Protocol: "Domain-Bind"},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID, Target: "192.0.2.10:22", Protocol: "PortScan", Port: 22, Service: "ssh"},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID, Target: "sub.example", Protocol: "DNS-SubFinder"},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID, Target: "assoc.test", Protocol: "RealIP", Tags: `{"domain":"assoc.test","ips":["198.51.100.9"]}`},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID, Target: "https://other.example", Protocol: "https"},
		{TenantID: "tenant-b", ProjectID: "foreign", TaskID: "foreign-task", Target: "https://secret.example", Protocol: "Web"},
	}
	if err := store.Create(&assets).Error; err != nil {
		t.Fatal(err)
	}

	recorder := invokeTaskResultHandler(t, "/assets?task_id="+root.ID+"&project_id="+project.ID+"&kind=web", getAssets)
	if recorder.Code != 200 {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var page struct {
		Items []db.Asset       `json:"items"`
		Total int64            `json:"total"`
		Stats assetResultStats `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("web page=%+v", page)
	}
	for _, item := range page.Items {
		if kind := assetKindForProtocol(item.Protocol); kind != assetKindWeb {
			t.Fatalf("web filter leaked %s", item.Protocol)
		}
		if item.TenantID != "tenant-a" {
			t.Fatalf("tenant leaked: %+v", item)
		}
	}
	if page.Stats.Total != 6 || page.Stats.Web != 2 || page.Stats.HostPort != 1 || page.Stats.Domain != 1 || page.Stats.Resolution != 1 || page.Stats.Other != 1 {
		t.Fatalf("stats=%+v", page.Stats)
	}
	if len(page.Stats.Resolutions) != 1 || page.Stats.Resolutions[0].Domain != "assoc.test" || len(page.Stats.Resolutions[0].IPs) != 1 || page.Stats.Resolutions[0].IPs[0] != "198.51.100.9" {
		t.Fatalf("resolutions=%+v", page.Stats.Resolutions)
	}

	if err := store.Create(&[]db.FingerprintHit{
		{
			TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID,
			Target: "https://web.example:443", ProductName: "nginx", RuleName: "Finger",
			Evidence: `{"type":"Finger","uri":"https://web.example/","finger":["nginx"]}`,
		},
		{
			TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID,
			Target: "https://web.example:443", ProductName: "Jenkins", RuleName: "Active-Finger",
			Evidence: `{"type":"Active-Finger","uri":"https://web.example/jenkins/login","finger":["Jenkins"]}`,
		},
		{
			TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID,
			Target: "https://bind.example:443", ProductName: "apache", RuleName: "Finger",
			Evidence: `{"type":"Finger","uri":"https://bind.example/","finger":["apache"]}`,
		},
	}).Error; err != nil {
		t.Fatal(err)
	}

	webWithFP := invokeTaskResultHandler(t, "/assets?task_id="+root.ID+"&project_id="+project.ID+"&kind=web", getAssets)
	var webPage struct {
		Items []assetWithFingerprints `json:"items"`
	}
	if err := json.Unmarshal(webWithFP.Body.Bytes(), &webPage); err != nil {
		t.Fatal(err)
	}
	byTarget := map[string][]assetFingerprintMatch{}
	for _, item := range webPage.Items {
		byTarget[item.Target] = item.Fingerprints
	}
	webPrints := byTarget["https://web.example"]
	if len(webPrints) != 2 || webPrints[0].ProductName != "Jenkins" || webPrints[0].Source != db.FingerprintSourceDirectory || webPrints[1].ProductName != "nginx" {
		t.Fatalf("web fingerprints=%+v", webPrints)
	}
	if webPrints[0].SourceLabel != "主动路径" {
		t.Fatalf("directory source label=%q", webPrints[0].SourceLabel)
	}
	bindPrints := byTarget["https://bind.example"]
	if len(bindPrints) != 1 || bindPrints[0].ProductName != "apache" || bindPrints[0].Source != db.FingerprintSourcePassive {
		t.Fatalf("bind fingerprints=%+v", bindPrints)
	}

	hostRecorder := invokeTaskResultHandler(t, "/assets?task_id="+root.ID+"&project_id="+project.ID+"&kind=host_port", getAssets)
	var hostPage struct {
		Items []db.Asset `json:"items"`
		Total int64      `json:"total"`
	}
	if err := json.Unmarshal(hostRecorder.Body.Bytes(), &hostPage); err != nil {
		t.Fatal(err)
	}
	if hostPage.Total != 1 || hostPage.Items[0].Protocol != "PortScan" {
		t.Fatalf("host_port page=%+v", hostPage)
	}

	bad := invokeTaskResultHandler(t, "/assets?task_id="+root.ID+"&kind=nope", getAssets)
	if bad.Code != 400 {
		t.Fatalf("unknown kind status=%d body=%s", bad.Code, bad.Body.String())
	}
}

func TestExportAssetsHonorsKindFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)
	project := db.Project{ID: "export-kind-project", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "export"}
	root := db.RootTask{ID: "export-kind-root", TenantID: "tenant-a", ProjectID: project.ID, Status: "Finished"}
	attempt := db.SubTask{ID: "export-kind-attempt", TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: root.ID, Status: "Finished"}
	for _, row := range []interface{}{&project, &root, &attempt} {
		if err := store.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Create(&[]db.Asset{
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID, Target: "https://keep.example", Protocol: "Web"},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: root.ID, Target: "192.0.2.8:80", Protocol: "PortScan", Port: 80},
	}).Error; err != nil {
		t.Fatal(err)
	}

	recorder := invokeTaskResultHandler(t, "/reports/export/assets?task_id="+root.ID+"&project_id="+project.ID+"&kind=web", exportAssets)
	if recorder.Code != 200 {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "keep.example") || strings.Contains(body, "192.0.2.8") {
		t.Fatalf("export body=%s", body)
	}
}
