package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
)

type profilesResponseForTest struct {
	Data  []HostProfile `json:"data"`
	Total int           `json:"total"`
}

func invokeGetProfiles(t *testing.T, projectID string) profilesResponseForTest {
	t.Helper()
	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/profiles?project_id="+projectID, "operator", "user-1")
	getProfiles(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("getProfiles status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp profilesResponseForTest
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode profiles: %v", err)
	}
	return resp
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// 同一 ip:port 的 PortScan/Nmap/Web 三行应合并为一个端口行，
// Transport/StatusCode 从最佳 Service(http/200) 派生，Title/URL 取 Web 行。
func TestGetProfilesMergesPortAcrossStages(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "prof-merge", TenantID: "default", OwnerUserID: "user-1", Name: "Merge", Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	assets := []db.Asset{
		{TenantID: "default", ProjectID: project.ID, TaskID: "task-1", Target: "127.0.0.1:80", Protocol: "PortScan", Port: 80, Service: ""},
		{TenantID: "default", ProjectID: project.ID, TaskID: "task-1", Target: "127.0.0.1:80", Protocol: "Nmap", Port: 80, Service: "http"},
		{TenantID: "default", ProjectID: project.ID, TaskID: "task-1", Target: "http://127.0.0.1:80", Protocol: "Web", Port: 80, Service: "http/200", Title: "Welcome to nginx!", URL: "http://127.0.0.1:80"},
	}
	for i := range assets {
		if err := store.Create(&assets[i]).Error; err != nil {
			t.Fatalf("seed asset %d: %v", i, err)
		}
	}

	resp := invokeGetProfiles(t, project.ID)
	if len(resp.Data) != 1 {
		t.Fatalf("hosts=%d want 1", len(resp.Data))
	}
	ports := resp.Data[0].Ports
	if len(ports) != 1 {
		t.Fatalf("merged ports=%d want 1 (跨阶段合并): %+v", len(ports), ports)
	}
	p := ports[0]
	if p.Port != 80 {
		t.Fatalf("port=%d want 80", p.Port)
	}
	if p.Transport != "http" {
		t.Fatalf("transport=%q want http", p.Transport)
	}
	if p.StatusCode != 200 {
		t.Fatalf("status_code=%d want 200", p.StatusCode)
	}
	if p.Title != "Welcome to nginx!" {
		t.Fatalf("title=%q want Web 行标题", p.Title)
	}
	if p.URL != "http://127.0.0.1:80" {
		t.Fatalf("url=%q want Web 行 URL", p.URL)
	}
	for _, stage := range []string{"PortScan", "Nmap", "Web"} {
		if !containsStr(p.Stages, stage) {
			t.Fatalf("stages=%v missing %s", p.Stages, stage)
		}
	}
	if len(p.AssetIDs) != 3 {
		t.Fatalf("asset_ids=%v want 3 个贡献资产", p.AssetIDs)
	}
}

// 仅裸 ip:port（无 URL/Service）时：状态码为 0，协议按知名端口兜底。
func TestGetProfilesBarePortFallsBack(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "prof-fallback", TenantID: "default", OwnerUserID: "user-1", Name: "Fallback", Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	asset := db.Asset{TenantID: "default", ProjectID: project.ID, TaskID: "task-1", Target: "10.0.0.1:443", Protocol: "PortScan", Port: 443, Service: ""}
	if err := store.Create(&asset).Error; err != nil {
		t.Fatal(err)
	}

	resp := invokeGetProfiles(t, project.ID)
	if len(resp.Data) != 1 || len(resp.Data[0].Ports) != 1 {
		t.Fatalf("unexpected profile: %+v", resp.Data)
	}
	p := resp.Data[0].Ports[0]
	if p.StatusCode != 0 {
		t.Fatalf("status_code=%d want 0 (无状态码)", p.StatusCode)
	}
	if p.Transport != "https" {
		t.Fatalf("transport=%q want https (知名端口 443 兜底)", p.Transport)
	}
}

func TestParseServiceVariants(t *testing.T) {
	cases := []struct {
		name       string
		asset      db.Asset
		wantTrans  string
		wantStatus int
	}{
		{"http/200 全量", db.Asset{Service: "http/200"}, "http", 200},
		{"http 仅协议", db.Asset{Service: "http"}, "http", 0},
		{"空 service 走 URL scheme", db.Asset{Service: "", URL: "http://x:8080/a", Port: 8080}, "http", 0},
		{"空 service 走知名端口", db.Asset{Service: "", Port: 3306}, "mysql", 0},
		{"空 service 默认 tcp", db.Asset{Service: "", Port: 5121}, "tcp", 0},
		{"非法状态码不采纳", db.Asset{Service: "http/9999"}, "http", 0},
	}
	for _, tc := range cases {
		trans, status := parseService(tc.asset)
		if trans != tc.wantTrans || status != tc.wantStatus {
			t.Fatalf("%s: got (%q,%d) want (%q,%d)", tc.name, trans, status, tc.wantTrans, tc.wantStatus)
		}
	}
}

func TestResolvePortForAsset(t *testing.T) {
	cases := []struct {
		asset db.Asset
		want  int
	}{
		{db.Asset{Port: 8080, Target: "x"}, 8080},
		{db.Asset{Target: "http://127.0.0.1:8080/path"}, 8080},
		{db.Asset{Target: "127.0.0.1:9090"}, 9090},
		{db.Asset{Target: "example.com"}, 0},
		{db.Asset{Target: ""}, 0},
	}
	for _, tc := range cases {
		if got := resolvePortForAsset(tc.asset); got != tc.want {
			t.Fatalf("resolvePortForAsset(%q, port=%d)=%d want %d", tc.asset.Target, tc.asset.Port, got, tc.want)
		}
	}
}
