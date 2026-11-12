package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

type lineageResponseForTest struct {
	Nodes []struct {
		Target   string `json:"target"`
		Stage    string `json:"stage"`
		NodeType string `json:"node_type"`
	} `json:"nodes"`
}

func invokeLineageHandler(t *testing.T, path, id string, handler gin.HandlerFunc) lineageResponseForTest {
	t.Helper()
	ctx, recorder := newTenantContextWithRole(http.MethodGet, path, "operator", "user-1")
	ctx.Params = gin.Params{{Key: "id", Value: id}}
	handler(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("lineage status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp lineageResponseForTest
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode lineage: %v", err)
	}
	return resp
}

func nodeSummary(resp lineageResponseForTest) []string {
	out := make([]string, 0, len(resp.Nodes))
	for _, n := range resp.Nodes {
		out = append(out, fmt.Sprintf("%s:%s:%s", n.NodeType, n.Stage, n.Target))
	}
	return out
}

func TestAssetLineageChainRootFirst(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "lin-project", TenantID: "default", OwnerUserID: "user-1", Name: "Lin"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	chain := []db.Asset{
		{TenantID: "default", ProjectID: project.ID, Target: "example.com", Protocol: "CDN-Domain", Source: ""},
		{TenantID: "default", ProjectID: project.ID, Target: "www.example.com", Protocol: "DNS-SubFinder", Source: "example.com"},
		{TenantID: "default", ProjectID: project.ID, Target: "1.2.3.4", Protocol: "IPAlive", Source: "www.example.com"},
		{TenantID: "default", ProjectID: project.ID, Target: "1.2.3.4:80", Protocol: "PortScan", Source: "1.2.3.4"},
		{TenantID: "default", ProjectID: project.ID, Target: "http://1.2.3.4:80", Protocol: "Web", Source: "1.2.3.4:80"},
	}
	for i := range chain {
		if err := store.Create(&chain[i]).Error; err != nil {
			t.Fatalf("seed asset %d: %v", i, err)
		}
	}

	urlAsset := chain[len(chain)-1]
	resp := invokeLineageHandler(t, "/assets/"+fmt.Sprint(urlAsset.ID)+"/lineage?project_id="+project.ID, fmt.Sprint(urlAsset.ID), getAssetLineage)

	got := nodeSummary(resp)
	want := []string{
		"input:input:example.com",
		"asset:CDN-Domain:example.com",
		"asset:DNS-SubFinder:www.example.com",
		"asset:IPAlive:1.2.3.4",
		"asset:PortScan:1.2.3.4:80",
		"asset:Web:http://1.2.3.4:80",
	}
	if len(got) != len(want) {
		t.Fatalf("lineage length=%d want %d\ngot:  %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("node[%d]=%q want %q\ngot:  %v", i, got[i], want[i], got)
		}
	}
}

func TestAssetLineageCycleAndNullSourceTerminate(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "lin-cycle", TenantID: "default", OwnerUserID: "user-1", Name: "Lin Cycle"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// 环：a <-> b，必须靠 seen 防护终止。
	a := db.Asset{TenantID: "default", ProjectID: project.ID, Target: "a.example", Protocol: "Web", Source: "b.example"}
	b := db.Asset{TenantID: "default", ProjectID: project.ID, Target: "b.example", Protocol: "Web", Source: "a.example"}
	if err := store.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&b).Error; err != nil {
		t.Fatal(err)
	}
	resp := invokeLineageHandler(t, "/assets/"+fmt.Sprint(a.ID)+"/lineage?project_id="+project.ID, fmt.Sprint(a.ID), getAssetLineage)
	if len(resp.Nodes) == 0 || len(resp.Nodes) > 3 {
		t.Fatalf("cycle should terminate with bounded nodes, got %v", nodeSummary(resp))
	}

	// NULL source：仅 input + 自身。
	root := db.Asset{TenantID: "default", ProjectID: project.ID, Target: "root-only.example", Protocol: "IPAlive", Source: ""}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	resp = invokeLineageHandler(t, "/assets/"+fmt.Sprint(root.ID)+"/lineage?project_id="+project.ID, fmt.Sprint(root.ID), getAssetLineage)
	got := nodeSummary(resp)
	if len(got) != 2 || got[0] != "input:input:root-only.example" || got[1] != "asset:IPAlive:root-only.example" {
		t.Fatalf("null-source lineage wrong: %v", got)
	}
}

func TestAssetLineageMissingParentNamesSourceAsInput(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "lin-missing", TenantID: "default", OwnerUserID: "user-1", Name: "Lin Missing"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// www.example.com 由输入 example.com 枚举而来，但 example.com 自身从未
	// 物化为资产行：起点节点必须回退到 Source 引用，具体到该输入资产。
	sub := db.Asset{TenantID: "default", ProjectID: project.ID, Target: "www.example.com", Protocol: "DNS-SubFinder", Source: "example.com"}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}
	resp := invokeLineageHandler(t, "/assets/"+fmt.Sprint(sub.ID)+"/lineage?project_id="+project.ID, fmt.Sprint(sub.ID), getAssetLineage)
	got := nodeSummary(resp)
	if len(got) != 2 || got[0] != "input:input:example.com" || got[1] != "asset:DNS-SubFinder:www.example.com" {
		t.Fatalf("missing-parent lineage wrong: %v", got)
	}
}

// 网段扫描：存活 IP 与其端口都是派生资产，链路起点必须是输入网段本身，
// 而不是从网段扫出来的某个 IP。
func TestAssetLineageSegmentInputIsStartNode(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "lin-segment", TenantID: "default", OwnerUserID: "user-1", Name: "Lin Segment"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	alive := db.Asset{TenantID: "default", ProjectID: project.ID, Target: "10.3.130.95", Protocol: "IPAlive", Source: "10.3.130.0/24"}
	port := db.Asset{TenantID: "default", ProjectID: project.ID, Target: "10.3.130.95:22", Protocol: "PortScan", Source: "10.3.130.95"}
	if err := store.Create(&alive).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&port).Error; err != nil {
		t.Fatal(err)
	}
	resp := invokeLineageHandler(t, "/assets/"+fmt.Sprint(port.ID)+"/lineage?project_id="+project.ID, fmt.Sprint(port.ID), getAssetLineage)
	got := nodeSummary(resp)
	want := []string{
		"input:input:10.3.130.0/24",
		"asset:IPAlive:10.3.130.95",
		"asset:PortScan:10.3.130.95:22",
	}
	if len(got) != len(want) {
		t.Fatalf("segment lineage length=%d want %d\ngot:  %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("node[%d]=%q want %q\ngot:  %v", i, got[i], want[i], got)
		}
	}
}

func TestVulnAndFingerprintLineageAppendNode(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "lin-vf", TenantID: "default", OwnerUserID: "user-1", Name: "Lin VF"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	host := db.Asset{TenantID: "default", ProjectID: project.ID, Target: "http://1.2.3.4:80", Protocol: "Web", Source: "1.2.3.4:80"}
	parent := db.Asset{TenantID: "default", ProjectID: project.ID, Target: "1.2.3.4:80", Protocol: "PortScan", Source: ""}
	if err := store.Create(&parent).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&host).Error; err != nil {
		t.Fatal(err)
	}
	vuln := db.Vulnerability{TenantID: "default", ProjectID: project.ID, Target: "http://1.2.3.4:80", Plugin: "poc-x", Severity: "High"}
	fp := db.FingerprintHit{TenantID: "default", ProjectID: project.ID, Target: "http://1.2.3.4:80", ProductName: "nginx", RuleName: "r-nginx"}
	if err := store.Create(&vuln).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&fp).Error; err != nil {
		t.Fatal(err)
	}

	vResp := invokeLineageHandler(t, "/vulns/"+fmt.Sprint(vuln.ID)+"/lineage?project_id="+project.ID, fmt.Sprint(vuln.ID), getVulnLineage)
	vGot := nodeSummary(vResp)
	if len(vGot) != 4 || vGot[0] != "input:input:1.2.3.4:80" || vGot[3] != "vulnerability:poc-x:http://1.2.3.4:80" {
		t.Fatalf("vuln lineage wrong: %v", vGot)
	}

	fResp := invokeLineageHandler(t, "/fingerprints/"+fmt.Sprint(fp.ID)+"/lineage?project_id="+project.ID, fmt.Sprint(fp.ID), getFingerprintLineage)
	fGot := nodeSummary(fResp)
	if len(fGot) != 4 || fGot[0] != "input:input:1.2.3.4:80" || fGot[3] != "fingerprint:nginx:http://1.2.3.4:80" {
		t.Fatalf("fingerprint lineage wrong: %v", fGot)
	}
}
