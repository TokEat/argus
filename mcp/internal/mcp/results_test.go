package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// resultsTestServer 按路径分发固定响应，并记录每个端点收到的 RawQuery。
func resultsTestServer(t *testing.T, queries map[string]*string) *httptest.Server {
	t.Helper()
	responses := map[string]string{
		"/api/v1/vulns":              `{"items":[{"ID":1,"Target":"http://h:8080/a","Severity":"high","Status":"open","Plugin":"poc-x","Request":"GET /a HTTP/1.1","Response":"HTTP/1.1 200"},{"ID":2,"Target":"http://h:8080/b","Severity":"low","Status":"fixed","Plugin":"poc-y"}],"total":2,"page":1,"page_size":200}`,
		"/api/v1/assets":             `{"items":[{"ID":1,"Target":"http://h:8080","Protocol":"http"},{"ID":2,"Target":"http://h:8080","Protocol":"http"},{"ID":3,"Target":"tcp://h:22","Protocol":"tcp"}],"total":3,"page":1,"page_size":200}`,
		"/api/v1/fingerprints":       `{"items":[{"ID":1,"Target":"http://h:8080","ProductName":"Shiro"},{"ID":2,"Target":"http://h:8080","ProductName":"Shiro"},{"ID":3,"Target":"http://h:8081","ProductName":"Nginx"}],"total":3,"page":1,"page_size":200}`,
		"/api/v1/vulns/42":           `{"ID":42,"Target":"http://h:8080/admin","Plugin":"poc-sqli","Severity":"critical","Request":"POST /admin HTTP/1.1\r\nHost: h\r\n\r\nid=1'","Response":"HTTP/1.1 500\r\n\r\nSQL error"}`,
		"/api/v1/vulns/42/ai-review": `{"vulnerability_id":42,"ai_status":"confirmed","reviews":[{"verdict":"confirmed"}]}`,
		"/api/v1/vulns/42/lineage":   `{"nodes":[{"target":"http://h:8080","stage":"target","node_type":"asset"},{"target":"http://h:8080/admin","stage":"poc-sqli","node_type":"vulnerability"}]}`,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if recorder, ok := queries[r.URL.Path]; ok && recorder != nil {
			*recorder = r.URL.RawQuery
		}
		body, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(body))
	}))
}

func TestArgusResultsSummaryAggregatesAllEndpoints(t *testing.T) {
	var vulnsQ, assetsQ, fpsQ string
	queries := map[string]*string{
		"/api/v1/vulns":        &vulnsQ,
		"/api/v1/assets":       &assetsQ,
		"/api/v1/fingerprints": &fpsQ,
	}
	ts := resultsTestServer(t, queries)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	out, err := client.CallTool(context.Background(), "argus_results", map[string]interface{}{
		"action": "summary", "project_id": "p1", "task_id": "t1",
	})
	if err != nil {
		t.Fatalf("argus_results summary: %v", err)
	}
	result := out.(map[string]interface{})
	if result["status"] != "success" || result["action"] != "summary" {
		t.Fatalf("unexpected envelope: %#v", result)
	}
	vulns := result["vulns"].(map[string]interface{})
	if vulns["total"].(int64) != 2 || vulns["sampled"].(int) != 2 || vulns["truncated"] != false {
		t.Fatalf("unexpected vulns summary: %#v", vulns)
	}
	bySeverity := vulns["by_severity"].(map[string]int)
	if bySeverity["high"] != 1 || bySeverity["low"] != 1 {
		t.Fatalf("unexpected severity buckets: %#v", bySeverity)
	}
	byStatus := vulns["by_status"].(map[string]int)
	if byStatus["open"] != 1 || byStatus["fixed"] != 1 {
		t.Fatalf("unexpected status buckets: %#v", byStatus)
	}
	assets := result["assets"].(map[string]interface{})
	byProtocol := assets["by_protocol"].(map[string]int)
	if byProtocol["http"] != 2 || byProtocol["tcp"] != 1 {
		t.Fatalf("unexpected protocol buckets: %#v", byProtocol)
	}
	fps := result["fingerprints"].(map[string]interface{})
	byProduct := fps["by_product"].(map[string]int)
	if byProduct["Shiro"] != 2 || byProduct["Nginx"] != 1 {
		t.Fatalf("unexpected product buckets: %#v", byProduct)
	}
	if !strings.Contains(*queries["/api/v1/vulns"], "project_id=p1") ||
		!strings.Contains(*queries["/api/v1/vulns"], "page_size=200") ||
		!strings.Contains(*queries["/api/v1/fingerprints"], "task_id=t1") {
		t.Fatalf("filters not forwarded: vulns=%q fps=%q", *queries["/api/v1/vulns"], *queries["/api/v1/fingerprints"])
	}
}

func TestArgusResultsVulnsListForwardsSortAndKeepsEvidence(t *testing.T) {
	var vulnsQ string
	queries := map[string]*string{"/api/v1/vulns": &vulnsQ}
	ts := resultsTestServer(t, queries)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	out, err := client.CallTool(context.Background(), "argus_results", map[string]interface{}{
		"action": "vulns", "project_id": "p1", "search": "h:8080", "sort": "severity", "order": "desc",
	})
	if err != nil {
		t.Fatalf("argus_results vulns: %v", err)
	}
	result := out.(map[string]interface{})
	if result["total"].(int64) != 2 {
		t.Fatalf("unexpected vulns result: %#v", result)
	}
	for _, want := range []string{"search=h%3A8080", "sort=severity", "order=desc"} {
		if !strings.Contains(*queries["/api/v1/vulns"], want) {
			t.Fatalf("vulns query missing %q: %q", want, *queries["/api/v1/vulns"])
		}
	}
	items := result["items"].([]map[string]interface{})
	if items[0]["Request"] != "GET /a HTTP/1.1" || items[0]["Response"] != "HTTP/1.1 200" {
		t.Fatalf("request/response evidence lost: %#v", items[0])
	}
}

func TestArgusResultsVulnDetailAssemblesEvidenceBundle(t *testing.T) {
	var vulnQ, aiQ, lineageQ string
	queries := map[string]*string{
		"/api/v1/vulns/42":           &vulnQ,
		"/api/v1/vulns/42/ai-review": &aiQ,
		"/api/v1/vulns/42/lineage":   &lineageQ,
	}
	ts := resultsTestServer(t, queries)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	out, err := client.CallTool(context.Background(), "argus_results", map[string]interface{}{
		"action": "vuln_detail", "id": "42", "project_id": "p1",
	})
	if err != nil {
		t.Fatalf("argus_results vuln_detail: %v", err)
	}
	result := out.(map[string]interface{})
	if result["action"] != "vuln_detail" || result["id"] != "42" {
		t.Fatalf("unexpected detail envelope: %#v", result)
	}
	vuln := result["vulnerability"].(map[string]interface{})
	if vuln["Request"] == "" || vuln["Response"] == "" || vuln["Severity"] != "critical" {
		t.Fatalf("vuln evidence missing: %#v", vuln)
	}
	aiReview := result["ai_review"].(map[string]interface{})
	if aiReview["ai_status"] != "confirmed" {
		t.Fatalf("ai_review missing: %#v", aiReview)
	}
	nodes := result["lineage"].([]interface{})
	if len(nodes) != 2 {
		t.Fatalf("lineage nodes missing: %#v", result["lineage"])
	}
	if !strings.Contains(*queries["/api/v1/vulns/42"], "project_id=p1") ||
		!strings.Contains(*queries["/api/v1/vulns/42/lineage"], "project_id=p1") {
		t.Fatalf("project filter not forwarded to detail endpoints: %q / %q",
			*queries["/api/v1/vulns/42"], *queries["/api/v1/vulns/42/lineage"])
	}
}

func TestArgusResultsVulnDetailRequiresIDAndProject(t *testing.T) {
	ts := resultsTestServer(t, map[string]*string{})
	defer ts.Close()
	client := NewClient(ts.URL, "test-token")
	ctx := context.Background()

	if _, err := client.CallTool(ctx, "argus_results", map[string]interface{}{"action": "vuln_detail", "project_id": "p1"}); err == nil ||
		!strings.Contains(err.Error(), "id is required") {
		t.Fatalf("expected id required error, got %v", err)
	}
	if _, err := client.CallTool(ctx, "argus_results", map[string]interface{}{"action": "vuln_detail", "id": "42"}); err == nil ||
		!strings.Contains(err.Error(), "project_id is required") {
		t.Fatalf("expected project_id required error, got %v", err)
	}
}

func TestArgusResultsFingerprintsGroupByProduct(t *testing.T) {
	var fpsQ string
	queries := map[string]*string{"/api/v1/fingerprints": &fpsQ}
	ts := resultsTestServer(t, queries)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	out, err := client.CallTool(context.Background(), "argus_results", map[string]interface{}{
		"action": "fingerprints", "project_id": "p1", "group_by": "product", "search": "Shiro",
	})
	if err != nil {
		t.Fatalf("argus_results fingerprints: %v", err)
	}
	if !strings.Contains(*queries["/api/v1/fingerprints"], "group_by=product") ||
		!strings.Contains(*queries["/api/v1/fingerprints"], "search=Shiro") {
		t.Fatalf("group_by/search not forwarded: %q", *queries["/api/v1/fingerprints"])
	}
	if out.(map[string]interface{})["total"].(int64) != 3 {
		t.Fatalf("unexpected fingerprints result: %#v", out)
	}
}

func TestArgusResultsRejectsUnknownAction(t *testing.T) {
	ts := resultsTestServer(t, map[string]*string{})
	defer ts.Close()
	client := NewClient(ts.URL, "test-token")
	if _, err := client.CallTool(context.Background(), "argus_results", map[string]interface{}{"action": "delete"}); err == nil ||
		!strings.Contains(err.Error(), "unsupported action") {
		t.Fatalf("expected unsupported action error, got %v", err)
	}
}
