package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// findingsTestServer 记录两个 findings 端点收到的查询参数，并返回固定页。
func findingsTestServer(t *testing.T, crawlQuery, sensitiveQuery *string, crawl, sensitive string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/crawl-site-candidates":
			*crawlQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(crawl))
		case "/api/v1/sensitive-findings":
			*sensitiveQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(sensitive))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
}

func TestArgusFindingsSummaryAggregatesBothEndpoints(t *testing.T) {
	var crawlQuery, sensitiveQuery string
	ts := findingsTestServer(t,
		&crawlQuery, &sensitiveQuery,
		`{"items":[
			{"id":1,"url":"http://h:8080/app1","site_type":"path_app","ai_status":"confirmed"},
			{"id":2,"url":"http://h:8080/","site_type":"","ai_status":"pending"},
			{"id":3,"url":"http://h:8080/internal","site_type":"hidden_path","ai_status":"confirmed"}
		],"total":3,"page":1,"page_size":200}`,
		`{"items":[
			{"id":4,"kind":"apikey","ai_status":"confirmed"},
			{"id":5,"kind":"apikey","ai_status":"pending"},
			{"id":6,"kind":"username","ai_status":"confirmed"}
		],"total":3,"page":1,"page_size":200}`)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	out, err := client.CallTool(context.Background(), "argus_findings", map[string]interface{}{
		"action": "summary", "project_id": "p1", "task_id": "t1",
	})
	if err != nil {
		t.Fatalf("argus_findings summary: %v", err)
	}
	result := out.(map[string]interface{})
	if result["status"] != "success" || result["action"] != "summary" {
		t.Fatalf("unexpected result envelope: %#v", result)
	}

	crawl := result["crawl_sites"].(map[string]interface{})
	if crawl["total"].(int64) != 3 || crawl["sampled"].(int) != 3 || crawl["truncated"] != false {
		t.Fatalf("unexpected crawl summary: %#v", crawl)
	}
	bySiteType := crawl["by_site_type"].(map[string]int)
	if bySiteType["path_app"] != 1 || bySiteType["hidden_path"] != 1 || bySiteType["port_or_subdomain"] != 1 {
		t.Fatalf("unexpected site_type buckets: %#v", bySiteType)
	}
	byCrawlStatus := crawl["by_ai_status"].(map[string]int)
	if byCrawlStatus["confirmed"] != 2 || byCrawlStatus["pending"] != 1 {
		t.Fatalf("unexpected crawl ai_status buckets: %#v", byCrawlStatus)
	}

	sensitive := result["sensitive"].(map[string]interface{})
	byKind := sensitive["by_kind"].(map[string]int)
	if byKind["apikey"] != 2 || byKind["username"] != 1 {
		t.Fatalf("unexpected kind buckets: %#v", byKind)
	}
	bySensitiveStatus := sensitive["by_ai_status"].(map[string]int)
	if bySensitiveStatus["confirmed"] != 2 || bySensitiveStatus["pending"] != 1 {
		t.Fatalf("unexpected sensitive ai_status buckets: %#v", bySensitiveStatus)
	}

	if !strings.Contains(crawlQuery, "project_id=p1") || !strings.Contains(crawlQuery, "task_id=t1") ||
		!strings.Contains(crawlQuery, "page_size=200") {
		t.Fatalf("crawl query missing filters: %q", crawlQuery)
	}
	if !strings.Contains(sensitiveQuery, "project_id=p1") {
		t.Fatalf("sensitive query missing project filter: %q", sensitiveQuery)
	}
}

func TestArgusFindingsCrawlSitesForwardsSiteType(t *testing.T) {
	var crawlQuery, sensitiveQuery string
	ts := findingsTestServer(t,
		&crawlQuery, &sensitiveQuery,
		`{"items":[{"id":1,"url":"http://h:8080/app1","site_type":"path_app","ai_status":"confirmed"}],"total":1,"page":1,"page_size":20}`,
		`{"items":[],"total":0,"page":1,"page_size":20}`)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	out, err := client.CallTool(context.Background(), "argus_findings", map[string]interface{}{
		"action": "crawl_sites", "site_type": "path_app", "ai_status": "confirmed", "search": "app1",
	})
	if err != nil {
		t.Fatalf("argus_findings crawl_sites: %v", err)
	}
	result := out.(map[string]interface{})
	if result["action"] != "crawl_sites" || result["total"].(int64) != 1 {
		t.Fatalf("unexpected crawl_sites result: %#v", result)
	}
	for _, want := range []string{"site_type=path_app", "ai_status=confirmed", "search=app1"} {
		if !strings.Contains(crawlQuery, want) {
			t.Fatalf("crawl query missing %q: %q", want, crawlQuery)
		}
	}
	items := result["items"].([]map[string]interface{})
	if items[0]["url"] != "http://h:8080/app1" {
		t.Fatalf("unexpected crawl item: %#v", items[0])
	}
	if sensitiveQuery != "" {
		t.Fatalf("crawl_sites should not call sensitive endpoint, got %q", sensitiveQuery)
	}
}

func TestArgusFindingsSensitiveForwardsKind(t *testing.T) {
	var crawlQuery, sensitiveQuery string
	ts := findingsTestServer(t,
		&crawlQuery, &sensitiveQuery,
		`{"items":[],"total":0,"page":1,"page_size":20}`,
		`{"items":[{"id":9,"kind":"apikey","value":"AKIAIOSFODNN7EXAMPLE","ai_status":"confirmed"}],"total":1,"page":1,"page_size":20}`)
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	out, err := client.CallTool(context.Background(), "argus_findings", map[string]interface{}{
		"action": "sensitive", "kind": "apikey", "page": 2, "page_size": 50,
	})
	if err != nil {
		t.Fatalf("argus_findings sensitive: %v", err)
	}
	result := out.(map[string]interface{})
	if result["action"] != "sensitive" || result["total"].(int64) != 1 {
		t.Fatalf("unexpected sensitive result: %#v", result)
	}
	for _, want := range []string{"kind=apikey", "page=2", "page_size=50"} {
		if !strings.Contains(sensitiveQuery, want) {
			t.Fatalf("sensitive query missing %q: %q", want, sensitiveQuery)
		}
	}
	if crawlQuery != "" {
		t.Fatalf("sensitive should not call crawl endpoint, got %q", crawlQuery)
	}
}

func TestArgusFindingsDefaultsToSummaryAndRejectsUnknownAction(t *testing.T) {
	var crawlQuery, sensitiveQuery string
	ts := findingsTestServer(t,
		&crawlQuery, &sensitiveQuery,
		`{"items":[],"total":0,"page":1,"page_size":200}`,
		`{"items":[],"total":0,"page":1,"page_size":200}`)
	defer ts.Close()
	client := NewClient(ts.URL, "test-token")
	ctx := context.Background()

	out, err := client.CallTool(ctx, "argus_findings", map[string]interface{}{"project_id": "p1"})
	if err != nil {
		t.Fatalf("default action should be summary: %v", err)
	}
	if out.(map[string]interface{})["action"] != "summary" {
		t.Fatalf("default action mismatch: %#v", out)
	}

	if _, err := client.CallTool(ctx, "argus_findings", map[string]interface{}{"action": "delete"}); err == nil ||
		!strings.Contains(err.Error(), "unsupported action") {
		t.Fatalf("expected unsupported action error, got %v", err)
	}
}

func TestArgusFindingsToolRegisteredInServer(t *testing.T) {
	var crawlQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crawlQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"total":0,"page":1,"page_size":200}`))
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_findings",
		Arguments: map[string]any{"action": "summary", "project_id": "p1"},
	})
	if err != nil {
		t.Fatalf("session CallTool(argus_findings): %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &payload); err != nil {
		t.Fatalf("decode findings payload: %v", err)
	}
	if payload["status"] != "success" {
		t.Fatalf("unexpected findings payload: %#v", payload)
	}
	if !strings.Contains(crawlQuery, "project_id=p1") {
		t.Fatalf("server session did not forward project filter: %q", crawlQuery)
	}
}
