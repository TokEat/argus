package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func connectTestSession(t *testing.T, server *sdkmcp.Server) (*sdkmcp.ClientSession, func()) {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := sdkmcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "argus-mcp-test-client", Version: "0.1.0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Wait()
		t.Fatalf("connect client: %v", err)
	}
	return clientSession, func() {
		_ = clientSession.Close()
		_ = serverSession.Wait()
	}
}

func TestSDKServerListsOnlyAggregateTools(t *testing.T) {
	session, cleanup := connectTestSession(t, NewServer(NewClient("http://argus.local", "token")))
	defer cleanup()

	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	got := make([]string, 0, len(result.Tools))
	for _, tool := range result.Tools {
		got = append(got, tool.Name)
	}
	want := map[string]bool{"argus_context": true, "argus_product_search": true, "argus_rule_debug": true, "argus_rule_save": true, "argus_rule_apply": true}
	if len(got) != len(want) {
		t.Fatalf("unexpected tool count: got %v want %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("unexpected tool %q in %v", name, got)
		}
	}
	data, _ := json.Marshal(result.Tools)
	for _, wantText := range []string{"intent", "test_only", "workflow_links", "stable_ref", "argus_product_search", "rule_get", "rule_list", "drafts", "range_start", "range_end", "product_search for fuzzy"} {
		if !strings.Contains(string(data), wantText) {
			t.Fatalf("tool schema/description missing %q: %s", wantText, data)
		}
	}
}

func TestSDKServerListsAndReadsResources(t *testing.T) {
	var seenPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"uri":"argus://fingerprint/spec","mime_type":"text/markdown","text":"fingerprint spec"}`))
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "token")))
	defer cleanup()

	list, err := session.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(list.Resources) != 11 {
		t.Fatalf("expected 11 resources, got %d", len(list.Resources))
	}
	listData, _ := json.Marshal(list.Resources)
	for _, want := range []string{"argus://argus-mcp/quickstart", "argus://fingerprint/spec", "argus://workflow/template", "argus://examples/fingerprint-poc-workflow"} {
		if !strings.Contains(string(listData), want) {
			t.Fatalf("resource list missing %q: %s", want, listData)
		}
	}
	read, err := session.ReadResource(context.Background(), &sdkmcp.ReadResourceParams{URI: "argus://fingerprint/spec"})
	if err != nil {
		t.Fatalf("read resource: %v", err)
	}
	if seenPath != "/api/v1/mcp/resources/fingerprint/spec" {
		t.Fatalf("unexpected resource path: %s", seenPath)
	}
	data, _ := json.Marshal(read.Contents)
	if !strings.Contains(string(data), "fingerprint spec") || !strings.Contains(string(data), "text/markdown") {
		t.Fatalf("unexpected resource contents: %s", data)
	}
}

func TestSDKServerRoutesAggregateToolsToNativeRESTEndpoints(t *testing.T) {
	seen := make([]string, 0, 4)
	var seenArsenalListQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/nodes":
			_, _ = w.Write([]byte(`[{"agent_id":"agent-1","status":"Alive"}]`))
		case "/api/v1/arsenals/poc/native-route.yaml":
			_, _ = w.Write([]byte(`{"status":"saved","artifact_id":"poc_native-route.yaml","file_name":"native-route.yaml","hash":"h1","version":3,"state":"Draft"}`))
		case "/api/v1/arsenals/poc":
			seenArsenalListQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`[{"ID":"poc_native-route.yaml","FileName":"native-route.yaml","Hash":"h1","Version":3,"State":"Draft"}]`))
		case "/api/v1/arsenals/poc/native-route.yaml/approve":
			_, _ = w.Write([]byte(`{"status":"approved","rule_version":"v-test"}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	cases := []struct {
		name string
		args map[string]any
	}{
		{name: "argus_context", args: map[string]any{"action": "agents"}},
		{name: "argus_rule_save", args: map[string]any{"rule_type": "poc", "file_name": "native-route.yaml", "content": "id: native-route\ninfo:\n  name: native route\n  severity: info\nrequests: []\n"}},
		{name: "argus_rule_apply", args: map[string]any{"action": "publish", "rule_type": "poc", "file_name": "native-route.yaml", "hash": "h1", "version": 3}},
	}
	for _, tc := range cases {
		result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
			Name:      tc.name,
			Arguments: tc.args,
		})
		if err != nil {
			t.Fatalf("CallTool(%s): %v", tc.name, err)
		}
		if len(result.Content) != 1 {
			t.Fatalf("CallTool(%s) returned %d content items", tc.name, len(result.Content))
		}
		text := result.Content[0].(*sdkmcp.TextContent).Text
		if !strings.Contains(text, `"stable_ref"`) && tc.name == "argus_rule_save" {
			t.Fatalf("CallTool(%s) returned no stable_ref: %s", tc.name, text)
		}
	}

	want := []string{
		"GET /api/v1/nodes",
		"POST /api/v1/arsenals/poc/native-route.yaml",
		"GET /api/v1/arsenals/poc",
		"POST /api/v1/arsenals/poc/native-route.yaml/approve",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected aggregate routes:\n got %v\nwant %v", seen, want)
	}
	if seenArsenalListQuery != "all=1&lite=1" {
		t.Fatalf("publish freshness should use lite arsenal listing, got query %q", seenArsenalListQuery)
	}
}

func TestContextRuleListRangeAndDrafts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/arsenals/poc":
			if r.URL.Query().Get("all") != "1" || r.URL.Query().Get("lite") != "1" {
				t.Fatalf("expected arsenals all=1&lite=1, got %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[
				{"ID":"poc_a.yaml","Type":"poc","FileName":"a.yaml","Hash":"ha","Version":1,"State":"Approved","UpdatedAt":"2026-06-18T10:00:00Z"},
				{"ID":"poc_b.yaml","Type":"poc","FileName":"b.yaml","Hash":"hb","Version":2,"State":"Draft","UpdatedAt":"2026-06-18T09:00:00Z"},
				{"ID":"poc_c.yaml","Type":"poc","FileName":"c.yaml","Hash":"hc","Version":3,"State":"Approved","UpdatedAt":"2026-06-18T08:00:00Z"},
				{"ID":"poc_d.yaml","Type":"poc","FileName":"d.yaml","Hash":"hd","Version":4,"State":"Draft","UpdatedAt":"2026-06-18T07:00:00Z"}
			]`))
		case "/api/v1/poc-rules":
			_, _ = w.Write([]byte(`[{"artifact_id":"poc_b.yaml","source_file":"b.yaml","name":"b"},{"artifact_id":"poc_d.yaml","source_file":"d.yaml","name":"d"}]`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_context",
		Arguments: map[string]any{"action": "rule_list", "rule_type": "poc", "range_start": 1, "range_end": 2},
	})
	if err != nil {
		t.Fatalf("CallTool(rule_list): %v", err)
	}
	var listed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &listed); err != nil {
		t.Fatalf("decode rule_list: %v", err)
	}
	if listed["total"].(float64) != 4 || listed["returned"].(float64) != 2 || listed["has_more"] != true || listed["next_range_start"].(float64) != 3 {
		t.Fatalf("unexpected rule_list paging: %#v", listed)
	}
	items := listed["items"].([]interface{})
	if first := items[0].(map[string]interface{}); first["file_name"] != "a.yaml" || first["content"] != nil {
		t.Fatalf("unexpected first range item: %#v", first)
	}

	result, err = session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_context",
		Arguments: map[string]any{"action": "rule_list", "rule_type": "poc", "range_start": 3, "range_end": 4},
	})
	if err != nil {
		t.Fatalf("CallTool(rule_list second range): %v", err)
	}
	var second map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &second); err != nil {
		t.Fatalf("decode second rule_list: %v", err)
	}
	secondItems := second["items"].([]interface{})
	if got := secondItems[0].(map[string]interface{})["file_name"]; got != "c.yaml" {
		t.Fatalf("range_start=3 repeated previous rows, first file = %#v", got)
	}

	result, err = session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_context",
		Arguments: map[string]any{"action": "drafts", "rule_type": "poc", "range_start": 1, "range_end": 10},
	})
	if err != nil {
		t.Fatalf("CallTool(drafts): %v", err)
	}
	var drafts map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &drafts); err != nil {
		t.Fatalf("decode drafts: %v", err)
	}
	draftItems := drafts["items"].([]interface{})
	if drafts["total"].(float64) != 2 || draftItems[0].(map[string]interface{})["state"] != "Draft" || draftItems[1].(map[string]interface{})["state"] != "Draft" {
		t.Fatalf("drafts should only return Draft rows: %#v", drafts)
	}
}

func TestContextRuleGetReturnsExactContentAndPyexpRuleID(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/arsenals/poc":
			_, _ = w.Write([]byte(`[{"ID":"poc_exact.yaml","Type":"poc","FileName":"exact.yaml","Content":"id: exact\ninfo:\n  name: Exact\n","Hash":"hp","Version":5,"State":"Draft","UpdatedAt":"2026-06-18T10:00:00Z"}]`))
		case "/api/v1/poc-rules":
			_, _ = w.Write([]byte(`[
				{"artifact_id":"poc_other.yaml","source_file":"other.yaml","name":"other","severity":"low"},
				{"artifact_id":"poc_exact.yaml","source_file":"exact.yaml","name":"exact","severity":"info"}
			]`))
		case "/api/v1/dictionaries/workflow":
			_, _ = w.Write([]byte(`[{"product":"ExactProduct","pocs":["exact.yaml"],"type":["root"]}]`))
		case "/api/v1/arsenals/exp":
			_, _ = w.Write([]byte(`[{"ID":"exp_demo.py","Type":"exp","FileName":"demo.py","Content":"ARGUS_EXP = {\"id\":\"exp-demo\"}\n","Hash":"he","Version":7,"State":"Approved","UpdatedAt":"2026-06-18T09:00:00Z"}]`))
		case "/api/v1/exploits":
			_, _ = w.Write([]byte(`[{"artifact_id":"exp_demo.py","source_file":"demo.py","rule_id":"exp-demo","name":"Demo EXP","linked_pocs":["exact.yaml"]}]`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_context",
		Arguments: map[string]any{"action": "rule_get", "rule_type": "poc", "file_name": "exact.yaml"},
	})
	if err != nil {
		t.Fatalf("CallTool(rule_get poc): %v", err)
	}
	var poc map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &poc); err != nil {
		t.Fatalf("decode poc rule_get: %v", err)
	}
	if poc["content"] == "" || poc["hash"] != "hp" || poc["version"].(float64) != 5 || poc["state"] != "Draft" {
		t.Fatalf("unexpected poc rule_get: %#v", poc)
	}
	refs := poc["references"].(map[string]interface{})
	if len(refs["workflows"].([]interface{})) != 1 {
		t.Fatalf("expected workflow reference for POC: %#v", poc)
	}

	result, err = session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_context",
		Arguments: map[string]any{"action": "rule_get", "rule_type": "pyexp", "rule_id": "exp-demo"},
	})
	if err != nil {
		t.Fatalf("CallTool(rule_get pyexp): %v", err)
	}
	var exp map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &exp); err != nil {
		t.Fatalf("decode exp rule_get: %v", err)
	}
	if exp["file_name"] != "demo.py" || !strings.Contains(exp["content"].(string), "ARGUS_EXP") || exp["hash"] != "he" {
		t.Fatalf("unexpected pyexp rule_get: %#v", exp)
	}
}

func TestPyexpDebugResolvesCurrentExploitIDThroughNativeList(t *testing.T) {
	seen := make([]string, 0, 2)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/exploits":
			if r.URL.RawQuery != "all=1" {
				t.Fatalf("expected pyexp resolve to include all=1, got %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[{"id":42,"artifact_id":"exp_demo.py","source_file":"demo.py","rule_id":"exp-demo"}]`))
		case "/api/v1/exploits/42/debug":
			_, _ = w.Write([]byte(`{"status":"started","session_id":"debug-1"}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "argus_rule_debug",
		Arguments: map[string]any{
			"rule_type":  "pyexp",
			"file_name":  "demo.py",
			"agent_id":   "agent-1",
			"target_url": "http://target.local",
			"params":     map[string]any{"marker": "argus"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool(argus_rule_debug): %v", err)
	}
	text := result.Content[0].(*sdkmcp.TextContent).Text
	if !strings.Contains(text, `"session_id": "debug-1"`) || strings.Contains(text, `"exploit_rule_id"`) {
		t.Fatalf("unexpected pyexp debug result: %s", text)
	}
	want := []string{"GET /api/v1/exploits", "POST /api/v1/exploits/42/debug"}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected pyexp debug routes:\n got %v\nwant %v", seen, want)
	}
}

func TestPyexpSourceDryRunUsesSourceEndpointWithoutResolve(t *testing.T) {
	seen := make([]string, 0, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/exploits/source/dry-run":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode dry-run body: %v", err)
			}
			if body["source"] == "" || body["target"] != "http://target.local" {
				t.Fatalf("unexpected dry-run body: %#v", body)
			}
			_, _ = w.Write([]byte(`{"status":"validated","exploit_id":"exp-source","params_valid":true}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "argus_rule_debug",
		Arguments: map[string]any{
			"rule_type":  "pyexp",
			"action":     "dry_run",
			"source":     "ARGUS_EXP = {}",
			"target_url": "http://target.local",
			"params":     map[string]any{},
		},
	})
	if err != nil {
		t.Fatalf("CallTool(argus_rule_debug source dry-run): %v", err)
	}
	text := result.Content[0].(*sdkmcp.TextContent).Text
	if !strings.Contains(text, `"source_level": true`) || !strings.Contains(text, `"params_valid": true`) {
		t.Fatalf("unexpected source dry-run result: %s", text)
	}
	want := []string{"POST /api/v1/exploits/source/dry-run"}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected source dry-run routes:\n got %v\nwant %v", seen, want)
	}
}

func TestPyexpSourceDebugUsesMCPDebugEndpointWithoutResolve(t *testing.T) {
	seen := make([]string, 0, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/exploits/source/debug":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode debug body: %v", err)
			}
			if body["source"] == "" || body["agent_id"] != "agent-1" {
				t.Fatalf("unexpected debug body: %#v", body)
			}
			_, _ = w.Write([]byte(`{"status":"completed","result":{"status":"Succeeded"}}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "argus_rule_debug",
		Arguments: map[string]any{
			"rule_type":  "pyexp",
			"action":     "run",
			"source":     "ARGUS_EXP = {}",
			"agent_id":   "agent-1",
			"target_url": "http://target.local",
		},
	})
	if err != nil {
		t.Fatalf("CallTool(argus_rule_debug source debug): %v", err)
	}
	text := result.Content[0].(*sdkmcp.TextContent).Text
	if !strings.Contains(text, `"source_level": true`) || !strings.Contains(text, `"Succeeded"`) {
		t.Fatalf("unexpected source debug result: %s", text)
	}
	want := []string{"POST /api/v1/exploits/source/debug"}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected source debug routes:\n got %v\nwant %v", seen, want)
	}
}

func TestFingerprintAndWorkflowSaveComposeNativeArsenalDrafts(t *testing.T) {
	seen := make([]string, 0, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/arsenals/finger":
			_, _ = w.Write([]byte(`[{"ID":"finger_finger.yaml","FileName":"finger.yaml","Content":"ExistingProduct:\n  - body=\"old\"\n","Hash":"old","Version":1,"State":"Approved"}]`))
		case "POST /api/v1/arsenals/finger/finger.yaml":
			var body struct {
				Content string `json:"content"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode finger save: %v", err)
			}
			if !strings.Contains(body.Content, "ExistingProduct") || !strings.Contains(body.Content, "ArgusMCPNativeFinger") || !strings.Contains(body.Content, `body="native"`) {
				t.Fatalf("unexpected finger content: %s", body.Content)
			}
			_, _ = w.Write([]byte(`{"status":"saved","file_name":"finger.yaml","hash":"finger-hash","version":2,"state":"Draft"}`))
		case "GET /api/v1/arsenals/workflow":
			_, _ = w.Write([]byte(`[{"ID":"workflow_workflow.yaml","FileName":"workflow.yaml","Content":"ExistingProduct:\n  type:\n    - root\n  pocs:\n    - old.yaml\n","Hash":"old","Version":1,"State":"Approved"}]`))
		case "POST /api/v1/arsenals/workflow/workflow.yaml":
			var body struct {
				Content string `json:"content"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode workflow save: %v", err)
			}
			if !strings.Contains(body.Content, "ArgusMCPNativeFinger") || !strings.Contains(body.Content, "native-poc.yaml") || !strings.Contains(body.Content, "root") {
				t.Fatalf("unexpected workflow content: %s", body.Content)
			}
			_, _ = w.Write([]byte(`{"status":"saved","file_name":"workflow.yaml","hash":"workflow-hash","version":2,"state":"Draft"}`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.String())
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{name: "fingerprint", args: map[string]any{"rule_type": "fingerprint", "product_name": "ArgusMCPNativeFinger", "rules": []any{`body="native"`}}},
		{name: "workflow", args: map[string]any{"rule_type": "workflow", "product_name": "ArgusMCPNativeFinger", "workflow_types": []any{"root"}, "workflow_pocs": []any{"native-poc.yaml"}}},
	} {
		result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: "argus_rule_save", Arguments: tc.args})
		if err != nil {
			t.Fatalf("CallTool save %s: %v", tc.name, err)
		}
		text := result.Content[0].(*sdkmcp.TextContent).Text
		if !strings.Contains(text, `"stable_ref"`) {
			t.Fatalf("save %s missing stable_ref: %s", tc.name, text)
		}
	}

	want := []string{
		"GET /api/v1/arsenals/finger?all=1",
		"POST /api/v1/arsenals/finger/finger.yaml?",
		"GET /api/v1/arsenals/workflow?all=1",
		"POST /api/v1/arsenals/workflow/workflow.yaml?",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected save routes:\n got %v\nwant %v", seen, want)
	}
}

func TestWorkflowContextUsesNativeRESTEndpoints(t *testing.T) {
	seen := make([]string, 0, 3)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/dictionaries/fingerprint":
			_, _ = w.Write([]byte(`[{"product":"ArgusMCPNative","rules":["body=\"native\""]}]`))
		case "/api/v1/dictionaries/workflow":
			_, _ = w.Write([]byte(`[{"product":"ArgusMCPNative","type":["root"],"pocs":["native-poc.yaml"]},{"product":"BrokenProduct","type":["root"],"pocs":["missing.yaml"]}]`))
		case "/api/v1/poc-rules":
			_, _ = w.Write([]byte(`[{"name":"native-poc","source_file":"native-poc.yaml","severity":"info","state":"Approved","enabled":true}]`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.String())
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_context",
		Arguments: map[string]any{"action": "workflow_links", "product_name": "ArgusMCPNative", "limit": 5},
	})
	if err != nil {
		t.Fatalf("CallTool workflow_links: %v", err)
	}
	text := result.Content[0].(*sdkmcp.TextContent).Text
	for _, want := range []string{`"source": "native_api"`, "ArgusMCPNative", "native-poc.yaml"} {
		if !strings.Contains(text, want) {
			t.Fatalf("workflow_links missing %q: %s", want, text)
		}
	}
	for _, got := range seen {
		if strings.Contains(got, "/mcp/tools/rule/context") {
			t.Fatalf("workflow context used MCP aggregate route: %v", seen)
		}
	}
	wantRoutes := []string{
		"GET /api/v1/dictionaries/fingerprint?",
		"GET /api/v1/dictionaries/workflow?",
		"GET /api/v1/poc-rules?all=1",
	}
	if strings.Join(seen, "\n") != strings.Join(wantRoutes, "\n") {
		t.Fatalf("unexpected workflow context routes:\n got %v\nwant %v", seen, wantRoutes)
	}
}

func TestProductSearchUsesNativeRESTIndexes(t *testing.T) {
	seen := make([]string, 0, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/dictionaries/fingerprint":
			_, _ = w.Write([]byte(`[{"product":"Spring-Framework","rules":["title=\"Spring Boot\""]}]`))
		case "/api/v1/dictionaries/workflow":
			_, _ = w.Write([]byte(`[{"product":"Spring-Framework","type":["root"],"pocs":["springboot-env.yaml"]}]`))
		case "/api/v1/poc-rules":
			_, _ = w.Write([]byte(`[{"name":"springboot-env","source_file":"springboot-env.yaml","target_product":"Spring Boot Actuator","severity":"high","state":"Approved","enabled":true,"tags":"springboot,actuator","description":"Spring actuator env disclosure"}]`))
		case "/api/v1/exploits":
			_, _ = w.Write([]byte(`[{"id":7,"artifact_id":"exp_spring.py","rule_id":"exp-spring","name":"Spring EXP","source_file":"spring.py","target_product":"Spring-Framework","risk_level":"low","state":"Approved","enabled":true}]`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.String())
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_product_search",
		Arguments: map[string]any{"query": "spring boot", "limit": 5},
	})
	if err != nil {
		t.Fatalf("CallTool product_search: %v", err)
	}
	text := result.Content[0].(*sdkmcp.TextContent).Text
	for _, want := range []string{`"source": "native_api"`, "Spring-Framework", "springboot-env.yaml", "exp-spring", "workflow_linked_poc"} {
		if !strings.Contains(text, want) {
			t.Fatalf("product_search missing %q: %s", want, text)
		}
	}
	wantRoutes := []string{
		"GET /api/v1/dictionaries/fingerprint?",
		"GET /api/v1/dictionaries/workflow?",
		"GET /api/v1/poc-rules?all=1",
		"GET /api/v1/exploits?all=1",
	}
	if strings.Join(seen, "\n") != strings.Join(wantRoutes, "\n") {
		t.Fatalf("unexpected product_search routes:\n got %v\nwant %v", seen, wantRoutes)
	}
}

func TestSDKStreamableHTTPHandlerListsTools(t *testing.T) {
	handler := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
		return NewServer(NewClient("http://argus.local", "token"))
	}, &sdkmcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "argus-mcp-http-test-client", Version: "0.1.0"}, nil)
	session, err := client.Connect(context.Background(), &sdkmcp.StreamableClientTransport{
		Endpoint:             ts.URL,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect streamable http client: %v", err)
	}
	defer session.Close()

	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools over streamable http: %v", err)
	}
	if len(result.Tools) != 5 {
		t.Fatalf("expected 5 tools over streamable http, got %d", len(result.Tools))
	}
}

func TestClientTurnsHTTPErrorIntoMessage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("missing bearer token: %q", got)
		}
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "test-token")
	_, err := client.Resource(context.Background(), "argus://pyexp/spec")
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("expected HTTP error detail, got %v", err)
	}
}

func TestClientRejectsLegacyFineGrainedEXPTools(t *testing.T) {
	client := NewClient("http://argus.local", "test-token")
	for _, name := range []string{"pyexp_validate", "pyexp_dry_run", "pyexp_save_draft", "pyexp_debug"} {
		_, err := client.CallTool(context.Background(), name, map[string]interface{}{})
		if err == nil || !strings.Contains(err.Error(), "unknown tool") {
			t.Fatalf("CallTool(%s) error = %v, want unknown tool", name, err)
		}
	}
}

func TestConfigLoadsTokenFileWhenTokenEnvIsEmpty(t *testing.T) {
	t.Setenv("ARGUS_BASE_URL", "http://argus.local")
	t.Setenv("ARGUS_TOKEN", "")
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(" file-token \n"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	t.Setenv("ARGUS_TOKEN_FILE", tokenPath)

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Token != "file-token" {
		t.Fatalf("expected token from file, got %q", cfg.Token)
	}
}
