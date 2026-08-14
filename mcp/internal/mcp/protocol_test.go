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
	want := map[string]bool{"argus_context": true, "argus_product_search": true, "argus_rule_debug": true, "argus_rule_save": true, "argus_rule_apply": true, "argus_yaksha_exp": true, "argus_exp_workspace": true, "argus_scan_task": true}
	if len(got) != len(want) {
		t.Fatalf("unexpected tool count: got %v want %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("unexpected tool %q in %v", name, got)
		}
	}
	capabilities, _ := json.Marshal(session.InitializeResult().Capabilities.Extensions)
	for _, wantText := range []string{"io.modelcontextprotocol/ui", expConsoleMIMEType} {
		if !strings.Contains(string(capabilities), wantText) {
			t.Fatalf("server capabilities missing %q: %s", wantText, capabilities)
		}
	}
	data, _ := json.Marshal(result.Tools)
	for _, wantText := range []string{"intent", "test_only", "workflow_links", "stable_ref", "argus_product_search", "rule_get", "rule_list", "drafts", "relationship_stats", "relationship_list", "unlinked_fingerprints", "missing_poc_refs", "range_start", "range_end", "product_search for fuzzy", "General-Poc-*", "argus_yaksha_exp", "argus_exp_workspace", "argus_scan_task", "argus.scan-policy/v1", "plan_hash", "revision_create", "exp_id", "revision", "source_sha256", "immutable source identity", expConsoleURI} {
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
	if len(list.Resources) != 12 {
		t.Fatalf("expected 12 resources, got %d", len(list.Resources))
	}
	listData, _ := json.Marshal(list.Resources)
	for _, want := range []string{"argus://argus-mcp/quickstart", "argus://fingerprint/spec", "argus://behavior-probe/spec", "argus://behavior-probe/template", "argus://workflow/template", "argus://examples/fingerprint-poc-workflow"} {
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
	app, err := session.ReadResource(context.Background(), &sdkmcp.ReadResourceParams{URI: expConsoleURI})
	if err != nil {
		t.Fatalf("read EXP console resource: %v", err)
	}
	appData, _ := json.Marshal(app.Contents)
	for _, want := range []string{expConsoleMIMEType, "Yaksha EXP Workspace", "argus_yaksha_exp", "ui/initialize", "tools/call", "prefersBorder"} {
		if !strings.Contains(string(appData), want) {
			t.Fatalf("EXP console resource missing %q: %s", want, appData)
		}
	}
}

func TestExpConsoleUsesYakshaCanonicalParameterTypes(t *testing.T) {
	for _, want := range []string{
		"type === 'boolean'",
		"type === 'text'",
		"type === 'string_array'",
		"type === 'integer'",
		"type === 'number'",
	} {
		if !strings.Contains(expConsoleHTML, want) {
			t.Fatalf("EXP console does not handle Yaksha parameter type %q", want)
		}
	}
	for _, stale := range []string{"item.type === 'Bool'", "item.type === 'Integer'", "item.type === 'StringSlice'"} {
		if strings.Contains(expConsoleHTML, stale) {
			t.Fatalf("EXP console still contains stale CLI type check %q", stale)
		}
	}
	for _, want := range []string{"ui/notifications/tool-cancelled", "ui/resource-teardown", "value.isError", "event.source !== window.parent", "boundContext.exp_id", "boundContext.revision", "boundContext.source_sha256", "workspaceRevision.addEventListener('change'", "value.dependency_refs", "value.asset_refs", "action.value === 'test' ? 'disabled'", "action.value === 'test' && !isBound", "if (!isBound)", "run/debug 必须先保存并绑定 Server EXP Revision", "args.script = source.value", "[source, dependencies, assets]", "内存源码", "egress-mode", "['disabled', 'direct', 'socks5', 'agent']", "risk-confirmed", "proxy.value = ''", "autocomplete=\"new-password\""} {
		if !strings.Contains(expConsoleHTML, want) {
			t.Fatalf("EXP console is missing MCP App lifecycle behavior %q", want)
		}
	}
	if strings.Contains(expConsoleHTML, "proxy.value = a.egress.socks5_proxy") {
		t.Fatal("EXP console must never refill the write-only SOCKS5 URL")
	}
}

func TestYakshaPublicEgressSchemaExposesAgentButExcludesRelay(t *testing.T) {
	schema := yakshaInputSchema()
	properties := schema["properties"].(map[string]interface{})
	egress := properties["egress"].(map[string]interface{})
	if egress["additionalProperties"] != false {
		t.Fatalf("egress schema is not closed: %#v", egress)
	}
	egressProperties := egress["properties"].(map[string]interface{})
	mode := egressProperties["mode"].(map[string]interface{})
	values := mode["enum"].([]string)
	if strings.Join(values, ",") != "disabled,direct,socks5,agent" {
		t.Fatalf("public modes=%v", values)
	}
	proxy := egressProperties["socks5_proxy"].(map[string]interface{})
	if proxy["writeOnly"] != true {
		t.Fatalf("SOCKS5 URL is not write-only: %#v", proxy)
	}
	if _, exists := egressProperties["route_id"]; exists {
		t.Fatal("trusted relay route_id is exposed in the public MCP schema")
	}
}

func TestSDKYakshaToolReturnsStructuredContentAndCompleteDebugTrace(t *testing.T) {
	const hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/exps/exp-debug/revisions/1/sealed-package":
			_, _ = w.Write([]byte(`{"exp_id":"exp-debug","revision":1,"source_sha256":"` + hash + `","script":"cli.check()","dependencies":[],"assets":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/exps/exp-debug/revisions/1/runs":
			_, _ = w.Write([]byte(`{"run_id":"run-1","response":{"status":"Succeeded","debug":{"events":[{"kind":"http","target":"https://authorized.invalid/path?token=full-detail","error":"dial tcp 192.0.2.10:443: exact diagnostic detail"}]}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient(server.URL, "token")
	runner, closeServer := helperYakshaRunner()
	defer closeServer()
	client.yaksha = runner
	session, cleanup := connectTestSession(t, NewServer(client))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "argus_yaksha_exp",
		Arguments: map[string]interface{}{
			"action":         "debug",
			"exp_id":         "exp-debug",
			"revision":       1,
			"source_sha256":  hash,
			"risk_confirmed": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool(argus_yaksha_exp): %v", err)
	}
	if result.IsError || result.StructuredContent == nil {
		t.Fatalf("result=%#v", result)
	}
	raw, _ := json.Marshal(result.StructuredContent)
	for _, want := range []string{"Succeeded", "token=full-detail", "192.0.2.10:443", "exact diagnostic detail"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("structuredContent missing %q: %s", want, raw)
		}
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

func TestRelationshipStatsAndListUseNativeRESTEndpoints(t *testing.T) {
	seen := make([]string, 0, 8)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/dictionaries/fingerprint":
			_, _ = w.Write([]byte(`[
				{"product":"LinkedProduct","rules":["body=\"linked\"","title=\"linked\""]},
				{"product":"UnlinkedProduct","rules":["body=\"unlinked\""]}
			]`))
		case "/api/v1/dictionaries/workflow":
			_, _ = w.Write([]byte(`[
				{"product":"LinkedProduct","type":["root"],"pocs":["linked-poc"]},
				{"product":"MissingFingerProduct","type":["root"],"pocs":["missing-poc"]},
				{"product":"General-Poc-Shiro","type":["root"],"pocs":["general-poc"]}
			]`))
		case "/api/v1/poc-rules":
			_, _ = w.Write([]byte(`[
				{"name":"linked-poc","source_file":"linked-poc.yaml","state":"Approved","enabled":true},
				{"name":"general-poc","source_file":"general-poc.yaml","state":"Approved","enabled":true}
			]`))
		default:
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.String())
		}
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_context",
		Arguments: map[string]any{"action": "relationship_stats", "limit": 5},
	})
	if err != nil {
		t.Fatalf("CallTool relationship_stats: %v", err)
	}
	var stats map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &stats); err != nil {
		t.Fatalf("decode relationship_stats: %v", err)
	}
	totals := stats["totals"].(map[string]interface{})
	if totals["fingerprint_products"].(float64) != 2 ||
		totals["fingerprint_with_workflow"].(float64) != 1 ||
		totals["fingerprint_without_workflow"].(float64) != 1 ||
		totals["workflow_without_fingerprint"].(float64) != 1 ||
		totals["general_poc_workflows"].(float64) != 1 ||
		totals["workflow_missing_poc_references"].(float64) != 1 {
		t.Fatalf("unexpected relationship totals: %#v", totals)
	}

	result, err = session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_context",
		Arguments: map[string]any{"action": "relationship_list", "view": "unlinked_fingerprints", "range_start": 1, "range_end": 10},
	})
	if err != nil {
		t.Fatalf("CallTool relationship_list: %v", err)
	}
	var list map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &list); err != nil {
		t.Fatalf("decode relationship_list: %v", err)
	}
	items := list["items"].([]interface{})
	if list["total"].(float64) != 1 || items[0].(map[string]interface{})["product_name"] != "UnlinkedProduct" {
		t.Fatalf("unexpected relationship list: %#v", list)
	}

	wantRoutes := []string{
		"GET /api/v1/dictionaries/fingerprint?",
		"GET /api/v1/dictionaries/workflow?",
		"GET /api/v1/poc-rules?all=1",
		"GET /api/v1/dictionaries/fingerprint?",
		"GET /api/v1/dictionaries/workflow?",
		"GET /api/v1/poc-rules?all=1",
	}
	if strings.Join(seen, "\n") != strings.Join(wantRoutes, "\n") {
		t.Fatalf("unexpected relationship routes:\n got %v\nwant %v", seen, wantRoutes)
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
		case "/api/v1/active-fingerprint-rules":
			_, _ = w.Write([]byte(`[{"name":"spring-behavior","source_file":"spring-behavior.yaml","product_name":"Spring-Framework","state":"Approved","enabled":true,"computed_auto_profile":"safe","auto_eligible":true}]`))
		case "/api/v1/poc-rules":
			_, _ = w.Write([]byte(`[{"name":"springboot-env","source_file":"springboot-env.yaml","target_product":"Spring Boot Actuator","severity":"high","state":"Approved","enabled":true,"tags":"springboot,actuator","description":"Spring actuator env disclosure"}]`))
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
	for _, want := range []string{`"source": "native_api"`, "Spring-Framework", "springboot-env.yaml", "spring-behavior.yaml", "workflow_linked_poc"} {
		if !strings.Contains(text, want) {
			t.Fatalf("product_search missing %q: %s", want, text)
		}
	}
	wantRoutes := []string{
		"GET /api/v1/dictionaries/fingerprint?",
		"GET /api/v1/dictionaries/workflow?",
		"GET /api/v1/active-fingerprint-rules?all=1",
		"GET /api/v1/poc-rules?all=1",
	}
	if strings.Join(seen, "\n") != strings.Join(wantRoutes, "\n") {
		t.Fatalf("unexpected product_search routes:\n got %v\nwant %v", seen, wantRoutes)
	}
}
