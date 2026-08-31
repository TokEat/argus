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

func TestSDKServerListsFocusedTools(t *testing.T) {
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
	want := map[string]bool{}
	for _, name := range focusedMCPToolNames() {
		want[name] = true
	}
	if len(got) != len(want) {
		t.Fatalf("unexpected tool count: got %v want %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("unexpected tool %q in %v", name, got)
		}
	}
	for _, banned := range []string{"argus_context", "argus_rule_debug", "argus_rule_save", "argus_scan_task"} {
		if want[banned] {
			t.Fatalf("banned aggregate tool %q still registered", banned)
		}
		for _, name := range got {
			if name == banned {
				t.Fatalf("banned aggregate tool %q still listed", banned)
			}
		}
	}
	if instr := session.InitializeResult().Instructions; !strings.Contains(instr, "argus_help") || !strings.Contains(instr, "do not have the Argus source") {
		t.Fatalf("missing source-less instructions: %q", instr)
	}
	capabilities, _ := json.Marshal(session.InitializeResult().Capabilities.Extensions)
	for _, wantText := range []string{"io.modelcontextprotocol/ui", expConsoleMIMEType} {
		if !strings.Contains(string(capabilities), wantText) {
			t.Fatalf("server capabilities missing %q: %s", wantText, capabilities)
		}
	}
	data, _ := json.Marshal(result.Tools)
	for _, wantText := range []string{"intent", "test_only", "stable_ref", "argus_help", "argus_resource", "argus_rule_get", "argus_rule_list", "drafts", "argus_coverage", "include_content", "range_start", "range_end", "Hyphens are literal", "argus_yaksha_exp", "argus_exp_workspace", "argus_scan_preview", "argus_scan_create", "argus.scan-policy/v1", "plan_hash", "revision_create", "exp_id", "revision", "source_sha256", "immutable source identity", expConsoleURI, `"dir"`, "argus_debug_fingerprint", "argus_save_poc"} {
		if !strings.Contains(string(data), wantText) {
			t.Fatalf("tool schema/description missing %q: %s", wantText, data)
		}
	}
	if strings.Contains(string(data), `"argus_context"`) || strings.Contains(string(data), `"argus_scan_task"`) || strings.Contains(string(data), `"argus_rule_debug"`) || strings.Contains(string(data), `"argus_rule_save"`) {
		t.Fatalf("aggregate tool names leaked into schema: %s", data)
	}
	for _, tool := range result.Tools {
		if tool.Name != "argus_coverage" {
			continue
		}
		schema, _ := json.Marshal(tool.InputSchema)
		if strings.Contains(string(schema), "range_start") || strings.Contains(string(schema), "range_end") {
			t.Fatalf("argus_coverage must not advertise range fields: %s", schema)
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
	if len(list.Resources) != 14 {
		t.Fatalf("expected 14 resources, got %d", len(list.Resources))
	}
	listData, _ := json.Marshal(list.Resources)
	for _, want := range []string{"argus://argus-mcp/quickstart", "argus://fingerprint/spec", "argus://dir/spec", "argus://dir/template", "argus://behavior-probe/spec", "argus://behavior-probe/template", "argus://workflow/template", "argus://examples/fingerprint-poc-workflow"} {
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
	for _, want := range []string{expConsoleMIMEType, "Yaksha EXP Studio", "argus_yaksha_exp", "ui/initialize", "tools/call", "prefersBorder"} {
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
		"item.input_type === 'host_port'",
		"item.input_type === 'url'",
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
	for _, want := range []string{"ui/notifications/tool-cancelled", "ui/resource-teardown", "value.isError", "event.source !== window.parent", "boundContext.exp_id", "boundContext.revision", "boundContext.source_sha256", "workspaceRevision.addEventListener('change'", "current.cli_schema", "value.dependency_refs", "value.asset_refs", "action.value === 'test' ? 'disabled'", "action.value === 'test' && !isBound", "if (!isBound)", "checkpointWorkspace", "args.script = source.value", "[source, dependencies, assets, tests]", "draft_inspect", "draft_test", "draftReceipt", "scheduleLiveInspect", "renderFlow", "内存源码", "egress-mode", "['disabled', 'direct', 'socks5', 'agent']", "risk-confirmed", "proxy.value = ''", "autocomplete=\"new-password\"", "EXP 生命周期", "clearBinding(true)", "result-tabs", "parseTargets", "resetRunContext()"} {
		if !strings.Contains(expConsoleHTML, want) {
			t.Fatalf("EXP console is missing MCP App lifecycle behavior %q", want)
		}
	}
	if strings.Contains(expConsoleHTML, "proxy.value = a.egress.socks5_proxy") {
		t.Fatal("EXP console must never refill the write-only SOCKS5 URL")
	}
	if strings.Contains(expConsoleHTML, "await checkpointWorkspace();\n\t        isBound = true") {
		t.Fatal("MCP App must never auto-save an untested in-memory draft before debug/run")
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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/mcp/tools/rule/context":
			_, _ = w.Write([]byte(`{"status":"success","agents":[{"agent_id":"agent-1","status":"Alive"}]}`))
		case "/api/v1/mcp/tools/rule/save":
			_, _ = w.Write([]byte(`{"status":"saved","artifact_id":"poc_native-route.yaml","file_name":"native-route.yaml","hash":"h1","version":3,"state":"Draft"}`))
		case "/api/v1/mcp/tools/rule/apply":
			_, _ = w.Write([]byte(`{"status":"approved","file_name":"native-route.yaml","hash":"h1","version":3}`))
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
		{name: "argus_agents", args: map[string]any{}},
		{name: "argus_save_poc", args: map[string]any{"file_name": "native-route.yaml", "content": "id: native-route\ninfo:\n  name: native route\n  severity: info\nrequests: []\n"}},
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
		if !strings.Contains(text, `"stable_ref"`) && tc.name == "argus_save_poc" {
			t.Fatalf("CallTool(%s) returned no stable_ref: %s", tc.name, text)
		}
	}

	want := []string{
		"POST /api/v1/mcp/tools/rule/context",
		"POST /api/v1/mcp/tools/rule/save",
		"POST /api/v1/mcp/tools/rule/apply",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected aggregate routes:\n got %v\nwant %v", seen, want)
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
		Name:      "argus_rule_list",
		Arguments: map[string]any{"rule_type": "poc", "range_start": 1, "range_end": 2},
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
		Name:      "argus_rule_list",
		Arguments: map[string]any{"rule_type": "poc", "range_start": 3, "range_end": 4},
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
		Name:      "argus_rule_list",
		Arguments: map[string]any{"rule_type": "poc", "state": "Draft", "range_start": 1, "range_end": 10},
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

func TestContextRuleGetReturnsProductNamesWithoutYAML(t *testing.T) {
	const yamlBody = "ProdA:\n  - body=\"a\"\nProdB:\n  - body=\"b\"\nProdC:\n  - body=\"c\"\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/arsenals/finger/finger.yaml" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ID":"finger_finger.yaml","Type":"finger","FileName":"finger.yaml","Hash":"h1","Version":1,"State":"Approved","Content":` + jsonString(yamlBody) + `,"UpdatedAt":"2026-06-18T10:00:00Z"}`))
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_rule_get",
		Arguments: map[string]any{"rule_type": "fingerprint"},
	})
	if err != nil {
		t.Fatalf("CallTool(rule_get): %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &got); err != nil {
		t.Fatalf("decode rule_get: %v", err)
	}
	if _, exists := got["content"]; exists {
		t.Fatalf("rule_get should omit YAML content by default: %#v", got)
	}
	if got["content_included"] != false || got["product_count"].(float64) != 3 {
		t.Fatalf("unexpected rule_get metadata: %#v", got)
	}
	products, ok := got["products"].([]interface{})
	if !ok || len(products) != 3 {
		t.Fatalf("expected compact name array, got %#v", got["products"])
	}
	for i, name := range []string{"ProdA", "ProdB", "ProdC"} {
		if products[i] != name {
			t.Fatalf("products[%d]=%#v want %q (names only, no nested JSON)", i, products[i], name)
		}
	}

	result, err = session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_rule_get",
		Arguments: map[string]any{"rule_type": "fingerprint", "product_name": "ProdB"},
	})
	if err != nil {
		t.Fatalf("CallTool(rule_get product_name): %v", err)
	}
	var one map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &one); err != nil {
		t.Fatalf("decode product rule_get: %v", err)
	}
	if _, exists := one["products"]; exists {
		t.Fatalf("product_name lookup should not echo the full name list: %#v", one)
	}
	entry, _ := one["product_entry"].(map[string]interface{})
	if entry["product_name"] != "ProdB" {
		t.Fatalf("unexpected product_entry: %#v", one["product_entry"])
	}

	result, err = session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_rule_get",
		Arguments: map[string]any{"rule_type": "fingerprint", "include_content": true},
	})
	if err != nil {
		t.Fatalf("CallTool(rule_get include_content): %v", err)
	}
	var withContent map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &withContent); err != nil {
		t.Fatalf("decode include_content: %v", err)
	}
	content, _ := withContent["content"].(string)
	if withContent["content_included"] != true || !strings.Contains(content, "ProdA") {
		t.Fatalf("small file include_content should return YAML: %#v", withContent)
	}
}

func TestContextRuleGetPOCDoesNotUseYAMLKeysAsProducts(t *testing.T) {
	const yamlBody = "id: mcp-server-detect\ninfo:\n  name: MCP Server Detect\n  author: argus\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/arsenals/poc/mcp-server-detect.yaml" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ID":"poc_mcp-server-detect.yaml","Type":"poc","FileName":"mcp-server-detect.yaml","Hash":"h1","Version":1,"State":"Approved","Content":` + jsonString(yamlBody) + `,"UpdatedAt":"2026-06-18T10:00:00Z"}`))
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token")))
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_rule_get",
		Arguments: map[string]any{"rule_type": "poc", "file_name": "mcp-server-detect.yaml"},
	})
	if err != nil {
		t.Fatalf("CallTool(rule_get poc): %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].(*sdkmcp.TextContent).Text), &got); err != nil {
		t.Fatalf("decode poc rule_get: %v", err)
	}
	if _, exists := got["products"]; exists {
		t.Fatalf("POC rule_get must not treat YAML keys as products: %#v", got)
	}
	if got["template_id"] != "mcp-server-detect" || got["template_name"] != "MCP Server Detect" {
		t.Fatalf("unexpected POC identity: %#v", got)
	}
}

func jsonString(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}
