package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

var resourceEndpoints = map[string]string{
	"argus://argus-mcp/quickstart":              "/api/v1/mcp/resources/argus-mcp/quickstart",
	"argus://argus-mcp/tool-guide":              "/api/v1/mcp/resources/argus-mcp/tool-guide",
	"argus://fingerprint/spec":                  "/api/v1/mcp/resources/fingerprint/spec",
	"argus://fingerprint/template":              "/api/v1/mcp/resources/fingerprint/template",
	"argus://poc/spec":                          "/api/v1/mcp/resources/poc/spec",
	"argus://poc/template":                      "/api/v1/mcp/resources/poc/template",
	"argus://workflow/spec":                     "/api/v1/mcp/resources/workflow/spec",
	"argus://workflow/template":                 "/api/v1/mcp/resources/workflow/template",
	"argus://examples/fingerprint-poc-workflow": "/api/v1/mcp/resources/examples/fingerprint-poc-workflow",
	"argus://pyexp/spec":                        "/api/v1/mcp/resources/pyexp/spec",
	"argus://pyexp/template":                    "/api/v1/mcp/resources/pyexp/template",
}

func NewServer(client *Client) *sdkmcp.Server {
	server := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "argus-mcp", Version: "0.1.0"}, &sdkmcp.ServerOptions{
		Capabilities: &sdkmcp.ServerCapabilities{
			Extensions: map[string]interface{}{
				"io.modelcontextprotocol/ui": map[string]interface{}{
					"mimeTypes": []string{expConsoleMIMEType},
				},
			},
			Resources: &sdkmcp.ResourceCapabilities{},
			Tools:     &sdkmcp.ToolCapabilities{},
		},
	})
	RegisterArgusMCP(server, client)
	return server
}

func RegisterArgusMCP(server *sdkmcp.Server, client *Client) {
	for _, resource := range resources() {
		resource := resource
		server.AddResource(resource, func(ctx context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
			payload, err := client.Resource(ctx, req.Params.URI)
			if err != nil {
				return nil, err
			}
			return &sdkmcp.ReadResourceResult{
				Contents: []*sdkmcp.ResourceContents{{
					URI:      payload.URI,
					MIMEType: payload.MIMEType,
					Text:     payload.Text,
					Meta:     sdkmcp.Meta(payload.Meta),
				}},
			}, nil
		})
	}
	for _, tool := range tools() {
		tool := tool
		server.AddTool(tool, func(ctx context.Context, req *sdkmcp.CallToolRequest) (*sdkmcp.CallToolResult, error) {
			args := map[string]interface{}{}
			if len(req.Params.Arguments) > 0 {
				if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
					return nil, fmt.Errorf("invalid tools/call arguments: %w", err)
				}
			}
			result, err := client.CallTool(ctx, tool.Name, args)
			if err != nil {
				if tool.Name == "argus_yaksha_exp" {
					return &sdkmcp.CallToolResult{
						Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: err.Error()}},
						IsError: true,
					}, nil
				}
				return nil, err
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			response := &sdkmcp.CallToolResult{
				Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: string(data)}},
			}
			if tool.Name == "argus_yaksha_exp" {
				response.StructuredContent = result
			}
			return response, nil
		})
	}
}

func resources() []*sdkmcp.Resource {
	return []*sdkmcp.Resource{
		{URI: "argus://argus-mcp/quickstart", Name: "Argus MCP Quickstart", Description: "Start here when the client has no Argus source code.", MIMEType: "text/markdown"},
		{URI: "argus://argus-mcp/tool-guide", Name: "Argus MCP Tool Guide", Description: "How to use the four aggregate MCP tools and their required field combinations.", MIMEType: "text/markdown"},
		{URI: "argus://fingerprint/spec", Name: "Argus Fingerprint Spec", Description: "Fingerprint YAML format and rule expression examples.", MIMEType: "text/markdown"},
		{URI: "argus://fingerprint/template", Name: "Argus Fingerprint Template", Description: "Minimal fingerprint YAML snippet.", MIMEType: "text/yaml"},
		{URI: "argus://poc/spec", Name: "Argus POC Spec", Description: "POC YAML format and debug/save boundaries.", MIMEType: "text/markdown"},
		{URI: "argus://workflow/spec", Name: "Argus Workflow Spec", Description: "Workflow mapping format for product -> POC associations.", MIMEType: "text/markdown"},
		{URI: "argus://workflow/template", Name: "Argus Workflow Template", Description: "Minimal workflow YAML snippet.", MIMEType: "text/yaml"},
		{URI: "argus://examples/fingerprint-poc-workflow", Name: "Argus Fingerprint POC Workflow Example", Description: "Full debug/save/publish/verify example including test_only lifecycle guidance.", MIMEType: "text/markdown"},
		{URI: "argus://pyexp/spec", Name: "Argus Python EXP Spec", Description: "Current Argus Python EXP source format.", MIMEType: "text/markdown"},
		{URI: "argus://pyexp/template", Name: "Argus Python EXP Template", Description: "Minimal Python EXP template.", MIMEType: "text/x-python"},
		{URI: "argus://poc/template", Name: "Argus POC Template", Description: "Minimal POC YAML template.", MIMEType: "text/yaml"},
		{URI: expConsoleURI, Name: "yaksha_exp_console", Title: "Yaksha EXP Console", Description: "Interactive single-file Yaklang EXP inspect, validate, test, debug, and run console.", MIMEType: expConsoleMIMEType, Meta: sdkmcp.Meta(expConsoleMeta)},
	}
}

func tools() []*sdkmcp.Tool {
	return []*sdkmcp.Tool{
		{Name: "argus_context", Description: "Read Argus self-description, exact rule facts, and rule relationship governance views. Use product_search for fuzzy discovery; use action=rule_list/drafts with range_start/range_end to scan artifacts; use action=rule_get before save/publish; use action=relationship_stats for full fingerprint/workflow/POC coverage counts; use action=relationship_list with view=unlinked_fingerprints, workflow_without_fingerprint, missing_poc_refs, general_poc_workflows, linked_fingerprints, or workflow_links for pageable governance candidates. Workflow names with the reserved General-Poc-* prefix are general POC groups, not fingerprint product aliases.", InputSchema: objectSchema(map[string]interface{}{"action": enumSchema([]string{"resources", "quickstart", "lifecycle_policy", "resource", "agents", "agent_pyenv", "workflow_links", "workflow_recommend", "workflow_conflicts", "rule_get", "rule_list", "drafts", "relationship_stats", "relationship_list"}), "uri": stringSchema("Resource URI for action=resource"), "agent_id": stringSchema("Agent ID"), "rule_type": enumSchema([]string{"fingerprint", "poc", "workflow", "pyexp"}), "file_name": stringSchema("Exact artifact file name for rule_get or list filtering"), "artifact_id": stringSchema("Exact artifact id for rule_get"), "rule_id": stringSchema("Stable rule id/name for rule_get, especially Python EXP ARGUS_EXP.id"), "state": enumSchema([]string{"Draft", "Approved", "Deprecated"}), "query": stringSchema("Exact list filter across file name, artifact id, state, catalog summary, content preview, or relationship item text; product_search remains fuzzy"), "view": enumSchema([]string{"linked_fingerprints", "unlinked_fingerprints", "workflow_without_fingerprint", "missing_poc_refs", "general_poc_workflows", "workflow_links"}), "range_start": map[string]interface{}{"type": "integer", "description": "1-based inclusive first row for rule_list/drafts/relationship_list, for example 1 then 101"}, "range_end": map[string]interface{}{"type": "integer", "description": "1-based inclusive last row for rule_list/drafts/relationship_list, max window width 200"}, "product_name": stringSchema("Fingerprint/workflow product filter or product entry for rule_get; General-Poc-* means a general POC workflow, not a real fingerprint product"), "poc_name": stringSchema("POC name filter"), "limit": map[string]interface{}{"type": "integer", "description": "Sample size for relationship_stats or legacy workflow views"}}, []string{"action"})},
		{Name: "argus_product_search", Description: "Read-only fuzzy product search across fingerprint, workflow, POC and Python EXP indexes. Use it before governance or merge work to find related product names, linked POCs, workflows, EXPs, and evidence. It never saves, deletes, or publishes.", InputSchema: objectSchema(map[string]interface{}{"query": stringSchema("Product, alias, POC name, CVE, tag, EXP id, or keyword to search"), "limit": map[string]interface{}{"type": "integer", "description": "Maximum product groups to return, capped at 100"}}, []string{"query"})},
		{Name: "argus_rule_debug", Description: "Debug a fingerprint, POC, or Python EXP through Argus Server before saving. Fingerprint/POC require agent_id and target_url. For pyexp source-level dry-run use rule_type=pyexp, source, target_url, action=dry_run; it does not require Agent and never saves. For pyexp source-level debug use source + action=run + agent_id + target_url. Saved pyexp cleanup/install should use stable_ref fields from argus_rule_save. For workflow injection, workflow_product may be a real fingerprint product or a reserved General-Poc-* general POC group.", InputSchema: objectSchema(map[string]interface{}{"rule_type": enumSchema([]string{"fingerprint", "poc", "pyexp"}), "agent_id": stringSchema("Agent ID; required for live debug, not required for pyexp action=dry_run"), "target_url": stringSchema("Target URL"), "source": stringSchema("Python EXP source for source-level dry-run/debug before saving"), "proxy": stringSchema("Proxy"), "timeout_sec": map[string]interface{}{"type": "integer"}, "product_name": stringSchema("Fingerprint product name"), "rule": stringSchema("Fingerprint rule expression"), "include_dir": map[string]interface{}{"type": "boolean"}, "include_poc": map[string]interface{}{"type": "boolean"}, "workflow_product": stringSchema("Workflow product for injected debug mapping; General-Poc-* means a general POC workflow, not a real fingerprint product"), "workflow_types": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "workflow_pocs": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "poc_content": stringSchema("POC YAML source"), "artifact_id": stringSchema("Stable DB artifact id from argus_rule_save"), "rule_id": stringSchema("Stable EXP rule id from ARGUS_EXP.id"), "file_name": stringSchema("Artifact display file name"), "params": map[string]interface{}{"type": "object"}, "action": stringSchema("pyexp action: dry_run, run or cleanup")}, []string{"rule_type", "target_url"})},
		{Name: "argus_rule_save", Description: "Save fingerprint, POC, Workflow, or Python EXP source into the Argus database as a Draft artifact and return stable_ref {artifact_id, rule_id, file_name, hash, version}. Optional intent=test_only|production_candidate|approved_reusable only affects guidance; it never auto-deletes or auto-publishes. Workflow product_name may use the reserved General-Poc-* prefix for general POC groups whose YAML performs its own matching.", InputSchema: objectSchema(map[string]interface{}{"rule_type": enumSchema([]string{"fingerprint", "poc", "workflow", "pyexp"}), "intent": enumSchema([]string{"test_only", "production_candidate", "approved_reusable"}), "file_name": stringSchema("Draft artifact display file name"), "content": stringSchema("Rule source content"), "product_name": stringSchema("Fingerprint product or Workflow product; General-Poc-* means a general POC workflow and should not be merged into a real product alias"), "rules": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "workflow_types": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "workflow_pocs": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, []string{"rule_type"})},
		{Name: "argus_rule_apply", Description: "Admin-only controlled action. action=publish activates a Draft artifact and should use stable_ref fields from argus_rule_save; action=install_requirements only supports saved pyexp rules and also uses stable_ref fields.", InputSchema: objectSchema(map[string]interface{}{"action": enumSchema([]string{"publish", "install_requirements"}), "rule_type": enumSchema([]string{"fingerprint", "poc", "workflow", "pyexp"}), "artifact_id": stringSchema("Stable DB artifact id from argus_rule_save"), "rule_id": stringSchema("Stable EXP rule id from ARGUS_EXP.id"), "file_name": stringSchema("Draft artifact display file name"), "hash": stringSchema("Expected draft hash"), "version": map[string]interface{}{"type": "integer"}, "agent_id": stringSchema("Agent ID for install_requirements")}, []string{"action", "rule_type"})},
		{Name: "argus_yaksha_exp", Title: "Yaksha EXP Runtime", Description: "Operate one sealed single-file Yaklang EXP through the persistent independent Yaksha runtime. inspect derives the official cli.* UI plus literal yaksha.call/yaksha.asset references; validate checks source, params, dependencies, assets, exact network targets, and egress shape; test is fixture-only and always offline; debug returns complete unredacted HTTP/TCP Trace; run executes once. exp_id + revision + source_sha256 bind an immutable source identity; dependencies are pinned child revisions, assets are hash-bound content, and egress explicitly selects disabled, direct, or a per-call write-only SOCKS5 route. Agent-native egress is a future trusted relay integration and is not exposed by this MCP tool. This tool does not persist or publish revisions, access Argus Server, or expose any filesystem path.", Meta: sdkmcp.Meta{"ui": map[string]interface{}{"resourceUri": expConsoleURI, "visibility": []string{"model", "app"}}}, InputSchema: yakshaInputSchema(), OutputSchema: map[string]interface{}{"type": "object"}},
	}
}

func objectSchema(properties map[string]interface{}, required []string) map[string]interface{} {
	schema := map[string]interface{}{"type": "object", "properties": properties}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func stringSchema(description string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "description": description}
}

func enumSchema(values []string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "enum": values}
}

func yakshaInputSchema() map[string]interface{} {
	schema := objectSchema(map[string]interface{}{
		"action": enumSchema([]string{"inspect", "validate", "test", "debug", "run"}),
		"script": map[string]interface{}{
			"type":        "string",
			"description": "Complete main.yak source; this is the only authoritative source for this call",
			"minLength":   1,
			"maxLength":   1 << 20,
		},
		"params": map[string]interface{}{
			"type":        "object",
			"description": "Values for declared cli.* parameters",
		},
		"timeout_ms": map[string]interface{}{
			"type":    "integer",
			"minimum": 0,
			"maximum": 120000,
		},
		"test_cases": map[string]interface{}{
			"type":        "array",
			"description": "Fixture-backed Yaksha test cases; required only for action=test",
			"items":       map[string]interface{}{"type": "object"},
			"maxItems":    32,
		},
		"exp_id": map[string]interface{}{
			"type":        "string",
			"description": "Optional logical EXP id; requires revision and source_sha256",
			"minLength":   1,
			"maxLength":   128,
		},
		"revision": map[string]interface{}{
			"type":        "integer",
			"description": "Optional immutable EXP revision; requires exp_id and source_sha256",
			"minimum":     1,
		},
		"source_sha256": map[string]interface{}{
			"type":        "string",
			"description": "Expected lowercase SHA-256 of script for revision binding",
			"pattern":     "^[0-9a-f]{64}$",
		},
		"dependencies": map[string]interface{}{
			"type":        "array",
			"description": "Flattened transitive closure of literal yaksha.call references, pinned to exact revisions and source hashes",
			"maxItems":    16,
			"items": objectSchema(map[string]interface{}{
				"exp_id":        stringSchema("Referenced EXP id"),
				"revision":      map[string]interface{}{"type": "integer", "minimum": 1},
				"source_sha256": map[string]interface{}{"type": "string", "pattern": "^[0-9a-f]{64}$"},
				"script":        map[string]interface{}{"type": "string", "minLength": 1, "maxLength": 1 << 20},
			}, []string{"exp_id", "revision", "source_sha256", "script"}),
		},
		"assets": map[string]interface{}{
			"type":        "array",
			"description": "Hash-bound logical assets referenced by yaksha.asset",
			"maxItems":    32,
			"items": objectSchema(map[string]interface{}{
				"asset_id": stringSchema("Logical asset id"),
				"sha256":   map[string]interface{}{"type": "string", "pattern": "^[0-9a-f]{64}$"},
				"encoding": enumSchema([]string{"utf8", "base64"}),
				"content":  map[string]interface{}{"type": "string", "maxLength": 2 << 20},
			}, []string{"asset_id", "sha256", "encoding", "content"}),
		},
		"network_targets": map[string]interface{}{
			"type":        "array",
			"description": "Exact authorized http://host:port, https://host:port, or tcp://host:port origins",
			"maxItems":    32,
			"items":       map[string]interface{}{"type": "string"},
		},
		"egress": objectSchema(map[string]interface{}{
			"mode": map[string]interface{}{
				"type":        "string",
				"description": "Per-call outbound mode; omitted egress defaults to disabled",
				"enum":        []string{"disabled", "direct", "socks5"},
			},
			"socks5_proxy": map[string]interface{}{
				"type":        "string",
				"description": "Write-only per-call socks5://[user:password@]host:port route; valid only when mode=socks5",
				"maxLength":   2048,
				"writeOnly":   true,
			},
		}, []string{"mode"}),
	}, []string{"action", "script"})
	for _, name := range []string{"dependencies", "assets", "egress"} {
		if value, ok := schema["properties"].(map[string]interface{})[name].(map[string]interface{}); ok {
			if items, ok := value["items"].(map[string]interface{}); ok {
				items["additionalProperties"] = false
			}
			if name == "egress" {
				value["additionalProperties"] = false
			}
		}
	}
	schema["additionalProperties"] = false
	return schema
}
