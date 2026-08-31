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
	"argus://dir/spec":                          "/api/v1/mcp/resources/dir/spec",
	"argus://dir/template":                      "/api/v1/mcp/resources/dir/template",
	"argus://behavior-probe/spec":               "/api/v1/mcp/resources/behavior-probe/spec",
	"argus://behavior-probe/template":           "/api/v1/mcp/resources/behavior-probe/template",
	"argus://poc/spec":                          "/api/v1/mcp/resources/poc/spec",
	"argus://poc/template":                      "/api/v1/mcp/resources/poc/template",
	"argus://workflow/spec":                     "/api/v1/mcp/resources/workflow/spec",
	"argus://workflow/template":                 "/api/v1/mcp/resources/workflow/template",
	"argus://examples/fingerprint-poc-workflow": "/api/v1/mcp/resources/examples/fingerprint-poc-workflow",
}

func NewServer(client *Client) *sdkmcp.Server {
	server := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "argus-mcp", Version: "0.1.0"}, &sdkmcp.ServerOptions{
		Instructions: sourceLessMCPInstructions,
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
			if pending, err := maybeElicit(client, tool.Name, req, args); pending != nil || err != nil {
				return pending, err
			}
			result, err := client.CallTool(ctx, tool.Name, args)
			if err != nil {
				if isStructuredContentTool(tool.Name) {
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
			if isStructuredContentTool(tool.Name) {
				response.StructuredContent = result
			}
			return response, nil
		})
	}
}

func resources() []*sdkmcp.Resource {
	return []*sdkmcp.Resource{
		{URI: "argus://argus-mcp/quickstart", Name: "Argus MCP Quickstart", Description: "Start here when the client has no Argus source code.", MIMEType: "text/markdown"},
		{URI: "argus://argus-mcp/tool-guide", Name: "Argus MCP Tool Guide", Description: "How to use the rule authoring MCP tools and their required field combinations.", MIMEType: "text/markdown"},
		{URI: "argus://fingerprint/spec", Name: "Argus Fingerprint Spec", Description: "Fingerprint YAML format and rule expression examples.", MIMEType: "text/markdown"},
		{URI: "argus://fingerprint/template", Name: "Argus Fingerprint Template", Description: "Minimal fingerprint YAML snippet.", MIMEType: "text/yaml"},
		{URI: "argus://dir/spec", Name: "Argus Dir Probe Spec", Description: "Dir dictionary format mapping products to URL paths.", MIMEType: "text/markdown"},
		{URI: "argus://dir/template", Name: "Argus Dir Probe Template", Description: "Minimal dir YAML snippet.", MIMEType: "text/yaml"},
		{URI: "argus://behavior-probe/spec", Name: "Argus Behavior Probe Spec", Description: "Nuclei HTTP/HTTPS behavior probe contract and safety classification.", MIMEType: "text/markdown"},
		{URI: "argus://behavior-probe/template", Name: "Argus Behavior Probe Template", Description: "Minimal single-file Nuclei active fingerprint.", MIMEType: "text/yaml"},
		{URI: "argus://poc/spec", Name: "Argus POC Spec", Description: "POC YAML format and debug/save boundaries.", MIMEType: "text/markdown"},
		{URI: "argus://workflow/spec", Name: "Argus Workflow Spec", Description: "Workflow mapping format for product -> POC associations.", MIMEType: "text/markdown"},
		{URI: "argus://workflow/template", Name: "Argus Workflow Template", Description: "Minimal workflow YAML snippet.", MIMEType: "text/yaml"},
		{URI: "argus://examples/fingerprint-poc-workflow", Name: "Argus Fingerprint POC Workflow Example", Description: "Full debug/save/publish/verify example including test_only lifecycle guidance.", MIMEType: "text/markdown"},
		{URI: "argus://poc/template", Name: "Argus POC Template", Description: "Minimal POC YAML template.", MIMEType: "text/yaml"},
		{URI: expConsoleURI, Name: "yaksha_exp_studio", Title: "Yaksha EXP Studio", Description: "Interactive Server-authoritative Yaklang EXP Studio for revisions, fixtures, execution and audit.", MIMEType: expConsoleMIMEType, Meta: sdkmcp.Meta(expConsoleMeta)},
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
			"description": "Complete transient main.yak source for inspect, validate, or offline Fixture test only; debug/run require a saved Server Revision",
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
		"risk_confirmed": map[string]interface{}{
			"type":        "boolean",
			"description": "Server governance flag for high/critical saved EXP debug or run when no active risk waiver exists. Hosts with elicitation ignore this argument and confirm via the operator prompt; other clients must set true.",
		},
		"test_cases": map[string]interface{}{
			"type":        "array",
			"description": "Fixture-backed Yaksha test cases; required only for action=test",
			"items": objectSchema(map[string]interface{}{
				"id":     stringSchema("Unique test case id"),
				"params": map[string]interface{}{"type": "object"},
				"fixture": objectSchema(map[string]interface{}{
					"http": map[string]interface{}{"type": "array", "items": objectSchema(map[string]interface{}{
						"method": stringSchema("Exact HTTP method"), "url": stringSchema("Exact fixture URL"),
						"status_code":      map[string]interface{}{"type": "integer", "minimum": 100, "maximum": 599},
						"request_headers":  map[string]interface{}{"type": "object", "additionalProperties": fixtureMatcherSchema()},
						"request_body":     fixtureMatcherSchema(),
						"response_headers": map[string]interface{}{"type": "object", "additionalProperties": map[string]interface{}{"type": "string"}},
						"body":             map[string]interface{}{"type": "string"}, "body_encoding": enumSchema([]string{"utf8", "base64"}), "fail": map[string]interface{}{"type": "boolean"},
					}, []string{"method", "url"})},
					"tcp": map[string]interface{}{"type": "array", "items": objectSchema(map[string]interface{}{
						"address": stringSchema("Exact host:port fixture address"), "success": map[string]interface{}{"type": "boolean"},
						"remote_address": map[string]interface{}{"type": "string"},
						"steps":          map[string]interface{}{"type": "array", "maxItems": 16, "items": objectSchema(map[string]interface{}{"operation": enumSchema([]string{"write", "read", "half_close"}), "data": fixtureMatcherSchema(), "response": map[string]interface{}{"type": "string"}, "encoding": enumSchema([]string{"utf8", "base64"})}, []string{"operation"})},
					}, []string{"address", "success"})},
				}, nil),
				"expect": objectSchema(map[string]interface{}{
					"status": enumSchema([]string{"Succeeded", "Failed", "Timeout", "Canceled"}), "result": map[string]interface{}{},
					"evidence": map[string]interface{}{"type": "object"}, "logs_contain": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
					"error_contains": map[string]interface{}{"type": "string"},
				}, nil),
			}, []string{"id", "expect"}),
			"maxItems": 32,
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
				"enum":        []string{"disabled", "direct", "socks5", "agent"},
			},
			"socks5_proxy": map[string]interface{}{
				"type":        "string",
				"description": "Write-only per-call socks5://[user:password@]host:port route; valid only when mode=socks5",
				"maxLength":   2048,
				"writeOnly":   true,
			},
			"agent_id":       stringSchema("Explicit Agent id for mode=agent"),
			"risk_confirmed": map[string]interface{}{"type": "boolean", "description": "Server governance flag for mode=agent. Hosts with elicitation set this after operator accept; other clients must set true."},
		}, []string{"mode"}),
	}, []string{"action"})
	schema["anyOf"] = []interface{}{
		map[string]interface{}{"required": []string{"script"}, "not": map[string]interface{}{"anyOf": []interface{}{map[string]interface{}{"required": []string{"exp_id"}}, map[string]interface{}{"required": []string{"revision"}}}}},
		map[string]interface{}{"required": []string{"exp_id", "revision", "source_sha256"}, "not": map[string]interface{}{"required": []string{"script"}}},
	}
	schema["allOf"] = []interface{}{
		map[string]interface{}{
			"if": map[string]interface{}{
				"properties": map[string]interface{}{"action": map[string]interface{}{"enum": []string{"debug", "run"}}},
				"required":   []string{"action"},
			},
			"then": map[string]interface{}{
				"required": []string{"exp_id", "revision", "source_sha256"},
				"not":      map[string]interface{}{"required": []string{"script"}},
			},
		},
	}
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

func fixtureMatcherSchema() map[string]interface{} {
	return map[string]interface{}{"type": "object", "properties": map[string]interface{}{"exact": map[string]interface{}{"type": "string"}, "contains": map[string]interface{}{"type": "string"}, "regex": map[string]interface{}{"type": "string"}}, "additionalProperties": false, "minProperties": 1, "maxProperties": 1}
}

func expWorkspaceInputSchema() map[string]interface{} {
	actions := []string{
		"exp_list", "exp_create", "exp_get", "exp_update", "exp_deprecate",
		"audit_list", "risk_waiver_get", "risk_waiver_upsert", "risk_waiver_delete",
		"draft_inspect", "draft_validate", "draft_test",
		"revision_list", "revision_create", "revision_get", "revision_inspect", "revision_validate", "revision_publish", "revision_set_active", "revision_sealed",
		"asset_list", "asset_create", "asset_get", "asset_delete",
		"test_case_list", "test_case_create", "test_case_update", "test_case_delete",
		"run_list", "run_get", "run_cancel",
	}
	schema := objectSchema(map[string]interface{}{
		"action":        enumSchema(actions),
		"exp_id":        stringSchema("Tenant-scoped EXP UUID"),
		"name":          stringSchema("EXP or Fixture test case name"),
		"description":   stringSchema("EXP description"),
		"risk_level":    enumSchema([]string{"low", "medium", "high", "critical"}),
		"revision":      map[string]interface{}{"type": "integer", "minimum": 1},
		"source":        map[string]interface{}{"type": "string", "minLength": 1, "maxLength": 1 << 20},
		"source_sha256": map[string]interface{}{"type": "string", "pattern": "^[0-9a-f]{64}$"},
		"dependencies":  map[string]interface{}{"type": "array", "maxItems": 16, "items": objectSchema(map[string]interface{}{"exp_id": stringSchema("Pinned child EXP id"), "revision": map[string]interface{}{"type": "integer", "minimum": 1}, "source_sha256": map[string]interface{}{"type": "string", "pattern": "^[0-9a-f]{64}$"}}, []string{"exp_id", "revision", "source_sha256"})},
		"assets":        map[string]interface{}{"type": "array", "maxItems": 32, "items": objectSchema(map[string]interface{}{"asset_id": stringSchema("Logical Asset id"), "version": map[string]interface{}{"type": "integer", "minimum": 1}, "sha256": map[string]interface{}{"type": "string", "pattern": "^[0-9a-f]{64}$"}}, []string{"asset_id", "version", "sha256"})},
		"test_cases": map[string]interface{}{
			"type": "array", "maxItems": 128,
			"items": objectSchema(map[string]interface{}{
				"name": stringSchema("Fixture test case name"), "params": map[string]interface{}{"type": "object"},
				"fixture": map[string]interface{}{"type": "object"}, "expect": map[string]interface{}{"type": "object"}, "enabled": map[string]interface{}{"type": "boolean"},
			}, []string{"name", "params", "fixture", "expect"}),
		},
		"test_receipt":  map[string]interface{}{"type": "string", "minLength": 1, "maxLength": 256, "writeOnly": true, "description": "Short-lived receipt from draft_test; never display or log"},
		"asset_id":      stringSchema("Logical Asset id"),
		"asset_version": map[string]interface{}{"type": "integer", "minimum": 1},
		"media_type":    stringSchema("Asset media type"),
		"encoding":      enumSchema([]string{"utf8", "base64"}),
		"content":       map[string]interface{}{"type": "string", "maxLength": 2 << 20},
		"reason":        stringSchema("Administrative risk waiver reason"),
		"expires_at":    map[string]interface{}{"type": "string", "format": "date-time"},
		"case_id":       stringSchema("Fixture test case UUID"),
		"params":        map[string]interface{}{"type": "object"},
		"fixture":       map[string]interface{}{"type": "object"},
		"expect":        map[string]interface{}{"type": "object"},
		"enabled":       map[string]interface{}{"type": "boolean"},
		"include_tests": map[string]interface{}{"type": "boolean"},
		"run_id":        stringSchema("EXP run UUID"),
		"page":          map[string]interface{}{"type": "integer", "minimum": 1},
		"page_size":     map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 200},
	}, []string{"action"})
	schema["additionalProperties"] = false
	return schema
}
