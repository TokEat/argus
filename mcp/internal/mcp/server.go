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

const sourceLessMCPInstructions = "You do not have the Argus source tree. Argus MCP is the only API. First call argus_context with action=help, then action=resource with the spec and template URIs for the rule_type. Sequence: help -> spec/template -> agents -> debug on a user-authorized target -> save Draft -> admin publish with exact stable_ref hash/version -> verify with action=rule_get. rule_get omits YAML by default and returns fingerprint/workflow/dir product names as a compact string array; pass product_name for one mapping, or include_content=true only for small POC/behavior_probe files. POC rule_get does not treat YAML keys as products. Catalog coverage (fingerprint vs workflow POC) is action=coverage; query is a substring and hyphens are literal. Do not guess YAML or invent tools. Nuclei YAML requires info.author. Controlled behavior probes need risk_confirmed=true. EXP: argus_yaksha_exp and argus_exp_workspace. Scans: argus_scan_task preview then create with plan_hash."

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
			result, err := client.CallTool(ctx, tool.Name, args)
			if err != nil {
				if tool.Name == "argus_yaksha_exp" || tool.Name == "argus_exp_workspace" || tool.Name == "argus_scan_task" {
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
			if tool.Name == "argus_yaksha_exp" || tool.Name == "argus_exp_workspace" || tool.Name == "argus_scan_task" {
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

func tools() []*sdkmcp.Tool {
	return []*sdkmcp.Tool{
		{Name: "argus_context", Description: "Read Argus docs and compact rule metadata without a git checkout. Source-less clients must call action=help first, then action=resource for specs/templates. rule_get returns fingerprint/workflow/dir product names as a string array and omits YAML unless include_content=true. POC rule_get returns template_id/template_name, not YAML keys. coverage returns fingerprint vs workflow POC counts and missing product names.", InputSchema: objectSchema(map[string]interface{}{"action": enumSchema([]string{"help", "resources", "resource", "quickstart", "lifecycle_policy", "agents", "coverage", "rule_get", "rule_list", "drafts"}), "uri": stringSchema("Resource URI for action=resource, for example argus://fingerprint/spec"), "rule_type": enumSchema([]string{"fingerprint", "behavior_probe", "poc", "workflow", "dir"}), "file_name": stringSchema("Exact artifact file name"), "artifact_id": stringSchema("Exact artifact id"), "state": enumSchema([]string{"Draft", "Approved", "Deprecated"}), "query": stringSchema("Substring filter over listed fields or coverage product names. Hyphens are literal; query=MCP-Server is not a range. Use integer range_start/range_end for paging."), "range_start": map[string]interface{}{"type": "integer", "description": "1-based inclusive first row; not parsed from query"}, "range_end": map[string]interface{}{"type": "integer", "description": "1-based inclusive last row; rule_list/drafts max window 200"}, "product_name": stringSchema("rule_get: return that one mapping entry instead of the full name list"), "include_content": map[string]interface{}{"type": "boolean", "description": "rule_get: include YAML; refused for files larger than 64KiB"}, "include_names": map[string]interface{}{"type": "boolean", "description": "coverage: include compact product name array; default true"}, "missing": enumSchema([]string{"fingerprint_without_poc", "workflow_without_fingerprint"}), "limit": map[string]interface{}{"type": "integer"}}, []string{"action"})},
		{Name: "argus_rule_debug", Description: "Debug a fingerprint, dir probe, Nuclei behavior probe, POC or workflow through an authorized online Agent. Controlled behavior probes require risk_confirmed=true. Dir paths replace tenant dir.yaml for that call. Concurrent debug is per Agent, not per tenant.", InputSchema: objectSchema(map[string]interface{}{"rule_type": enumSchema([]string{"fingerprint", "behavior_probe", "poc", "workflow", "dir"}), "agent_id": stringSchema("Agent ID"), "target_url": stringSchema("Authorized target URL"), "proxy": stringSchema("Write-only proxy URL"), "timeout_sec": map[string]interface{}{"type": "integer"}, "file_name": stringSchema("Behavior probe YAML file name"), "content": stringSchema("Complete behavior probe or POC YAML"), "risk_confirmed": map[string]interface{}{"type": "boolean"}, "product_name": stringSchema("Fingerprint or dir product"), "rule": stringSchema("Fingerprint expression"), "paths": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Dir probe paths that replace tenant dir.yaml for this debug call"}, "include_dir": map[string]interface{}{"type": "boolean"}, "include_poc": map[string]interface{}{"type": "boolean"}, "workflow_product": stringSchema("Workflow product or General-Poc-* group"), "workflow_types": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "workflow_pocs": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "poc_content": stringSchema("POC YAML source")}, []string{"rule_type", "target_url"})},
		{Name: "argus_rule_save", Description: "Save fingerprint, dir, behavior probe, POC or Workflow source as a Draft and return stable_ref. Product patches do not rewrite the rest of finger.yaml/workflow.yaml/dir.yaml.", InputSchema: objectSchema(map[string]interface{}{"rule_type": enumSchema([]string{"fingerprint", "behavior_probe", "poc", "workflow", "dir"}), "intent": enumSchema([]string{"test_only", "production_candidate", "approved_reusable"}), "file_name": stringSchema("Draft file name"), "content": stringSchema("Complete rule source"), "product_name": stringSchema("Product or General-Poc-* group"), "rules": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "paths": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Dir probe paths"}, "workflow_types": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "workflow_pocs": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "risk_level": enumSchema([]string{"unknown", "info", "low", "medium", "high"})}, []string{"rule_type"})},
		{Name: "argus_rule_apply", Description: "Admin-only publish, deprecate or rollback using exact stable_ref hash/version guards.", InputSchema: objectSchema(map[string]interface{}{"action": enumSchema([]string{"publish", "deprecate", "rollback"}), "rule_type": enumSchema([]string{"fingerprint", "behavior_probe", "poc", "workflow", "dir"}), "artifact_id": stringSchema("Stable DB artifact id from stable_ref"), "file_name": stringSchema("Draft file name"), "hash": stringSchema("Expected artifact hash"), "version": map[string]interface{}{"type": "integer"}}, []string{"action", "rule_type"})},
		{Name: "argus_yaksha_exp", Title: "Yaksha EXP Runtime", Description: "Operate one sealed single-file Yaklang EXP through the persistent independent Yaksha runtime. Transient script is limited to inspect, validate, and offline Fixture test. Network-capable debug/run require a Server-saved Revision bound by exp_id + revision + source_sha256 as an immutable source identity, so tenant authorization, risk confirmation, and run audit cannot be bypassed. inspect derives the official cli.* UI plus literal yaksha.call/yaksha.asset references; validate checks source, params, dependencies, assets, exact network targets, and egress shape; test is fixture-only and always offline; debug returns complete unredacted HTTP/TCP Trace; run executes once. Dependencies are pinned child revisions and assets are hash-bound content. Egress explicitly selects disabled, direct, a per-call write-only SOCKS5 route, or an authorized Agent using agent_id plus risk_confirmed=true. Agent mode creates a single-use Server Route and never exposes route_id or Gateway credentials. This tool does not expose filesystem or object-storage paths.", Meta: sdkmcp.Meta{"ui": map[string]interface{}{"resourceUri": expConsoleURI, "visibility": []string{"model", "app"}}}, InputSchema: yakshaInputSchema(), OutputSchema: map[string]interface{}{"type": "object"}},
		{Name: "argus_exp_workspace", Title: "Yaksha EXP Studio Workspace", Description: "Manage the Server-authoritative Yaksha EXP Studio workspace: EXP metadata, immutable revisions, hash-bound Assets, Fixture acceptance cases, publication, rollback pointers and run history. All operations are tenant-scoped and require EXP authorization; publication/deprecation/rollback remain Admin-only. Source, Asset content and full run artifacts are stored in private MinIO and no object key, credential or host path is exposed.", Meta: sdkmcp.Meta{"ui": map[string]interface{}{"resourceUri": expConsoleURI, "visibility": []string{"model", "app"}}}, InputSchema: expWorkspaceInputSchema(), OutputSchema: map[string]interface{}{"type": "object"}},
		{Name: "argus_scan_task", Title: "Argus Scan Plan", Description: "Preview or create one authorized scan through the Server-authoritative argus.scan-policy/v1 compiler. Always call action=preview first, show its stages, port count, Agent capacity, POC scope and credential budget to the user, then pass the exact returned plan_hash to action=create. POC and credential validation share one explicit authorization confirmation. This tool never accepts Scanner raw config, Agent file paths or an independent manual POC phase.", InputSchema: scanTaskInputSchema(), OutputSchema: map[string]interface{}{"type": "object"}},
	}
}

func scanTaskInputSchema() map[string]interface{} {
	return objectSchema(map[string]interface{}{
		"action":          enumSchema([]string{"preview", "create"}),
		"project_id":      stringSchema("Tenant-scoped project ID"),
		"name":            stringSchema("Optional task name"),
		"targets":         map[string]interface{}{"oneOf": []interface{}{map[string]interface{}{"type": "string"}, map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, "description": "Authorized targets as newline text or a string array"},
		"policy":          map[string]interface{}{"type": "object", "description": "Complete argus.scan-policy/v1 policy; Server normalizes it and verifies dictionary revisions, authorization and Agent capacity"},
		"priority":        map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 2},
		"timeout_sec":     map[string]interface{}{"type": "integer", "minimum": 0},
		"plan_hash":       stringSchema("Exact plan_hash returned by preview; required for create"),
		"idempotency_key": stringSchema("Stable UUID-like key for this create intent; required for create and reused only when retrying the identical request"),
	}, []string{"action", "project_id", "targets", "policy"})
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
			"description": "Explicit per-call confirmation required for high/critical saved EXP debug or run when no active Server risk waiver exists",
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
			"risk_confirmed": map[string]interface{}{"type": "boolean", "description": "Must be true for mode=agent"},
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
