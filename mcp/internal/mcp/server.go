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
				return nil, err
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return &sdkmcp.CallToolResult{
				Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: string(data)}},
			}, nil
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
	}
}

func tools() []*sdkmcp.Tool {
	return []*sdkmcp.Tool{
		{Name: "argus_context", Description: "Read Argus self-description and exact rule facts. Use product_search for fuzzy discovery; use action=rule_list/drafts with range_start/range_end to scan candidates without repeating previous windows; use action=rule_get before save/publish to read exact content, hash, version and state.", InputSchema: objectSchema(map[string]interface{}{"action": enumSchema([]string{"resources", "quickstart", "lifecycle_policy", "resource", "agents", "agent_pyenv", "workflow_links", "workflow_recommend", "workflow_conflicts", "rule_get", "rule_list", "drafts"}), "uri": stringSchema("Resource URI for action=resource"), "agent_id": stringSchema("Agent ID"), "rule_type": enumSchema([]string{"fingerprint", "poc", "workflow", "pyexp"}), "file_name": stringSchema("Exact artifact file name for rule_get or list filtering"), "artifact_id": stringSchema("Exact artifact id for rule_get"), "rule_id": stringSchema("Stable rule id/name for rule_get, especially Python EXP ARGUS_EXP.id"), "state": enumSchema([]string{"Draft", "Approved", "Deprecated"}), "query": stringSchema("Exact list filter across file name, artifact id, state, catalog summary and content preview; product_search remains fuzzy"), "range_start": map[string]interface{}{"type": "integer", "description": "1-based inclusive first row for rule_list/drafts, for example 1 then 101"}, "range_end": map[string]interface{}{"type": "integer", "description": "1-based inclusive last row for rule_list/drafts, max window width 200"}, "product_name": stringSchema("Fingerprint/workflow product filter or product entry for rule_get"), "poc_name": stringSchema("POC name filter"), "limit": map[string]interface{}{"type": "integer"}}, []string{"action"})},
		{Name: "argus_product_search", Description: "Read-only fuzzy product search across fingerprint, workflow, POC and Python EXP indexes. Use it before governance or merge work to find related product names, linked POCs, workflows, EXPs, and evidence. It never saves, deletes, or publishes.", InputSchema: objectSchema(map[string]interface{}{"query": stringSchema("Product, alias, POC name, CVE, tag, EXP id, or keyword to search"), "limit": map[string]interface{}{"type": "integer", "description": "Maximum product groups to return, capped at 100"}}, []string{"query"})},
		{Name: "argus_rule_debug", Description: "Debug a fingerprint, POC, or Python EXP through Argus Server before saving. Fingerprint/POC require agent_id and target_url. For pyexp source-level dry-run use rule_type=pyexp, source, target_url, action=dry_run; it does not require Agent and never saves. For pyexp source-level debug use source + action=run + agent_id + target_url. Saved pyexp cleanup/install should use stable_ref fields from argus_rule_save.", InputSchema: objectSchema(map[string]interface{}{"rule_type": enumSchema([]string{"fingerprint", "poc", "pyexp"}), "agent_id": stringSchema("Agent ID; required for live debug, not required for pyexp action=dry_run"), "target_url": stringSchema("Target URL"), "source": stringSchema("Python EXP source for source-level dry-run/debug before saving"), "proxy": stringSchema("Proxy"), "timeout_sec": map[string]interface{}{"type": "integer"}, "product_name": stringSchema("Fingerprint product name"), "rule": stringSchema("Fingerprint rule expression"), "include_dir": map[string]interface{}{"type": "boolean"}, "include_poc": map[string]interface{}{"type": "boolean"}, "workflow_product": stringSchema("Workflow product for injected debug mapping"), "workflow_types": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "workflow_pocs": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "poc_content": stringSchema("POC YAML source"), "artifact_id": stringSchema("Stable DB artifact id from argus_rule_save"), "rule_id": stringSchema("Stable EXP rule id from ARGUS_EXP.id"), "file_name": stringSchema("Artifact display file name"), "params": map[string]interface{}{"type": "object"}, "action": stringSchema("pyexp action: dry_run, run or cleanup")}, []string{"rule_type", "target_url"})},
		{Name: "argus_rule_save", Description: "Save fingerprint, POC, Workflow, or Python EXP source into the Argus database as a Draft artifact and return stable_ref {artifact_id, rule_id, file_name, hash, version}. Optional intent=test_only|production_candidate|approved_reusable only affects guidance; it never auto-deletes or auto-publishes.", InputSchema: objectSchema(map[string]interface{}{"rule_type": enumSchema([]string{"fingerprint", "poc", "workflow", "pyexp"}), "intent": enumSchema([]string{"test_only", "production_candidate", "approved_reusable"}), "file_name": stringSchema("Draft artifact display file name"), "content": stringSchema("Rule source content"), "product_name": stringSchema("Fingerprint or Workflow product"), "rules": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "workflow_types": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "workflow_pocs": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}}, []string{"rule_type"})},
		{Name: "argus_rule_apply", Description: "Admin-only controlled action. action=publish activates a Draft artifact and should use stable_ref fields from argus_rule_save; action=install_requirements only supports saved pyexp rules and also uses stable_ref fields.", InputSchema: objectSchema(map[string]interface{}{"action": enumSchema([]string{"publish", "install_requirements"}), "rule_type": enumSchema([]string{"fingerprint", "poc", "workflow", "pyexp"}), "artifact_id": stringSchema("Stable DB artifact id from argus_rule_save"), "rule_id": stringSchema("Stable EXP rule id from ARGUS_EXP.id"), "file_name": stringSchema("Draft artifact display file name"), "hash": stringSchema("Expected draft hash"), "version": map[string]interface{}{"type": "integer"}, "agent_id": stringSchema("Agent ID for install_requirements")}, []string{"action", "rule_type"})},
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
