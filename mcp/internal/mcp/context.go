package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

func (c *Client) argusContext(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	switch stringArg(args, "action") {
	case "resources":
		items := make([]map[string]interface{}, 0, len(resourceEndpoints))
		for _, resource := range resources() {
			items = append(items, map[string]interface{}{
				"uri":         resource.URI,
				"name":        resource.Name,
				"mime_type":   resource.MIMEType,
				"description": resource.Description,
			})
		}
		return map[string]interface{}{
			"status":                 "success",
			"resources":              items,
			"recommended_read_order": []string{"argus://argus-mcp/quickstart", "argus://argus-mcp/tool-guide", "argus://fingerprint/spec", "argus://poc/spec", "argus://workflow/spec", "argus://pyexp/spec"},
		}, nil
	case "quickstart":
		return c.Resource(ctx, "argus://argus-mcp/quickstart")
	case "lifecycle_policy":
		return c.postTool(ctx, "/api/v1/mcp/tools/rule/context", args)
	case "resource":
		uri := stringArg(args, "uri")
		if uri == "" {
			return nil, fmt.Errorf("uri is required for action=resource")
		}
		return c.Resource(ctx, uri)
	case "agents":
		var out interface{}
		err := c.do(ctx, http.MethodGet, "/api/v1/nodes", nil, &out)
		return out, err
	case "agent_pyenv":
		agentID := stringArg(args, "agent_id")
		if agentID == "" {
			return nil, fmt.Errorf("agent_id is required for action=agent_pyenv")
		}
		var out interface{}
		err := c.do(ctx, http.MethodGet, "/api/v1/agents/"+url.PathEscape(agentID)+"/pyenv", nil, &out)
		return out, err
	case "rule_get":
		return c.argusRuleGet(ctx, args)
	case "rule_list":
		return c.argusRuleList(ctx, args, false)
	case "drafts":
		return c.argusRuleList(ctx, args, true)
	case "relationship_stats":
		return c.argusRelationshipStats(ctx, args)
	case "relationship_list":
		return c.argusRelationshipList(ctx, args)
	case "workflow_links", "workflow_recommend", "workflow_conflicts":
		return c.argusWorkflowContext(ctx, args)
	default:
		return nil, fmt.Errorf("unsupported argus_context action %q", stringArg(args, "action"))
	}
}
