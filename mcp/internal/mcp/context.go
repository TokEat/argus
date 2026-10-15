package mcp

import (
	"context"
	"fmt"
)

func (c *Client) argusContext(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	switch stringArg(args, "action") {
	case "help", "resources", "resource", "quickstart", "lifecycle_policy", "agents", "coverage":
		return c.postTool(ctx, "/api/v1/mcp/tools/rule/context", args)
	case "rule_get":
		return c.argusRuleGet(ctx, args)
	case "rule_list":
		return c.argusRuleList(ctx, args, false)
	case "drafts":
		return c.argusRuleList(ctx, args, true)
	default:
		return nil, fmt.Errorf("unsupported context action %q; call argus_help first if you have no Argus source", stringArg(args, "action"))
	}
}
