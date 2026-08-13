package mcp

import (
	"context"
	"fmt"
)

func (c *Client) argusRuleDebug(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	switch normalizeRuleType(stringArg(args, "rule_type")) {
	case "finger", "poc":
		return c.postTool(ctx, "/api/v1/mcp/tools/rule/debug", args)
	default:
		return nil, fmt.Errorf("argus_rule_debug only supports fingerprint or poc; use argus_yaksha_exp for EXP")
	}
}
