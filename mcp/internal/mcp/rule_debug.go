package mcp

import (
	"context"
	"fmt"
)

func (c *Client) argusRuleDebug(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ruleType := normalizeRuleType(stringArg(args, "rule_type"))
	if ruleType == "poc" && stringArg(args, "poc_content") == "" && stringArg(args, "content") != "" {
		args = withString(args, "poc_content", stringArg(args, "content"))
	}
	switch ruleType {
	case "finger", "poc", "active_fingerprint", "workflow", "dir":
		return c.postTool(ctx, "/api/v1/mcp/tools/rule/debug", args)
	default:
		return nil, fmt.Errorf("debug only supports fingerprint, behavior_probe, poc, workflow or dir; use argus_yaksha_exp for EXP")
	}
}
