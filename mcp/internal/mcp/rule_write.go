package mcp

import (
	"context"
	"net/http"
)

func (c *Client) argusRuleSave(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/mcp/tools/rule/save", args, &out); err != nil {
		return nil, err
	}
	return withStableRef(out, normalizeRuleType(stringArg(args, "rule_type")), firstNonEmpty(stringArg(args, "file_name"), mapString(out, "file_name"))), nil
}

func (c *Client) argusRuleApply(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	var out map[string]interface{}
	if err := c.do(ctx, http.MethodPost, "/api/v1/mcp/tools/rule/apply", args, &out); err != nil {
		return nil, err
	}
	return withStableRef(out, normalizeRuleType(stringArg(args, "rule_type")), firstNonEmpty(stringArg(args, "file_name"), mapString(out, "file_name"))), nil
}
