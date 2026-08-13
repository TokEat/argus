package mcp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// scanTask keeps MCP on the same Server-authoritative policy compiler used by
// Web and Copilot. Scanner config, host paths and validation sub-batches are
// deliberately not accepted by this boundary.
func (c *Client) scanTask(ctx context.Context, args map[string]interface{}) (map[string]interface{}, error) {
	action := strings.ToLower(strings.TrimSpace(rawStringArg(args, "action")))
	if action != "preview" && action != "create" {
		return nil, fmt.Errorf("argus_scan_task action must be preview or create")
	}
	body := make(map[string]interface{}, len(args))
	for key, value := range args {
		if key != "action" && key != "idempotency_key" {
			body[key] = value
		}
	}
	path := "/api/v1/tasks/plan-preview"
	headers := map[string]string(nil)
	if action == "create" {
		if strings.TrimSpace(rawStringArg(args, "plan_hash")) == "" {
			return nil, fmt.Errorf("argus_scan_task create requires the exact plan_hash returned by preview")
		}
		idempotencyKey := strings.TrimSpace(rawStringArg(args, "idempotency_key"))
		if idempotencyKey == "" {
			return nil, fmt.Errorf("argus_scan_task create requires idempotency_key")
		}
		path = "/api/v1/tasks"
		headers = map[string]string{"Idempotency-Key": idempotencyKey}
	}
	var result map[string]interface{}
	if err := c.doWithHeaders(ctx, http.MethodPost, path, body, &result, headers); err != nil {
		return nil, err
	}
	return result, nil
}
