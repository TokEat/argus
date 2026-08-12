package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	transport *httpTransport
	yaksha    *yakshaRunner
}

func NewClient(baseURL, token string) *Client {
	return NewClientWithYakshaURL(baseURL, token, "http://127.0.0.1:8790")
}

func NewClientWithYakshaURL(baseURL, token, yakshaURL string) *Client {
	return &Client{
		transport: newHTTPTransport(baseURL, token),
		yaksha:    newYakshaRunner(yakshaURL),
	}
}

func (c *Client) CheckYaksha(ctx context.Context) error {
	if c == nil || c.yaksha == nil {
		return fmt.Errorf("Yaksha Runtime Unavailable: client is not configured")
	}
	return c.yaksha.ready(ctx)
}

func (c *Client) Resource(ctx context.Context, uri string) (resourcePayload, error) {
	if uri == expConsoleURI {
		return resourcePayload{
			URI:      expConsoleURI,
			MIMEType: expConsoleMIMEType,
			Text:     expConsoleHTML,
			Meta:     expConsoleMeta,
		}, nil
	}
	endpoint, ok := resourceEndpoints[uri]
	if !ok {
		return resourcePayload{}, fmt.Errorf("unknown resource uri %q", uri)
	}
	var payload resourcePayload
	if err := c.do(ctx, http.MethodGet, endpoint, nil, &payload); err != nil {
		return resourcePayload{}, err
	}
	return payload, nil
}

func (c *Client) CallTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	switch name {
	case "argus_context":
		return c.argusContext(ctx, args)
	case "argus_product_search":
		return c.argusProductSearch(ctx, args)
	case "argus_rule_debug":
		return c.argusRuleDebug(ctx, args)
	case "argus_rule_save":
		return c.argusRuleSave(ctx, args)
	case "argus_rule_apply":
		return c.argusRuleApply(ctx, args)
	case "argus_yaksha_exp":
		return c.yakshaExp(ctx, args)
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

type expEgressRouteResponse struct {
	RouteID string `json:"route_id"`
}

func (c *Client) yakshaExp(ctx context.Context, args map[string]interface{}) (map[string]interface{}, error) {
	egressValue, _ := args["egress"].(map[string]interface{})
	if strings.TrimSpace(fmt.Sprint(egressValue["mode"])) != "agent" {
		return c.yaksha.call(ctx, args)
	}
	action := strings.ToLower(strings.TrimSpace(fmt.Sprint(args["action"])))
	if action != "run" && action != "debug" {
		return nil, fmt.Errorf("egress mode agent is only allowed for run and debug")
	}
	agentID := strings.TrimSpace(fmt.Sprint(egressValue["agent_id"]))
	riskConfirmed, _ := egressValue["risk_confirmed"].(bool)
	if agentID == "" || !riskConfirmed {
		return nil, fmt.Errorf("egress mode agent requires agent_id and risk_confirmed=true")
	}
	networkTargets, _ := args["network_targets"].([]interface{})
	routeRequest := map[string]interface{}{"agent_id": agentID, "network_targets": networkTargets, "risk_confirmed": true}
	if timeout, ok := args["timeout_ms"]; ok {
		routeRequest["timeout_ms"] = timeout
	}
	var route expEgressRouteResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/exp-egress-routes", routeRequest, &route); err != nil {
		return nil, fmt.Errorf("create Agent egress route: %w", err)
	}
	if strings.TrimSpace(route.RouteID) == "" {
		return nil, fmt.Errorf("create Agent egress route: Server returned no route_id")
	}
	internalArgs := make(map[string]interface{}, len(args))
	for key, value := range args {
		internalArgs[key] = value
	}
	internalArgs["egress"] = map[string]interface{}{"mode": "relay", "route_id": route.RouteID}
	result, runErr := c.yaksha.callInternal(ctx, internalArgs)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cleanupErr := c.do(cleanupCtx, http.MethodDelete, "/api/v1/exp-egress-routes/"+url.PathEscape(route.RouteID), nil, nil)
	cancel()
	if cleanupErr != nil {
		cleanupErr = errors.New(strings.ReplaceAll(cleanupErr.Error(), route.RouteID, "[route]"))
	}
	if runErr != nil || cleanupErr != nil {
		return nil, errors.Join(wrapAgentEgressError("execute EXP", runErr), wrapAgentEgressError("revoke Agent egress route", cleanupErr))
	}
	return result, nil
}

func wrapAgentEgressError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
