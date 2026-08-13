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
	case "argus_exp_workspace":
		return c.expWorkspace(ctx, args)
	case "argus_scan_task":
		return c.scanTask(ctx, args)
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

type expEgressRouteResponse struct {
	RouteID string `json:"route_id"`
}

func (c *Client) yakshaExp(ctx context.Context, args map[string]interface{}) (map[string]interface{}, error) {
	prepared, saved, err := c.prepareSavedYakshaExp(ctx, args)
	if err != nil {
		return nil, err
	}
	action := strings.ToLower(strings.TrimSpace(rawStringArg(prepared, "action")))
	if (action == "debug" || action == "run") && !saved {
		return nil, fmt.Errorf("%s requires a saved Server EXP Revision bound by exp_id, revision, and source_sha256; save the Draft Revision before execution", action)
	}
	if saved && isRecordedYakshaAction(action) {
		return c.executeSavedYakshaExp(ctx, prepared)
	}
	result, err := c.executeYakshaExp(ctx, prepared)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Client) executeSavedYakshaExp(ctx context.Context, args map[string]interface{}) (map[string]interface{}, error) {
	expID := strings.TrimSpace(rawStringArg(args, "exp_id"))
	revision, ok := workspaceInt(args["revision"])
	if expID == "" || !ok || revision < 1 {
		return nil, fmt.Errorf("saved EXP execution requires exp_id and positive revision")
	}
	action := strings.ToLower(strings.TrimSpace(rawStringArg(args, "action")))
	body := map[string]interface{}{
		"action":        action,
		"source_sha256": strings.TrimSpace(rawStringArg(args, "source_sha256")),
	}
	for _, key := range []string{"params", "timeout_ms", "network_targets", "egress", "risk_confirmed"} {
		if value, exists := args[key]; exists {
			body[key] = value
		}
	}
	if action == "test" {
		body["egress"] = map[string]interface{}{"mode": "disabled"}
		delete(body, "network_targets")
	}
	path := fmt.Sprintf("/api/v1/exps/%s/revisions/%d/runs", url.PathEscape(expID), revision)
	var recorded map[string]interface{}
	if err := c.do(ctx, http.MethodPost, path, body, &recorded); err != nil {
		return nil, fmt.Errorf("execute trusted Server EXP Revision: %w", err)
	}
	response, ok := recorded["response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("execute trusted Server EXP Revision: response is missing")
	}
	response["server_run_id"] = strings.TrimSpace(rawStringArg(recorded, "run_id"))
	return response, nil
}

func (c *Client) executeYakshaExp(ctx context.Context, args map[string]interface{}) (map[string]interface{}, error) {
	runtimeArgs := make(map[string]interface{}, len(args))
	for key, value := range args {
		runtimeArgs[key] = value
	}
	// risk_confirmed is a Server governance assertion, not part of the Yaksha
	// execution protocol and must not enter script-visible Runtime input.
	delete(runtimeArgs, "risk_confirmed")
	egressValue, _ := args["egress"].(map[string]interface{})
	if strings.TrimSpace(rawStringArg(egressValue, "mode")) != "agent" {
		return c.yaksha.call(ctx, runtimeArgs)
	}
	action := strings.ToLower(strings.TrimSpace(rawStringArg(args, "action")))
	if action != "run" && action != "debug" {
		return nil, fmt.Errorf("egress mode agent is only allowed for run and debug")
	}
	agentID := strings.TrimSpace(rawStringArg(egressValue, "agent_id"))
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
	internalArgs := make(map[string]interface{}, len(runtimeArgs))
	for key, value := range runtimeArgs {
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

func (c *Client) prepareSavedYakshaExp(ctx context.Context, args map[string]interface{}) (map[string]interface{}, bool, error) {
	expID := strings.TrimSpace(rawStringArg(args, "exp_id"))
	revision, ok := workspaceInt(args["revision"])
	expectedHash := strings.TrimSpace(rawStringArg(args, "source_sha256"))
	hasScript := strings.TrimSpace(rawStringArg(args, "script")) != ""
	if expID != "" || ok || expectedHash != "" {
		if expID == "" || !ok || revision < 1 || expectedHash == "" {
			return nil, false, fmt.Errorf("saved EXP execution requires exp_id, positive revision, and source_sha256 together")
		}
		if hasScript {
			return nil, false, fmt.Errorf("script cannot be combined with saved exp_id and revision")
		}
	}
	if hasScript {
		return args, false, nil
	}
	if expID == "" || !ok || revision < 1 {
		return args, false, nil
	}
	action := strings.ToLower(strings.TrimSpace(rawStringArg(args, "action")))
	path := fmt.Sprintf("/api/v1/exps/%s/revisions/%d/sealed-package", url.PathEscape(expID), revision)
	if action == "test" {
		path += "?include_tests=true"
	}
	var sealed map[string]interface{}
	if err := c.do(ctx, http.MethodGet, path, nil, &sealed); err != nil {
		return nil, false, fmt.Errorf("load sealed EXP revision: %w", err)
	}
	sealedHash := strings.TrimSpace(rawStringArg(sealed, "source_sha256"))
	if expectedHash != sealedHash {
		return nil, false, fmt.Errorf("saved EXP source_sha256 confirmation does not match Server revision")
	}
	if strings.EqualFold(strings.TrimSpace(rawStringArg(sealed, "exp_status")), "deprecated") {
		return nil, false, fmt.Errorf("deprecated EXP cannot be executed")
	}
	if deprecated := strings.TrimSpace(rawStringArg(sealed, "deprecated_dependency")); deprecated != "" {
		return nil, false, fmt.Errorf("deprecated dependency EXP %s cannot be executed", deprecated)
	}
	requiresConfirmation, _ := sealed["requires_risk_confirmation"].(bool)
	if (action == "debug" || action == "run") && requiresConfirmation {
		confirmed, _ := args["risk_confirmed"].(bool)
		egress, _ := args["egress"].(map[string]interface{})
		if nested, _ := egress["risk_confirmed"].(bool); nested {
			confirmed = true
		}
		if !confirmed {
			return nil, false, fmt.Errorf("high-risk EXP execution requires risk_confirmed=true or a Server risk waiver")
		}
	}
	prepared := make(map[string]interface{}, len(args)+5)
	for key, value := range args {
		prepared[key] = value
	}
	prepared["exp_id"], prepared["revision"], prepared["source_sha256"] = expID, revision, sealedHash
	prepared["script"] = sealed["script"]
	prepared["dependencies"] = sealed["dependencies"]
	prepared["assets"] = sealed["assets"]
	if action == "test" {
		prepared["test_cases"] = sealed["test_cases"]
	}
	return prepared, true, nil
}

func isRecordedYakshaAction(action string) bool {
	return action == "test" || action == "debug" || action == "run"
}

func wrapAgentEgressError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
