package mcp

import (
	"context"
	"fmt"
	"net/http"
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
		return c.yaksha.call(ctx, args)
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}
