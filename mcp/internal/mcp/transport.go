package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type httpTransport struct {
	baseURL string
	token   string
	client  *http.Client
}

func newHTTPTransport(baseURL, token string) *httpTransport {
	return &httpTransport{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:   strings.TrimSpace(token),
		client:  &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *Client) postTool(ctx context.Context, path string, args map[string]interface{}) (interface{}, error) {
	var out interface{}
	err := c.do(ctx, http.MethodPost, path, args, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	return c.transport.doJSON(ctx, method, path, body, out)
}

func (c *Client) doWithHeaders(ctx context.Context, method, path string, body interface{}, out interface{}, headers map[string]string) error {
	return c.transport.doJSONWithHeaders(ctx, method, path, body, out, headers)
}

func (t *httpTransport) doJSON(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	return t.doJSONWithHeaders(ctx, method, path, body, out, nil)
}

func (t *httpTransport) doJSONWithHeaders(ctx context.Context, method, path string, body interface{}, out interface{}, headers map[string]string) error {
	if t.baseURL == "" {
		return fmt.Errorf("ARGUS_BASE_URL is required")
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	for key, value := range headers {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("argus API %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}
