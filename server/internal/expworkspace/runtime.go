package expworkspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxRuntimeRequest  = 4 << 20
	maxRuntimeResponse = 2 << 20
)

type RuntimeClient struct {
	baseURL string
	client  *http.Client
}

func NewRuntimeClient(rawURL string) (*RuntimeClient, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("ARGUS_YAKSHA_URL must be an HTTP origin")
	}
	return &RuntimeClient{baseURL: strings.TrimRight(parsed.String(), "/"), client: &http.Client{}}, nil
}

func (c *RuntimeClient) Ready(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/readyz", nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("Yaksha Runtime Unavailable: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Yaksha Runtime Unavailable: readyz returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *RuntimeClient) Execute(ctx context.Context, request RuntimeRequest) (RuntimeResponse, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxRuntimeRequest {
		return nil, fmt.Errorf("Yaksha request exceeds %d bytes", maxRuntimeRequest)
	}
	timeout := time.Duration(request.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.baseURL+"/v1/execute", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Yaksha Runtime Unavailable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRuntimeResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRuntimeResponse {
		return nil, fmt.Errorf("Yaksha response exceeds %d bytes", maxRuntimeResponse)
	}
	var result RuntimeResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode Yaksha response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Yaksha Runtime Unavailable (HTTP %d): %s", resp.StatusCode, stringValue(result, "error"))
	}
	if stringValue(result, "status") == "" {
		return nil, errors.New("Yaksha response is missing status")
	}
	return result, nil
}
