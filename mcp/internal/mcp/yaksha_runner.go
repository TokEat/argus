package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	yakshaDefaultTimeout = 15 * time.Second
	yakshaMaxTimeout     = 120 * time.Second
	yakshaRequestGrace   = 5 * time.Second
	yakshaMaxRequest     = 4 << 20
	yakshaMaxResponse    = 2 << 20
)

var yakshaActions = map[string]bool{"inspect": true, "validate": true, "run": true, "debug": true, "test": true}

type yakshaRunner struct {
	baseURL string
	client  *http.Client
}

func newYakshaRunner(rawURL string) *yakshaRunner {
	return &yakshaRunner{baseURL: strings.TrimRight(strings.TrimSpace(rawURL), "/"), client: &http.Client{}}
}

func (r *yakshaRunner) ready(ctx context.Context) error {
	endpoint, err := r.endpoint("/readyz")
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := r.httpClient().Do(request)
	if err != nil {
		return fmt.Errorf("Yaksha Runtime Unavailable: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Yaksha Runtime Unavailable: readyz returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (r *yakshaRunner) call(ctx context.Context, args map[string]interface{}) (map[string]interface{}, error) {
	requestValue, timeout, err := buildYakshaRequest(args)
	if err != nil {
		return nil, err
	}
	endpoint, err := r.endpoint("/v1/execute")
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(requestValue)
	if err != nil {
		return nil, fmt.Errorf("encode Yaksha request: %w", err)
	}
	if len(raw) > yakshaMaxRequest {
		return nil, fmt.Errorf("Yaksha request exceeds %d bytes", yakshaMaxRequest)
	}

	requestCtx, cancel := context.WithTimeout(ctx, timeout+yakshaRequestGrace)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.httpClient().Do(request)
	if errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("Yaksha request exceeded its %s controller deadline", timeout+yakshaRequestGrace)
	}
	if err != nil {
		return nil, fmt.Errorf("Yaksha Runtime Unavailable: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, yakshaMaxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("read Yaksha response: %w", err)
	}
	if len(body) > yakshaMaxResponse {
		return nil, fmt.Errorf("Yaksha response exceeds %d bytes", yakshaMaxResponse)
	}
	result, decodeErr := decodeYakshaResponse(body)
	if response.StatusCode != http.StatusOK {
		detail := strings.TrimSpace(string(body))
		if decodeErr == nil {
			detail = strings.TrimSpace(fmt.Sprint(result["error"]))
		}
		if detail == "" {
			detail = http.StatusText(response.StatusCode)
		}
		if response.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("Yaksha queue is full: %s", detail)
		}
		return nil, fmt.Errorf("Yaksha Runtime Unavailable (HTTP %d): %s", response.StatusCode, detail)
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	return result, nil
}

func (r *yakshaRunner) endpoint(path string) (string, error) {
	if r == nil || r.baseURL == "" {
		return "", fmt.Errorf("ARGUS_YAKSHA_URL is required")
	}
	parsed, err := url.Parse(r.baseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("ARGUS_YAKSHA_URL must be an HTTP origin")
	}
	return strings.TrimRight(parsed.String(), "/") + path, nil
}

func (r *yakshaRunner) httpClient() *http.Client {
	if r != nil && r.client != nil {
		return r.client
	}
	return http.DefaultClient
}

func decodeYakshaResponse(raw []byte) (map[string]interface{}, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("Yaksha returned an empty response")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var response map[string]interface{}
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("decode Yaksha response: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("Yaksha returned multiple JSON values")
		}
		return nil, fmt.Errorf("decode Yaksha response trailer: %w", err)
	}
	if strings.TrimSpace(fmt.Sprint(response["status"])) == "" {
		return nil, fmt.Errorf("Yaksha response is missing status")
	}
	return response, nil
}

func buildYakshaRequest(args map[string]interface{}) (map[string]interface{}, time.Duration, error) {
	allowed := map[string]bool{
		"action": true, "script": true, "params": true, "timeout_ms": true, "test_cases": true,
		"exp_id": true, "revision": true, "source_sha256": true, "dependencies": true, "assets": true,
		"network_targets": true, "egress": true,
	}
	for key := range args {
		if !allowed[key] {
			return nil, 0, fmt.Errorf("unsupported Yaksha argument %q", key)
		}
	}
	action := strings.ToLower(stringArg(args, "action"))
	if !yakshaActions[action] {
		return nil, 0, fmt.Errorf("action must be one of inspect, validate, run, debug, test")
	}
	script := rawStringArg(args, "script")
	if strings.TrimSpace(script) == "" {
		return nil, 0, fmt.Errorf("script is required")
	}

	timeout := yakshaDefaultTimeout
	timeoutMS := 0
	if value, ok := numberArg(args, "timeout_ms"); ok {
		if value < 0 || time.Duration(value)*time.Millisecond > yakshaMaxTimeout {
			return nil, 0, fmt.Errorf("timeout_ms must be between 0 and %d", yakshaMaxTimeout.Milliseconds())
		}
		timeoutMS = value
		if value > 0 {
			timeout = time.Duration(value) * time.Millisecond
		}
	}

	request := map[string]interface{}{"id": newYakshaRequestID(), "action": action, "script": script}
	expID := rawStringArg(args, "exp_id")
	sourceSHA256 := rawStringArg(args, "source_sha256")
	revisionValue, revisionPresent := args["revision"]
	revision, hasRevision := yakshaRevisionArg(revisionValue)
	boundContext := expID != "" || sourceSHA256 != "" || revisionPresent
	if boundContext {
		if expID == "" || sourceSHA256 == "" || !hasRevision || revision < 1 {
			return nil, 0, fmt.Errorf("exp_id, revision, and source_sha256 are required together")
		}
		request["exp_id"], request["revision"], request["source_sha256"] = expID, revision, sourceSHA256
	}
	if timeoutMS > 0 {
		request["timeout_ms"] = timeoutMS
	}
	if params, ok := args["params"]; ok && params != nil {
		if action == "test" {
			return nil, 0, fmt.Errorf("top-level params are not allowed for action test; use test_cases[].params")
		}
		if _, ok := params.(map[string]interface{}); !ok {
			return nil, 0, fmt.Errorf("params must be an object")
		}
		request["params"] = params
	}
	if testCases, ok := args["test_cases"]; ok && testCases != nil {
		if action != "test" {
			return nil, 0, fmt.Errorf("test_cases are only allowed for action test")
		}
		if _, ok := testCases.([]interface{}); !ok {
			return nil, 0, fmt.Errorf("test_cases must be an array")
		}
		request["test_cases"] = testCases
	} else if action == "test" {
		return nil, 0, fmt.Errorf("test_cases are required for action test")
	}
	for _, key := range []string{"dependencies", "assets", "network_targets"} {
		if value, ok := args[key]; ok && value != nil {
			if _, ok := value.([]interface{}); !ok {
				return nil, 0, fmt.Errorf("%s must be an array", key)
			}
			request[key] = value
		}
	}
	if value, ok := args["egress"]; ok && value != nil {
		config, ok := value.(map[string]interface{})
		if !ok {
			return nil, 0, fmt.Errorf("egress must be an object")
		}
		if err := validateMCPEgress(config); err != nil {
			return nil, 0, err
		}
		request["egress"] = config
	}
	if action == "inspect" {
		for _, key := range []string{"dependencies", "assets", "network_targets", "egress"} {
			if _, exists := request[key]; exists {
				return nil, 0, fmt.Errorf("inspect accepts source only; %s is not allowed", key)
			}
		}
	}
	return request, timeout, nil
}

func validateMCPEgress(config map[string]interface{}) error {
	for key := range config {
		if key != "mode" && key != "socks5_proxy" {
			return fmt.Errorf("egress contains unsupported field %q", key)
		}
	}
	mode, ok := config["mode"].(string)
	if !ok || strings.TrimSpace(mode) == "" {
		return fmt.Errorf("egress.mode is required")
	}
	proxyValue, hasProxy := config["socks5_proxy"]
	proxyURL, proxyIsString := proxyValue.(string)
	switch mode {
	case "disabled", "direct":
		if hasProxy {
			return fmt.Errorf("egress mode %s does not accept socks5_proxy", mode)
		}
	case "socks5":
		if !hasProxy || !proxyIsString || !validSOCKS5URL(proxyURL) {
			return fmt.Errorf("egress.socks5_proxy must be a valid write-only socks5 URL")
		}
	default:
		return fmt.Errorf("egress.mode must be one of disabled, direct, socks5")
	}
	return nil
}

func validSOCKS5URL(raw string) bool {
	if len(raw) == 0 || len(raw) > 2048 {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "socks5" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	port, err := strconv.Atoi(parsed.Port())
	return err == nil && port > 0 && port <= 65535
}

func yakshaRevisionArg(value interface{}) (int, bool) {
	switch revision := value.(type) {
	case int:
		return revision, true
	case int64:
		converted := int(revision)
		return converted, int64(converted) == revision
	case float64:
		converted := int(revision)
		return converted, float64(converted) == revision
	case json.Number:
		parsed, err := revision.Int64()
		if err != nil {
			return 0, false
		}
		converted := int(parsed)
		return converted, int64(converted) == parsed
	default:
		return 0, false
	}
}

func rawStringArg(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	value, _ := args[key].(string)
	return value
}

func newYakshaRequestID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("mcp-%d", time.Now().UnixNano())
	}
	return "mcp-" + hex.EncodeToString(raw[:])
}
