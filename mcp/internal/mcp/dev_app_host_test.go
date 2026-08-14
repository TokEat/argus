package mcp

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDevAppHostServesStudioAndProtectsToolBridge(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	host := NewDevAppHost(NewClient("http://127.0.0.1:1", "server-token"), next).(*devAppHost)

	request := httptest.NewRequest(http.MethodGet, "/__dev/exp-studio", nil)
	response := httptest.NewRecorder()
	host.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Yaksha EXP Studio Dev Host") || strings.Contains(response.Body.String(), "server-token") {
		t.Fatalf("host response=%d %s", response.Code, response.Body.String())
	}
	if want := "var nonce=" + strconv.Quote(host.nonce) + ";"; !strings.Contains(response.Body.String(), want) {
		t.Fatalf("development nonce is not encoded as a JavaScript string")
	}

	appRequest := httptest.NewRequest(http.MethodGet, "/__dev/exp-studio/app", nil)
	appResponse := httptest.NewRecorder()
	host.ServeHTTP(appResponse, appRequest)
	if appResponse.Code != http.StatusOK || !strings.Contains(appResponse.Body.String(), "Yaksha EXP Studio") {
		t.Fatalf("app response=%d", appResponse.Code)
	}

	toolRequest := httptest.NewRequest(http.MethodPost, "/__dev/tools/call", strings.NewReader(`{"name":"argus_exp_workspace","arguments":{"action":"exp_list"}}`))
	toolRequest.Header.Set("Content-Type", "application/json")
	toolResponse := httptest.NewRecorder()
	host.ServeHTTP(toolResponse, toolRequest)
	if toolResponse.Code != http.StatusForbidden {
		t.Fatalf("tool response=%d", toolResponse.Code)
	}
}

func TestDevAppHostRestrictsContextToAgentDiscovery(t *testing.T) {
	host := NewDevAppHost(NewClient("http://127.0.0.1:1", "server-token"), http.NotFoundHandler()).(*devAppHost)
	request := httptest.NewRequest(http.MethodPost, "/__dev/tools/call", strings.NewReader(`{"name":"argus_context","arguments":{"action":"overview"}}`))
	request.Header.Set("X-Argus-Dev-Nonce", host.nonce)
	response := httptest.NewRecorder()
	host.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "read-only agents") {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
}

func TestDevAppHostConfigRequiresExplicitLoopbackHTTP(t *testing.T) {
	t.Setenv("ARGUS_MCP_TRANSPORT", "http")
	t.Setenv("ARGUS_MCP_AUTH_TOKEN", "mcp-token")
	t.Setenv("ARGUS_MCP_APP_DEV_HOST", "true")
	t.Setenv("ARGUS_MCP_HTTP_ADDR", "0.0.0.0:8787")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error=%v", err)
	}
	t.Setenv("ARGUS_MCP_HTTP_ADDR", "127.0.0.1:8787")
	if cfg, err := ConfigFromEnv(); err != nil || !cfg.AppDevHost {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
}
