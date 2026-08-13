package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSDKStreamableHTTPHandlerListsTools(t *testing.T) {
	handler := sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server {
		return NewServer(NewClient("http://argus.local", "token"))
	}, &sdkmcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "argus-mcp-http-test-client", Version: "0.1.0"}, nil)
	session, err := client.Connect(context.Background(), &sdkmcp.StreamableClientTransport{Endpoint: ts.URL, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatalf("connect streamable http client: %v", err)
	}
	defer session.Close()
	if got := session.InitializeResult().ProtocolVersion; got != "2026-07-28" {
		t.Fatalf("negotiated protocol version = %q, want 2026-07-28", got)
	}
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools over streamable http: %v", err)
	}
	if len(result.Tools) != 8 {
		t.Fatalf("expected 8 tools over streamable http, got %d", len(result.Tools))
	}
}

func TestClientTurnsHTTPErrorIntoMessage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("missing bearer token: %q", got)
		}
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	}))
	defer ts.Close()
	client := NewClient(ts.URL, "test-token")
	_, err := client.Resource(context.Background(), "argus://argus-mcp/quickstart")
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("expected HTTP error detail, got %v", err)
	}
}

func TestConfigLoadsTokenFileWhenTokenEnvIsEmpty(t *testing.T) {
	t.Setenv("ARGUS_BASE_URL", "http://argus.local")
	t.Setenv("ARGUS_TOKEN", "")
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(" file-token \n"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	t.Setenv("ARGUS_TOKEN_FILE", tokenPath)
	t.Setenv("ARGUS_YAKSHA_URL", "http://127.0.0.1:18790")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Token != "file-token" || cfg.YakshaURL != "http://127.0.0.1:18790" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}
