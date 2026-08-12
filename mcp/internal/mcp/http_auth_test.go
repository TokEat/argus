package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateHTTPRequiresExactBearerToken(t *testing.T) {
	handler := AuthenticateHTTP("mcp-test-token", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, test := range []struct {
		header string
		want   int
	}{{"", http.StatusUnauthorized}, {"Bearer wrong", http.StatusUnauthorized}, {"Basic mcp-test-token", http.StatusUnauthorized}, {"Bearer mcp-test-token", http.StatusNoContent}} {
		request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		request.Header.Set("Authorization", test.header)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("header %q status=%d want=%d", test.header, response.Code, test.want)
		}
	}
}

func TestConfigRequiresInboundTokenForHTTP(t *testing.T) {
	t.Setenv("ARGUS_MCP_TRANSPORT", "http")
	t.Setenv("ARGUS_MCP_AUTH_TOKEN", "")
	t.Setenv("ARGUS_MCP_AUTH_TOKEN_FILE", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("HTTP transport started without an inbound authentication token")
	}
	t.Setenv("ARGUS_MCP_AUTH_TOKEN", "mcp-test-token")
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatal(err)
	}
}
