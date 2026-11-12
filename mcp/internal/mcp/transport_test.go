package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPTransportReturnsJSONDecodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"uri":`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.Resource(context.Background(), "argus://fingerprint/spec")
	if err == nil || !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("expected JSON decode error, got %v", err)
	}
}
