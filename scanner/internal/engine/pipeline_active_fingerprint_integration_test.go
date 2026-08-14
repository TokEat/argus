package engine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestDockerShiroActiveFingerprintSmoke(t *testing.T) {
	target := os.Getenv("ARGUS_SHIRO_URL")
	if target == "" {
		t.Skip("set ARGUS_SHIRO_URL to an authorized Docker Shiro target")
	}
	upstream, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	server := newLoopbackTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		proxy.ServeHTTP(response, request)
	}))

	templateDir := filepath.Join("..", "..", "common", "config", "active-fingerprints")
	content, err := os.ReadFile(filepath.Join(templateDir, "shiro-detect.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var output []structs.OutputMessage
	ctx := &ScanContext{Ctx: context.Background(), OutputHook: func(message structs.OutputMessage) { output = append(output, message) }}
	if err := runActiveFingerprintPhase(ctx, &Config{BehaviorProbe: false}, []string{server.URL}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 || len(output) != 0 {
		t.Fatalf("disabled behavior probe sent requests or emitted results: requests=%d output=%#v", requests.Load(), output)
	}
	cfg := &Config{
		BehaviorProbe: true, ActiveFingerprintTemplate: templateDir,
		ActiveFingerprintHashes:    map[string]string{"shiro-detect.yaml": fmt.Sprintf("%x", sha256.Sum256(content))},
		ActiveFingerprintProducts:  map[string]string{"shiro-detect.yaml": "APACHE-Shiro"},
		BehaviorProbeRequestBudget: 1, WebThreads: 1,
	}
	if err := runActiveFingerprintPhase(ctx, cfg, []string{server.URL, server.URL + "/redirected"}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("Shiro behavior probe sent %d requests, want exactly 1", requests.Load())
	}
	if len(output) != 1 || output[0].Type != "Active-Finger" || len(output[0].Finger) != 1 || output[0].Finger[0] != "APACHE-Shiro" {
		t.Fatalf("unexpected Shiro fingerprint result: %#v", output)
	}
}

func newLoopbackTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Start()
	t.Cleanup(server.Close)
	return server
}
