package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func helperYakshaRunner() (*yakshaRunner, func()) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/readyz" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ready"}`))
			return
		}
		var input map[string]interface{}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		response := map[string]interface{}{
			"id": input["id"], "action": input["action"], "status": "Succeeded",
			"result": map[string]interface{}{"request": input},
		}
		if input["exp_id"] != nil {
			response["context"] = map[string]interface{}{"exp_id": input["exp_id"], "revision": input["revision"], "source_sha256": input["source_sha256"]}
		}
		if input["action"] == "inspect" {
			response["inspection"] = map[string]interface{}{"valid": true, "source_sha256": "helper-hash", "parameters": []interface{}{map[string]interface{}{"name": "target", "type": "String", "required": true}}, "diagnostics": []interface{}{}}
		}
		if input["action"] == "debug" {
			response["debug"] = map[string]interface{}{"events": []interface{}{map[string]interface{}{"kind": "http", "operation": "GET", "target": "https://authorized.invalid/path?token=full-detail", "error": "dial tcp 192.0.2.10:443: exact diagnostic detail"}}, "truncated": false}
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	return newYakshaRunner(server.URL), server.Close
}

func TestYakshaRunnerUsesPersistentHTTPRuntime(t *testing.T) {
	runner, closeServer := helperYakshaRunner()
	defer closeServer()
	if err := runner.ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	response, err := runner.call(context.Background(), map[string]interface{}{"action": "inspect", "script": "cli.check()", "timeout_ms": float64(1000)})
	if err != nil {
		t.Fatal(err)
	}
	if response["status"] != "Succeeded" || response["action"] != "inspect" {
		t.Fatalf("response=%#v", response)
	}
}

func TestYakshaRunnerPassesSealedBundleAndPerCallEgress(t *testing.T) {
	runner, closeServer := helperYakshaRunner()
	defer closeServer()
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	response, err := runner.call(context.Background(), map[string]interface{}{
		"action": "run", "script": "cli.check()", "exp_id": "exp-demo", "revision": float64(4), "source_sha256": hash,
		"dependencies":    []interface{}{map[string]interface{}{"exp_id": "child", "revision": 1, "source_sha256": hash, "script": "cli.check()"}},
		"assets":          []interface{}{map[string]interface{}{"asset_id": "payload", "sha256": hash, "encoding": "utf8", "content": "x"}},
		"network_targets": []interface{}{"https://target.example:443"},
		"egress":          map[string]interface{}{"mode": "socks5", "socks5_proxy": "socks5://user:password@proxy.example:1080"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := response["result"].(map[string]interface{})
	request := result["request"].(map[string]interface{})
	for _, key := range []string{"dependencies", "assets", "network_targets", "egress"} {
		if request[key] == nil {
			t.Fatalf("request lost %s: %#v", key, request)
		}
	}
}

func TestYakshaRunnerPreservesCompleteDebugOutput(t *testing.T) {
	runner, closeServer := helperYakshaRunner()
	defer closeServer()
	response, err := runner.call(context.Background(), map[string]interface{}{"action": "debug", "script": "cli.check()"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(response)
	for _, want := range []string{"token=full-detail", "192.0.2.10:443", "exact diagnostic detail"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("debug output lost %q: %s", want, raw)
		}
	}
}

func TestYakshaRunnerDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, `{"status":"InternalError","error":"worker stopped"}`, http.StatusBadGateway)
	}))
	defer server.Close()
	_, err := newYakshaRunner(server.URL).call(context.Background(), map[string]interface{}{"action": "run", "script": "cli.check()"})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("error=%v calls=%d", err, calls.Load())
	}
}

func TestYakshaRunnerRejectsInvalidArguments(t *testing.T) {
	runner, closeServer := helperYakshaRunner()
	defer closeServer()
	for _, args := range []map[string]interface{}{
		{"action": "run", "script": "cli.check()", "binary_path": "/tmp/other"},
		{"action": "run", "script": "cli.check()", "params": "not-an-object"},
		{"action": "run", "script": "cli.check()", "dependencies": map[string]interface{}{}},
		{"action": "inspect", "script": "cli.check()", "network_targets": []interface{}{}},
		{"action": "run", "script": "cli.check()", "egress": "socks5://agent.example:1080"},
		{"action": "run", "script": "cli.check()", "egress": map[string]interface{}{}},
		{"action": "run", "script": "cli.check()", "egress": map[string]interface{}{"mode": "relay"}},
		{"action": "run", "script": "cli.check()", "egress": map[string]interface{}{"mode": "direct", "socks5_proxy": "socks5://proxy.example:1080"}},
		{"action": "run", "script": "cli.check()", "egress": map[string]interface{}{"mode": "socks5"}},
		{"action": "run", "script": "cli.check()", "egress": map[string]interface{}{"mode": "socks5", "socks5_proxy": "socks5://user:secret@proxy.example:1080", "route_id": "not-public"}},
		{"action": "test", "script": "cli.check()"},
		{"action": "shell", "script": "cli.check()"},
		{"action": "run", "script": "cli.check()", "exp_id": "exp-demo"},
	} {
		if _, err := runner.call(context.Background(), args); err == nil {
			t.Fatalf("expected validation error for %#v", args)
		}
	}
}

func TestYakshaRunnerEgressModesAndWriteOnlyErrors(t *testing.T) {
	runner, closeServer := helperYakshaRunner()
	defer closeServer()
	for _, mode := range []string{"disabled", "direct"} {
		if _, err := runner.call(context.Background(), map[string]interface{}{"action": "run", "script": "cli.check()", "egress": map[string]interface{}{"mode": mode}}); err != nil {
			t.Fatalf("mode %s: %v", mode, err)
		}
	}
	const secret = "never-echo-this-password"
	_, err := runner.call(context.Background(), map[string]interface{}{
		"action": "run", "script": "cli.check()",
		"egress": map[string]interface{}{"mode": "socks5", "socks5_proxy": "socks5://user:" + secret + "@proxy.example:not-a-port"},
	})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error must reject without echoing credentials: %v", err)
	}
}
