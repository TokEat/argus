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

func TestExpWorkspaceRoutesRevisionCreateThroughServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/exps/exp-1/revisions" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatal("missing Server authorization")
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["action"] != nil || body["source"] != "cli.check()" || body["test_receipt"] != "receipt" {
			t.Fatalf("unexpected body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"exp_id":"exp-1","revision":1,"source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	}))
	defer server.Close()
	client := NewClientWithYakshaURL(server.URL, "token", "http://127.0.0.1:8790")
	result, err := client.CallTool(context.Background(), "argus_exp_workspace", map[string]interface{}{"action": "revision_create", "exp_id": "exp-1", "source": "cli.check()", "dependencies": []interface{}{}, "assets": []interface{}{}, "test_cases": []interface{}{}, "test_receipt": "receipt"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(toJSON(result), `"revision":1`) {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestExpWorkspaceRoutesInMemoryDraftTestWithoutSavingSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/exps/exp-1/draft/test" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["source"] != "cli.check()" || len(body["test_cases"].([]interface{})) != 1 || body["test_receipt"] != nil {
			t.Fatalf("unexpected draft body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"runtime_response":{"status":"Succeeded","test":{"failed":0}},"test_receipt":"write-only","expires_at":"2026-08-14T12:00:00Z"}`))
	}))
	defer server.Close()
	client := NewClientWithYakshaURL(server.URL, "token", "http://127.0.0.1:8790")
	result, err := client.CallTool(context.Background(), "argus_exp_workspace", map[string]interface{}{
		"action": "draft_test", "exp_id": "exp-1", "source": "cli.check()", "dependencies": []interface{}{}, "assets": []interface{}{},
		"test_cases": []interface{}{map[string]interface{}{"name": "offline", "params": map[string]interface{}{}, "fixture": map[string]interface{}{}, "expect": map[string]interface{}{}}},
	})
	if err != nil || !strings.Contains(toJSON(result), `"test_receipt":"write-only"`) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestSavedYakshaExecutionLoadsSealedPackageAndReportsResult(t *testing.T) {
	const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var runs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/exps/exp-1/revisions/3/sealed-package":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"exp_id":"exp-1","exp_status":"draft","risk_level":"high","risk_waiver_active":false,"revision":3,"source_sha256":"` + hash + `","script":"cli.check(); yaksha.result(true)","dependencies":[],"assets":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/exps/exp-1/revisions/3/runs":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["source_sha256"] != hash || body["risk_confirmed"] != true || !strings.Contains(toJSON(body["egress"]), `"disabled"`) {
				t.Fatalf("unexpected trusted run: %#v", body)
			}
			runs.Add(1)
			_, _ = w.Write([]byte(`{"run_id":"run-1","response":{"id":"req","action":"debug","status":"Succeeded","context":{"exp_id":"exp-1","revision":3,"source_sha256":"` + hash + `"},"result":true,"debug":{"events":[{"kind":"tcp","target":"example.invalid:443"}]}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClientWithYakshaURL(server.URL, "token", "http://127.0.0.1:2")
	result, err := client.CallTool(context.Background(), "argus_yaksha_exp", map[string]interface{}{"action": "debug", "exp_id": "exp-1", "revision": 3, "source_sha256": hash, "risk_confirmed": true, "egress": map[string]interface{}{"mode": "disabled"}})
	if err != nil {
		t.Fatal(err)
	}
	response := result.(map[string]interface{})
	if response["status"] != "Succeeded" || response["server_run_id"] != "run-1" || runs.Load() != 1 {
		t.Fatalf("unexpected result/run count: %#v %d", result, runs.Load())
	}
}

func TestSavedHighRiskYakshaExecutionRequiresConfirmationBeforeRuntime(t *testing.T) {
	const hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"exp_id":"exp-risk","exp_status":"draft","risk_level":"critical","requires_risk_confirmation":true,"revision":1,"source_sha256":"` + hash + `","script":"cli.check()","dependencies":[],"assets":[]}`))
	}))
	defer server.Close()
	yakshaCalls := atomic.Int32{}
	yaksha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { yakshaCalls.Add(1) }))
	defer yaksha.Close()

	client := NewClientWithYakshaURL(server.URL, "token", yaksha.URL)
	_, err := client.CallTool(context.Background(), "argus_yaksha_exp", map[string]interface{}{"action": "debug", "exp_id": "exp-risk", "revision": 1, "source_sha256": hash})
	if err == nil || !strings.Contains(err.Error(), "risk_confirmed") || yakshaCalls.Load() != 0 {
		t.Fatalf("high-risk execution should fail before Runtime: err=%v calls=%d", err, yakshaCalls.Load())
	}
}

func TestSavedYakshaExecutionRejectsCallerScriptOverride(t *testing.T) {
	const hash = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
	client := NewClientWithYakshaURL("http://127.0.0.1:1", "token", "http://127.0.0.1:2")
	_, err := client.CallTool(context.Background(), "argus_yaksha_exp", map[string]interface{}{"action": "debug", "exp_id": "exp-1", "revision": 1, "source_sha256": hash, "script": "cli.check()"})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("saved identity plus script must fail closed: %v", err)
	}
}

func TestTransientYakshaExecutionRejectsRunAndDebugBeforeRuntime(t *testing.T) {
	client := NewClientWithYakshaURL("http://127.0.0.1:1", "token", "http://127.0.0.1:2")
	for _, action := range []string{"debug", "run"} {
		_, err := client.CallTool(context.Background(), "argus_yaksha_exp", map[string]interface{}{"action": action, "script": "cli.check()", "egress": map[string]interface{}{"mode": "direct"}})
		if err == nil || !strings.Contains(err.Error(), "saved Server EXP Revision") {
			t.Fatalf("transient %s should require saved Revision: %v", action, err)
		}
	}
}

func TestSavedYakshaTestUsesTrustedServerExecution(t *testing.T) {
	const hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/exps/exp-2/revisions/4/sealed-package" && r.URL.Query().Get("include_tests") == "true":
			_, _ = w.Write([]byte(`{"exp_id":"exp-2","revision":4,"source_sha256":"` + hash + `","script":"cli.check()","dependencies":[],"assets":[],"test_cases":[{"id":"case"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/exps/exp-2/revisions/4/runs":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["action"] != "test" || !strings.Contains(toJSON(body["egress"]), `"disabled"`) {
				t.Fatalf("unexpected trusted test request: %#v", body)
			}
			_, _ = w.Write([]byte(`{"run_id":"server-run","response":{"status":"Succeeded","test":{"failed":0}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	yakshaCalls := atomic.Int32{}
	yaksha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		yakshaCalls.Add(1)
		http.Error(w, "must not call local Yaksha", http.StatusInternalServerError)
	}))
	defer yaksha.Close()

	client := NewClientWithYakshaURL(server.URL, "token", yaksha.URL)
	result, err := client.CallTool(context.Background(), "argus_yaksha_exp", map[string]interface{}{"action": "test", "exp_id": "exp-2", "revision": 4, "source_sha256": hash})
	if err != nil {
		t.Fatal(err)
	}
	response := result.(map[string]interface{})
	if response["status"] != "Succeeded" || response["server_run_id"] != "server-run" || yakshaCalls.Load() != 0 {
		t.Fatalf("unexpected trusted test result: %#v local_calls=%d", response, yakshaCalls.Load())
	}
}

func toJSON(value interface{}) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
