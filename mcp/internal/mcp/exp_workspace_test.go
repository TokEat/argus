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
		if body["action"] != nil || body["source"] != "cli.check()" {
			t.Fatalf("unexpected body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"exp_id":"exp-1","revision":1,"source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	}))
	defer server.Close()
	client := NewClientWithYakshaURL(server.URL, "token", "http://127.0.0.1:8790")
	result, err := client.CallTool(context.Background(), "argus_exp_workspace", map[string]interface{}{"action": "revision_create", "exp_id": "exp-1", "source": "cli.check()", "dependencies": []interface{}{}, "assets": []interface{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(toJSON(result), `"revision":1`) {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestSavedYakshaExecutionLoadsSealedPackageAndReportsResult(t *testing.T) {
	const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var reports atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/exps/exp-1/revisions/3/sealed-package":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"exp_id":"exp-1","exp_status":"draft","risk_level":"high","risk_waiver_active":false,"revision":3,"source_sha256":"` + hash + `","script":"cli.check(); yaksha.result(true)","dependencies":[],"assets":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/exps/exp-1/revisions/3/run-reports":
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			response, _ := body["response"].(map[string]interface{})
			if body["egress_mode"] != "disabled" || body["risk_confirmed"] != true || response["status"] != "Succeeded" {
				t.Fatalf("unexpected report: %#v", body)
			}
			reports.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"run-1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	yaksha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["script"] != "cli.check(); yaksha.result(true)" || body["source_sha256"] != hash {
			t.Fatalf("Yaksha did not receive sealed package: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"req","action":"debug","status":"Succeeded","context":{"exp_id":"exp-1","revision":3,"source_sha256":"` + hash + `"},"result":true,"debug":{"events":[{"kind":"tcp","target":"example.invalid:443"}]}}`))
	}))
	defer yaksha.Close()

	client := NewClientWithYakshaURL(server.URL, "token", yaksha.URL)
	result, err := client.CallTool(context.Background(), "argus_yaksha_exp", map[string]interface{}{"action": "debug", "exp_id": "exp-1", "revision": 3, "risk_confirmed": true, "egress": map[string]interface{}{"mode": "disabled"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]interface{})["status"] != "Succeeded" || reports.Load() != 1 {
		t.Fatalf("unexpected result/report count: %#v %d", result, reports.Load())
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
	_, err := client.CallTool(context.Background(), "argus_yaksha_exp", map[string]interface{}{"action": "debug", "exp_id": "exp-risk", "revision": 1})
	if err == nil || !strings.Contains(err.Error(), "risk_confirmed") || yakshaCalls.Load() != 0 {
		t.Fatalf("high-risk execution should fail before Runtime: err=%v calls=%d", err, yakshaCalls.Load())
	}
}

func TestSavedYakshaExecutionRejectsCallerScriptOverride(t *testing.T) {
	client := NewClientWithYakshaURL("http://127.0.0.1:1", "token", "http://127.0.0.1:2")
	_, err := client.CallTool(context.Background(), "argus_yaksha_exp", map[string]interface{}{"action": "debug", "exp_id": "exp-1", "revision": 1, "script": "cli.check()"})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("saved identity plus script must fail closed: %v", err)
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
	result, err := client.CallTool(context.Background(), "argus_yaksha_exp", map[string]interface{}{"action": "test", "exp_id": "exp-2", "revision": 4})
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
