package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanTaskUsesServerPreviewAndSealedCreate(t *testing.T) {
	t.Helper()
	var previewed bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("missing Server authentication: %q", r.Header.Get("Authorization"))
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if _, leaked := body["action"]; leaked {
			t.Fatal("MCP action must not enter the Server policy payload")
		}
		switch r.URL.Path {
		case "/api/v1/tasks/plan-preview":
			previewed = true
			if r.Header.Get("Idempotency-Key") != "" {
				t.Fatal("preview must not carry a create idempotency key")
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"plan_hash": "sealed-plan", "stages": []interface{}{}})
		case "/api/v1/tasks":
			if !previewed || body["plan_hash"] != "sealed-plan" {
				t.Fatalf("create did not preserve preview identity: %#v", body)
			}
			if got := r.Header.Get("Idempotency-Key"); got != "intent-1" {
				t.Fatalf("unexpected idempotency key %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "created", "task_id": "task-1"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	policy := map[string]interface{}{"schema_version": "argus.scan-policy/v1", "preset": "quick"}
	preview, err := client.scanTask(context.Background(), map[string]interface{}{"action": "preview", "project_id": "project-1", "targets": "example.com", "policy": policy})
	if err != nil || preview["plan_hash"] != "sealed-plan" {
		t.Fatalf("preview failed: result=%#v err=%v", preview, err)
	}
	created, err := client.scanTask(context.Background(), map[string]interface{}{"action": "create", "project_id": "project-1", "targets": "example.com", "policy": policy, "plan_hash": "sealed-plan", "idempotency_key": "intent-1"})
	if err != nil || created["task_id"] != "task-1" {
		t.Fatalf("create failed: result=%#v err=%v", created, err)
	}
}

func TestScanTaskCreateRequiresPreviewIdentity(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "test-token")
	base := map[string]interface{}{"action": "create", "project_id": "project-1", "targets": "example.com", "policy": map[string]interface{}{}}
	if _, err := client.scanTask(context.Background(), base); err == nil || !strings.Contains(err.Error(), "plan_hash") {
		t.Fatalf("expected missing plan hash rejection, got %v", err)
	}
	base["plan_hash"] = "sealed-plan"
	if _, err := client.scanTask(context.Background(), base); err == nil || !strings.Contains(err.Error(), "idempotency_key") {
		t.Fatalf("expected missing idempotency key rejection, got %v", err)
	}
}
