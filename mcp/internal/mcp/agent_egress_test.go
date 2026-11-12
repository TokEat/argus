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

func TestYakshaAgentEgressOrchestration(t *testing.T) {
	var created, revoked atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/exp-egress-routes":
			var request map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode route: %v", err)
			}
			if request["agent_id"] != "agent-a" || request["risk_confirmed"] != true {
				t.Errorf("route request=%v", request)
			}
			created.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"route_id": "route-1"})
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/exp-egress-routes/route-1":
			revoked.Store(true)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	yaksha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode Yaksha: %v", err)
		}
		egress, _ := request["egress"].(map[string]interface{})
		if egress["mode"] != "relay" || egress["route_id"] != "route-1" {
			t.Errorf("Yaksha egress=%v", egress)
		}
		if _, leaked := egress["agent_id"]; leaked {
			t.Errorf("agent id leaked to Yaksha: %v", egress)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": request["id"], "status": "Succeeded"})
	}))
	defer yaksha.Close()

	client := NewClientWithYakshaURL(server.URL, "test-token", yaksha.URL)
	result, err := client.executeYakshaExp(context.Background(), map[string]interface{}{
		"action": "debug", "script": "cli.check()", "network_targets": []interface{}{"tcp://example.test:443"},
		"egress": map[string]interface{}{"mode": "agent", "agent_id": "agent-a", "risk_confirmed": true},
	})
	if err != nil {
		t.Fatalf("yakshaExp: %v", err)
	}
	if result["status"] != "Succeeded" || !created.Load() || !revoked.Load() {
		t.Fatalf("result=%v created=%v revoked=%v", result, created.Load(), revoked.Load())
	}
}

func TestYakshaAgentEgressReportsRunAndCleanupFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"route_id": "route-failed"})
			return
		}
		http.Error(w, "cleanup failed", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	yaksha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "run failed", http.StatusBadGateway)
	}))
	defer yaksha.Close()
	client := NewClientWithYakshaURL(server.URL, "test-token", yaksha.URL)
	_, err := client.executeYakshaExp(context.Background(), map[string]interface{}{
		"action": "run", "script": "cli.check()", "network_targets": []interface{}{"tcp://example.test:443"},
		"egress": map[string]interface{}{"mode": "agent", "agent_id": "agent-a", "risk_confirmed": true},
	})
	if err == nil || !strings.Contains(err.Error(), "execute EXP") || !strings.Contains(err.Error(), "run failed") || !strings.Contains(err.Error(), "revoke Agent egress route") || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("combined error=%v", err)
	}
	if strings.Contains(err.Error(), "route-failed") {
		t.Fatalf("route_id leaked in error: %v", err)
	}
}
