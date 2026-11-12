package mcp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestElicitStateBindsToolArguments(t *testing.T) {
	client := NewClient("http://argus.local", "token-a")
	args := map[string]interface{}{"agent_id": "agent-1", "target_url": "http://authorized.example/", "file_name": "probe.yaml", "content": "id: probe\n"}
	state, ok := signElicitState(client, "argus_debug_behavior_probe", args)
	if !ok {
		t.Fatal("expected signed state")
	}
	if !verifyElicitState(client, "argus_debug_behavior_probe", args, state) {
		t.Fatal("expected signed state to verify")
	}
	tampered := cloneArgs(args)
	tampered["target_url"] = "http://other.example/"
	if verifyElicitState(client, "argus_debug_behavior_probe", tampered, state) {
		t.Fatal("state must not verify after target_url changes")
	}
	tamperedContent := cloneArgs(args)
	tamperedContent["content"] = "id: other\n"
	if verifyElicitState(client, "argus_debug_behavior_probe", tamperedContent, state) {
		t.Fatal("state must not verify after probe content changes")
	}
	otherClient := NewClient("http://argus.local", "token-b")
	if verifyElicitState(otherClient, "argus_debug_behavior_probe", args, state) {
		t.Fatal("state must not verify under a different access token")
	}
}

func TestElicitIgnoresModelRiskConfirmedFlag(t *testing.T) {
	for _, tc := range []struct {
		tool string
		args map[string]interface{}
	}{
		{tool: "argus_debug_behavior_probe", args: map[string]interface{}{"risk_confirmed": true, "agent_id": "agent-1"}},
		{tool: "argus_yaksha_exp", args: map[string]interface{}{"action": "debug", "risk_confirmed": true, "egress": map[string]interface{}{"mode": "agent", "risk_confirmed": true}}},
	} {
		_, needed := elicitMessage(tc.tool, tc.args)
		if !needed {
			t.Fatalf("%s skipped elicitation when risk_confirmed was already true", tc.tool)
		}
	}
	if _, needed := elicitMessage("argus_yaksha_exp", map[string]interface{}{"action": "inspect"}); needed {
		t.Fatal("inspect must not elicit")
	}
}

func TestElicitRefusesEmptyServerToken(t *testing.T) {
	client := NewClient("http://argus.local", "")
	if _, ok := elicitMACKey(client); ok {
		t.Fatal("empty Server token must not yield a MAC key")
	}
	args := map[string]interface{}{"agent_id": "agent-1", "target_url": "http://authorized.example/"}
	if _, ok := signElicitState(client, "argus_debug_behavior_probe", args); ok {
		t.Fatal("empty Server token must not sign requestState")
	}
	if verifyElicitState(client, "argus_debug_behavior_probe", args, "payload.mac") {
		t.Fatal("empty Server token must not verify requestState")
	}
	payload, _ := json.Marshal(elicitState{Tool: "argus_debug_behavior_probe", Bound: elicitBoundFields("argus_debug_behavior_probe", args)})
	legacy := hmac.New(sha256.New, []byte("argus-mcp-elicit"))
	_, _ = legacy.Write(payload)
	forged := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(legacy.Sum(nil))
	if verifyElicitState(client, "argus_debug_behavior_probe", args, forged) {
		t.Fatal("legacy public HMAC fallback must not verify")
	}
	if verifyElicitState(NewClient("http://argus.local", "token-a"), "argus_debug_behavior_probe", args, forged) {
		t.Fatal("legacy public HMAC fallback must not verify against a real token")
	}
}

func TestElicitSkippedWithoutClientCapability(t *testing.T) {
	req := &sdkmcp.CallToolRequest{Params: &sdkmcp.CallToolParamsRaw{Name: "argus_scan_create"}}
	pending, err := maybeElicit(NewClient("http://argus.local", "token"), "argus_scan_create", req, map[string]interface{}{"plan_hash": "abc"})
	if err != nil || pending != nil {
		t.Fatalf("clients without elicitation must not be blocked: pending=%#v err=%v", pending, err)
	}
}

func TestElicitationStillPromptsWhenRiskConfirmedAlreadyTrue(t *testing.T) {
	var elicited int
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("model-supplied risk_confirmed must not skip elicitation or call REST after decline")
	}))
	defer ts.Close()

	ctx := context.Background()
	serverTransport, clientTransport := sdkmcp.NewInMemoryTransports()
	serverSession, err := NewServer(NewClient(ts.URL, "test-token")).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "argus-mcp-elicit-test", Version: "0.1.0"}, &sdkmcp.ClientOptions{
		ElicitationHandler: func(context.Context, *sdkmcp.ElicitRequest) (*sdkmcp.ElicitResult, error) {
			elicited++
			return &sdkmcp.ElicitResult{Action: "decline", Content: map[string]any{"confirmed": false}}, nil
		},
	})
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Wait()
		t.Fatalf("connect client: %v", err)
	}
	defer func() {
		_ = session.Close()
		_ = serverSession.Wait()
	}()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "argus_debug_behavior_probe",
		Arguments: map[string]any{
			"agent_id":       "agent-1",
			"target_url":     "http://authorized.example/",
			"file_name":      "probe.yaml",
			"content":        "id: probe\ninfo:\n  name: probe\n  author: argus\n  severity: info\n",
			"risk_confirmed": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if elicited == 0 {
		t.Fatal("expected elicitation even when risk_confirmed=true")
	}
	if !result.IsError {
		t.Fatalf("expected decline error, got %#v", result)
	}
}

func TestElicitEmptyTokenBlocksDangerousTool(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("empty Server token must not reach REST")
	}))
	defer ts.Close()

	session, cleanup := connectElicitSession(t, NewServer(NewClient(ts.URL, "")), "accept", true)
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "argus_debug_behavior_probe",
		Arguments: map[string]any{
			"agent_id":       "agent-1",
			"target_url":     "http://authorized.example/",
			"file_name":      "probe.yaml",
			"content":        "id: probe\ninfo:\n  name: probe\n  author: argus\n  severity: info\n",
			"risk_confirmed": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected token error, got %#v", result)
	}
	text := result.Content[0].(*sdkmcp.TextContent).Text
	if !strings.Contains(text, "Server access token") {
		t.Fatalf("unexpected error text: %s", text)
	}
}

func connectElicitSession(t *testing.T, server *sdkmcp.Server, action string, confirmed bool) (*sdkmcp.ClientSession, func()) {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := sdkmcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "argus-mcp-elicit-test", Version: "0.1.0"}, &sdkmcp.ClientOptions{
		ElicitationHandler: func(context.Context, *sdkmcp.ElicitRequest) (*sdkmcp.ElicitResult, error) {
			return &sdkmcp.ElicitResult{Action: action, Content: map[string]any{"confirmed": confirmed}}, nil
		},
	})
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Wait()
		t.Fatalf("connect client: %v", err)
	}
	return clientSession, func() {
		_ = clientSession.Close()
		_ = serverSession.Wait()
	}
}

func TestElicitationConfirmsScanCreateThenHitsREST(t *testing.T) {
	var created bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tasks" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		created = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"created","task_id":"task-1"}`))
	}))
	defer ts.Close()

	session, cleanup := connectElicitSession(t, NewServer(NewClient(ts.URL, "test-token")), "accept", true)
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "argus_scan_create",
		Arguments: map[string]any{
			"project_id":      "project-1",
			"targets":         "example.com",
			"policy":          map[string]any{"schema_version": "argus.scan-policy/v1"},
			"plan_hash":       "sealed-plan",
			"idempotency_key": "intent-1",
		},
	})
	if err != nil {
		t.Fatalf("CallTool(argus_scan_create): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %#v", result)
	}
	if !created {
		t.Fatal("accepted elicitation did not reach scan create REST")
	}
	raw, _ := json.Marshal(result.StructuredContent)
	if !strings.Contains(string(raw), "task-1") {
		t.Fatalf("missing created task: %s", raw)
	}
}

func TestElicitationDeclineDoesNotCallREST(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("declined elicitation must not call REST")
	}))
	defer ts.Close()

	session, cleanup := connectElicitSession(t, NewServer(NewClient(ts.URL, "test-token")), "decline", false)
	defer cleanup()

	result, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "argus_debug_behavior_probe",
		Arguments: map[string]any{
			"agent_id":   "agent-1",
			"target_url": "http://authorized.example/",
			"file_name":  "probe.yaml",
			"content":    "id: probe\ninfo:\n  name: probe\n  author: argus\n  severity: info\n",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected error result after decline, got %#v", result)
	}
	text := result.Content[0].(*sdkmcp.TextContent).Text
	if !strings.Contains(text, "declined") {
		t.Fatalf("unexpected decline text: %s", text)
	}
}
