package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type captureAuditor struct {
	mu      sync.Mutex
	records []ToolCallRecord
}

func (a *captureAuditor) Record(_ context.Context, rec ToolCallRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, rec)
}

func (a *captureAuditor) snapshot() []ToolCallRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ToolCallRecord, len(a.records))
	copy(out, a.records)
	return out
}

func TestAuditableToolActionCoverage(t *testing.T) {
	cases := []struct {
		tool   string
		args   map[string]interface{}
		action string
		ok     bool
	}{
		{tool: "argus_help", ok: false},
		{tool: "argus_scan_preview", ok: false},
		{tool: "argus_rule_list", ok: false},
		{tool: "argus_exp_workspace", args: map[string]interface{}{"action": "exp_list"}, ok: false},
		{tool: "argus_rule_apply", args: map[string]interface{}{"action": "deprecate"}, ok: false},
		{tool: "argus_yaksha_exp", args: map[string]interface{}{"action": "inspect"}, ok: false},
		{tool: "argus_yaksha_exp", args: map[string]interface{}{"action": "validate"}, ok: false},
		{tool: "argus_yaksha_exp", args: map[string]interface{}{"action": "test"}, ok: false},
		{tool: "argus_debug_fingerprint", ok: true},
		{tool: "argus_debug_dir", ok: true},
		{tool: "argus_debug_poc", ok: true},
		{tool: "argus_debug_workflow", ok: true},
		{tool: "argus_debug_behavior_probe", ok: true},
		{tool: "argus_save_fingerprint", ok: true},
		{tool: "argus_save_dir", ok: true},
		{tool: "argus_save_poc", ok: true},
		{tool: "argus_save_workflow", ok: true},
		{tool: "argus_debug_future", ok: true},
		{tool: "argus_save_future", ok: true},
		{tool: "argus_scan_create", ok: true},
		{tool: "argus_rule_apply", args: map[string]interface{}{"action": "publish"}, action: "publish", ok: true},
		{tool: "argus_yaksha_exp", args: map[string]interface{}{"action": "debug"}, action: "debug", ok: true},
		{tool: "argus_yaksha_exp", args: map[string]interface{}{"action": "run"}, action: "run", ok: true},
	}
	for _, tc := range cases {
		action, ok := AuditableToolAction(tc.tool, tc.args)
		if ok != tc.ok || action != tc.action {
			t.Fatalf("%s %#v => action=%q ok=%v, want action=%q ok=%v", tc.tool, tc.args, action, ok, tc.action, tc.ok)
		}
	}
}

func TestHelpDoesNotRecordAudit(t *testing.T) {
	auditor := &captureAuditor{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"help":"ok"}`))
	}))
	defer ts.Close()

	session, cleanup := connectTestSession(t, NewServer(NewClient(ts.URL, "test-token"), WithToolAuditor(auditor)))
	defer cleanup()

	if _, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      "argus_help",
		Arguments: map[string]any{"action": "help"},
	}); err != nil {
		t.Fatalf("CallTool(argus_help): %v", err)
	}
	if got := auditor.snapshot(); len(got) != 0 {
		t.Fatalf("help must not record, got %#v", got)
	}
}

func TestScanCreateRecordsAfterElicitAccept(t *testing.T) {
	auditor := &captureAuditor{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"created","task_id":"task-1"}`))
	}))
	defer ts.Close()

	session, cleanup := connectElicitSession(t, NewServer(NewClient(ts.URL, "test-token"), WithToolAuditor(auditor)), "accept", true)
	defer cleanup()

	if _, err := session.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "argus_scan_create",
		Arguments: map[string]any{
			"project_id":      "project-1",
			"targets":         "example.com",
			"policy":          map[string]any{"schema_version": "argus.scan-policy/v1"},
			"plan_hash":       "sealed-plan",
			"idempotency_key": "intent-1",
		},
	}); err != nil {
		t.Fatalf("CallTool(argus_scan_create): %v", err)
	}
	got := auditor.snapshot()
	if len(got) != 1 || got[0].ToolName != "argus_scan_create" || got[0].Err != nil {
		t.Fatalf("expected one successful scan create record, got %#v", got)
	}
	if got[0].Args["plan_hash"] != "sealed-plan" {
		t.Fatalf("expected plan_hash to be kept, got %#v", got[0].Args)
	}
}

func TestElicitDeclineDoesNotRecord(t *testing.T) {
	auditor := &captureAuditor{}
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("declined elicitation must not call REST")
	}))
	defer ts.Close()

	session, cleanup := connectElicitSession(t, NewServer(NewClient(ts.URL, "test-token"), WithToolAuditor(auditor)), "decline", false)
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
		t.Fatalf("expected decline error, got %#v", result)
	}
	if got := auditor.snapshot(); len(got) != 0 {
		t.Fatalf("decline must not record, got %#v", got)
	}
}
