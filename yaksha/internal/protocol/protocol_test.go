package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantID  string
		wantAct string
		wantErr string
	}{
		{name: "valid", line: `{"id":"run-1","script":"yaksha.result(1)","timeout_ms":1000}`, wantID: "run-1", wantAct: ActionRun},
		{name: "inspect", line: `{"id":"inspect-1","action":"inspect","script":"cli.check()"}`, wantID: "inspect-1", wantAct: ActionInspect},
		{name: "validate", line: `{"id":"validate-1","action":"validate","script":"cli.check()"}`, wantID: "validate-1", wantAct: ActionValidate},
		{name: "debug", line: `{"id":"debug-1","action":"debug","script":"cli.check()"}`, wantID: "debug-1", wantAct: ActionDebug},
		{name: "test", line: `{"id":"test-1","action":"test","script":"cli.check(); yaksha.result(2)","test_cases":[{"id":"case-1","expect":{"result":2}}]}`, wantID: "test-1", wantAct: ActionTest},
		{name: "anonymous id", line: `{"script":"yaksha.result(1)"}`, wantID: "anon", wantAct: ActionRun},
		{name: "malformed", line: `{`, wantErr: "invalid request JSON"},
		{name: "multiple values", line: `{"script":"x"} {"script":"y"}`, wantErr: "multiple values"},
		{name: "unknown field", line: `{"script":"x","unsafe":true}`, wantErr: "unknown field"},
		{name: "missing script", line: `{"id":"run-1"}`, wantErr: "missing script"},
		{name: "unknown action", line: `{"action":"publish","script":"x"}`, wantErr: "unsupported action"},
		{name: "test without cases", line: `{"action":"test","script":"cli.check()"}`, wantErr: "test_cases"},
		{name: "cases on run", line: `{"script":"cli.check()","test_cases":[{"id":"case-1","expect":{}}]}`, wantErr: "test_cases require action"},
		{name: "duplicate cases", line: `{"action":"test","script":"cli.check()","test_cases":[{"id":"same","expect":{}},{"id":"same","expect":{}}]}`, wantErr: "duplicate test case"},
		{name: "invalid fixture", line: `{"action":"test","script":"cli.check()","test_cases":[{"id":"case-1","fixture":{"http":[{"method":"CONNECT","url":"http://fixture.invalid","status_code":200}]},"expect":{}}]}`, wantErr: "unsupported method"},
		{name: "negative timeout", line: `{"script":"x","timeout_ms":-1}`, wantErr: "timeout_ms"},
		{name: "excessive timeout", line: `{"script":"x","timeout_ms":120001}`, wantErr: "timeout_ms"},
		{name: "disabled egress", line: `{"script":"x","egress":{"mode":"disabled"}}`, wantID: "anon", wantAct: ActionRun},
		{name: "direct egress", line: `{"script":"x","egress":{"mode":"direct"}}`, wantID: "anon", wantAct: ActionRun},
		{name: "per-request socks5", line: `{"script":"x","egress":{"mode":"socks5","socks5_proxy":"socks5://proxy.example:1080"}}`, wantID: "anon", wantAct: ActionRun},
		{name: "relay egress", line: `{"script":"x","egress":{"mode":"relay","route_id":"route-1"}}`, wantID: "anon", wantAct: ActionRun},
		{name: "missing mode", line: `{"script":"x","egress":{}}`, wantErr: "egress.mode"},
		{name: "invalid socks5", line: `{"script":"x","egress":{"mode":"socks5","socks5_proxy":"http://proxy.example:1080"}}`, wantErr: "socks5_proxy"},
		{name: "direct with proxy", line: `{"script":"x","egress":{"mode":"direct","socks5_proxy":"socks5://proxy.example:1080"}}`, wantErr: "does not accept"},
		{name: "socks with route", line: `{"script":"x","egress":{"mode":"socks5","socks5_proxy":"socks5://proxy.example:1080","route_id":"route-1"}}`, wantErr: "does not accept route_id"},
		{name: "relay with proxy", line: `{"script":"x","egress":{"mode":"relay","route_id":"route-1","socks5_proxy":"socks5://proxy.example:1080"}}`, wantErr: "does not accept socks5_proxy"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := ParseRequest(tc.line)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error=%v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if req.ID != tc.wantID {
				t.Fatalf("id=%q, want %q", req.ID, tc.wantID)
			}
			if req.Action != tc.wantAct {
				t.Fatalf("action=%q, want %q", req.Action, tc.wantAct)
			}
		})
	}
}

func TestBoundExecutionContextRequiresExactSourceIdentity(t *testing.T) {
	source := "cli.check()"
	hash := SourceHash(source)
	raw, err := json.Marshal(Request{ID: "bound", Action: ActionValidate, Script: source, ExpID: "exp.demo-1", Revision: 7, SourceSHA256: hash})
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseRequest(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	context := ExecutionContextFor(req)
	if context == nil || context.ExpID != "exp.demo-1" || context.Revision != 7 || context.SourceSHA256 != hash {
		t.Fatalf("context=%#v", context)
	}

	for name, request := range map[string]Request{
		"missing revision": {Script: source, ExpID: "exp.demo-1", SourceSHA256: hash},
		"missing exp":      {Script: source, Revision: 7, SourceSHA256: hash},
		"invalid exp":      {Script: source, ExpID: "../exp", Revision: 7, SourceSHA256: hash},
		"invalid hash":     {Script: source, ExpID: "exp.demo-1", Revision: 7, SourceSHA256: "ABC"},
		"hash mismatch":    {Script: source + "\n", ExpID: "exp.demo-1", Revision: 7, SourceSHA256: hash},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRequest(request); err == nil {
				t.Fatal("expected bound context validation error")
			}
		})
	}
}

func TestValidateRequestBounds(t *testing.T) {
	tests := []struct {
		name string
		req  Request
	}{
		{name: "id", req: Request{ID: strings.Repeat("i", MaxIDBytes+1), Script: "x"}},
		{name: "script", req: Request{ID: "x", Script: strings.Repeat("s", MaxScriptBytes+1)}},
		{name: "params", req: Request{ID: "x", Script: "x", Params: map[string]any{"v": strings.Repeat("p", MaxParamsBytes+1)}}},
		{name: "network targets", req: Request{ID: "x", Script: "x", NetworkTargets: make([]string, MaxNetworkTargets+1)}},
		{name: "proxy", req: Request{ID: "x", Script: "x", Egress: &EgressConfig{Mode: EgressSOCKS5, SOCKS5Proxy: strings.Repeat("p", MaxProxyURLBytes+1)}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateRequest(tc.req); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestInvalidSOCKS5URLIsNeverEchoed(t *testing.T) {
	const secret = "never-echo-this-password"
	_, err := ParseRequest(`{"script":"x","egress":{"mode":"socks5","socks5_proxy":"socks5://user:` + secret + `@proxy.example:not-a-port"}}`)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error must reject without echoing Raw URL: %v", err)
	}
}

func TestEncodeResponseBounds(t *testing.T) {
	if _, err := EncodeResponse(Response{ID: "ok", Status: StatusSucceeded, Result: "small"}); err != nil {
		t.Fatal(err)
	}
	_, err := EncodeResponse(Response{
		ID:     "large",
		Status: StatusSucceeded,
		Result: strings.Repeat("x", MaxResponseLineBytes),
	})
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("error=%v, want response limit error", err)
	}
}
