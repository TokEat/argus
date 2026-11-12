package api

import (
	"strings"
	"testing"
)

func TestRedactMCPToolArgsKeepsYAMLAndStripsSecrets(t *testing.T) {
	args := map[string]interface{}{
		"agent_id":      "agent-1",
		"target_url":    "http://authorized.example/",
		"plan_hash":     "sealed-plan",
		"content":       "id: probe\ninfo:\n  name: probe\n",
		"cookie":        "session=abc",
		"access_token":  "tok-1",
		"Authorization": "Bearer secret",
		"socks5_proxy":  "socks5://user:pass@127.0.0.1:1080",
		"egress": map[string]interface{}{
			"mode":         "direct",
			"socks5_proxy": "socks5://user:pass@127.0.0.1:1080",
		},
	}
	got := redactMCPToolArgs(args)
	if got["content"] != "id: probe\ninfo:\n  name: probe\n" || got["plan_hash"] != "sealed-plan" {
		t.Fatalf("expected YAML and plan_hash to remain, got %#v", got)
	}
	if got["cookie"] != "[redacted]" || got["access_token"] != "[redacted]" || got["Authorization"] != "[redacted]" || got["socks5_proxy"] != "[redacted]" {
		t.Fatalf("expected secret keys redacted, got %#v", got)
	}
	egress, _ := got["egress"].(map[string]interface{})
	if egress["mode"] != "direct" || egress["socks5_proxy"] != "[redacted]" {
		t.Fatalf("expected nested proxy redacted, got %#v", egress)
	}
}

func TestRedactMCPToolArgsStripsSecretsInsideYAMLContent(t *testing.T) {
	args := map[string]interface{}{
		"agent_id": "agent-1",
		"content": `id: probe
info:
  name: probe
  author: argus
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    headers:
      Cookie: session=abc
      Authorization: Bearer tok-1
      User-Agent: nuclei
`,
	}
	got := redactMCPToolArgs(args)
	content, _ := got["content"].(string)
	if !strings.Contains(content, "id: probe") || !strings.Contains(content, "User-Agent: nuclei") {
		t.Fatalf("expected non-secret YAML to remain, got %q", content)
	}
	if strings.Contains(content, "session=abc") || strings.Contains(content, "Bearer tok-1") {
		t.Fatalf("expected cookie/token inside YAML content to be redacted, got %q", content)
	}
	if !strings.Contains(content, "Cookie: '[redacted]'") && !strings.Contains(content, "Cookie: [redacted]") {
		t.Fatalf("expected Cookie key to stay with redacted value, got %q", content)
	}
}

func TestMarshalMCPAuditArgsCapsHugePayload(t *testing.T) {
	huge := strings.Repeat("x", mcpAuditArgsMaxBytes+16)
	payload, redacted := marshalMCPAuditArgs(map[string]interface{}{
		"plan_hash": "sealed-plan",
		"content":   huge,
	})
	if !strings.Contains(payload, `"_truncated":true`) {
		t.Fatalf("expected truncation marker, got %s", payload)
	}
	if redacted["plan_hash"] != "sealed-plan" {
		t.Fatalf("expected plan_hash kept after cap, got %#v", redacted)
	}
}
