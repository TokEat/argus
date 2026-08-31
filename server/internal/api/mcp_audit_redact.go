package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const mcpAuditArgsMaxBytes = 64 * 1024

func redactMCPToolArgs(args map[string]interface{}) map[string]interface{} {
	redacted, _ := redactMCPValue(args, 0).(map[string]interface{})
	if redacted == nil {
		return map[string]interface{}{}
	}
	return redacted
}

func redactMCPValue(value interface{}, depth int) interface{} {
	if depth > 16 {
		return "[truncated]"
	}
	switch v := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, val := range v {
			if mcpAuditKeySensitive(key) {
				out[key] = "[redacted]"
				continue
			}
			out[key] = redactMCPValue(val, depth+1)
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(v))
		for _, item := range v {
			out = append(out, redactMCPValue(item, depth+1))
		}
		return out
	case string:
		return redactMCPStructuredString(v, depth)
	default:
		return v
	}
}

func redactMCPStructuredString(value string, depth int) string {
	if depth > 16 || !strings.Contains(value, ":") {
		return value
	}
	var parsed interface{}
	if err := yaml.Unmarshal([]byte(value), &parsed); err != nil {
		return value
	}
	normalized := normalizeYAMLValue(parsed)
	switch normalized.(type) {
	case map[string]interface{}, []interface{}:
	default:
		return value
	}
	if !mcpStructuredValueHasSensitiveKey(normalized) {
		return value
	}
	redacted := redactMCPValue(normalized, depth+1)
	out, err := yaml.Marshal(redacted)
	if err != nil {
		return value
	}
	return string(out)
}

func normalizeYAMLValue(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, val := range v {
			out[key] = normalizeYAMLValue(val)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, val := range v {
			out[fmt.Sprint(key)] = normalizeYAMLValue(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(v))
		for _, item := range v {
			out = append(out, normalizeYAMLValue(item))
		}
		return out
	default:
		return v
	}
}

func mcpStructuredValueHasSensitiveKey(value interface{}) bool {
	switch v := value.(type) {
	case map[string]interface{}:
		for key, val := range v {
			if mcpAuditKeySensitive(key) || mcpStructuredValueHasSensitiveKey(val) {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if mcpStructuredValueHasSensitiveKey(item) {
				return true
			}
		}
	}
	return false
}

func mcpAuditKeySensitive(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "set-cookie" || lower == "proxy" || lower == "socks5_proxy" {
		return true
	}
	return strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "cookie")
}

func marshalMCPAuditArgs(args map[string]interface{}) (string, map[string]interface{}) {
	redacted := redactMCPToolArgs(args)
	data, err := json.Marshal(redacted)
	if err != nil {
		return "{}", map[string]interface{}{}
	}
	if len(data) > mcpAuditArgsMaxBytes {
		trimmed := map[string]interface{}{
			"_truncated": true,
			"_bytes":     len(data),
		}
		if preview, ok := redacted["plan_hash"]; ok {
			trimmed["plan_hash"] = preview
		}
		if preview, ok := redacted["agent_id"]; ok {
			trimmed["agent_id"] = preview
		}
		data, _ = json.Marshal(trimmed)
		return string(data), trimmed
	}
	return string(data), redacted
}

func mcpAuditLookupString(args map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(stringFromAny(args[key])); value != "" {
			return value
		}
	}
	return ""
}

func stringFromAny(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return ""
	}
}
