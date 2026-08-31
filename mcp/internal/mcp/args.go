package mcp

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

func cloneArgs(args map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(args)+1)
	for key, value := range args {
		out[key] = value
	}
	return out
}

func withString(args map[string]interface{}, key, value string) map[string]interface{} {
	out := cloneArgs(args)
	out[key] = value
	return out
}

func stringArg(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	if value, ok := args[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func intArgDefault(args map[string]interface{}, key string, fallback int) int {
	if value, ok := numberArg(args, key); ok {
		return value
	}
	return fallback
}

func boolArg(args map[string]interface{}, key string) bool {
	if args == nil {
		return false
	}
	switch value := args[key].(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "on":
			return true
		default:
			return false
		}
	default:
		if n, ok := intFromAny(value); ok {
			return n == 1
		}
		return false
	}
}

func hasArg(args map[string]interface{}, key string) bool {
	if args == nil {
		return false
	}
	_, ok := args[key]
	return ok
}

func numberArg(args map[string]interface{}, key string) (int, bool) {
	if args == nil {
		return 0, false
	}
	return intFromAny(args[key])
}

func intFromAny(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		converted := int(v)
		return converted, int64(converted) == v
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v {
			return 0, false
		}
		converted := int(v)
		return converted, float64(converted) == v
	case json.Number:
		i, err := v.Int64()
		converted := int(i)
		return converted, err == nil && int64(converted) == i
	default:
		return 0, false
	}
}

func mapString(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key]; ok && value != nil {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func firstPresent(values map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
