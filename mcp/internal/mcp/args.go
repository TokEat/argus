package mcp

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

func stringArg(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	if value, ok := args[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func copyArgs(args map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for key, value := range args {
		out[key] = value
	}
	return out
}

func stringSliceArg(args map[string]interface{}, key string) []string {
	if args == nil {
		return nil
	}
	raw, ok := args[key]
	if !ok {
		return nil
	}
	out := []string{}
	add := func(value interface{}) {
		item := strings.TrimSpace(fmt.Sprint(value))
		if item != "" {
			out = append(out, item)
		}
	}
	switch values := raw.(type) {
	case []interface{}:
		for _, value := range values {
			add(value)
		}
	case []string:
		for _, value := range values {
			add(value)
		}
	case string:
		for _, value := range strings.Split(values, ",") {
			add(value)
		}
	}
	return out
}

func stringSliceFromAny(raw interface{}) []string {
	out := []string{}
	add := func(value interface{}) {
		item := strings.TrimSpace(fmt.Sprint(value))
		if item != "" {
			out = append(out, item)
		}
	}
	switch values := raw.(type) {
	case []interface{}:
		for _, value := range values {
			add(value)
		}
	case []string:
		for _, value := range values {
			add(value)
		}
	case string:
		for _, value := range strings.Split(values, ",") {
			add(value)
		}
	}
	return out
}

func numberArg(args map[string]interface{}, key string) (int, bool) {
	if args == nil {
		return 0, false
	}
	return intFromAny(args[key])
}

func intArgDefault(args map[string]interface{}, key string, fallback int) int {
	if value, ok := numberArg(args, key); ok {
		return value
	}
	return fallback
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

func mapAny(values map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := values[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

func mapInt(values map[string]interface{}, keys ...string) (int, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return intFromAny(value)
		}
	}
	return 0, false
}

func mapBool(values map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			switch v := value.(type) {
			case bool:
				return v
			case string:
				return strings.EqualFold(v, "true")
			default:
				return fmt.Sprint(v) == "1"
			}
		}
	}
	return false
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

func matchesFilter(value, filter string) bool {
	if filter == "" {
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(value)), filter)
}

func appendLimited(items []map[string]interface{}, item map[string]interface{}, limit int) []map[string]interface{} {
	if limit <= 0 || len(items) >= limit {
		return items
	}
	return append(items, item)
}
