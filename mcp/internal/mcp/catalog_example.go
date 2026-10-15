package mcp

import (
	"strings"
)

func exampleCallForTool(name string, schema interface{}) ToolCatalogCallExample {
	return ToolCatalogCallExample{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: ToolCatalogCallExampleParams{
			Name:      name,
			Arguments: exampleArgsFromSchema(schema, 0),
		},
	}
}

func exampleArgsFromSchema(schema interface{}, depth int) map[string]interface{} {
	if depth > 4 {
		return map[string]interface{}{}
	}
	obj := schemaObject(schema)
	props := schemaProperties(obj)
	required := schemaRequired(obj)
	keys := required
	if len(keys) == 0 {
		keys = sortedKeys(props)
	}
	out := map[string]interface{}{}
	requiredSet := map[string]bool{}
	for _, key := range required {
		requiredSet[key] = true
	}
	for _, key := range keys {
		prop, ok := props[key]
		if !ok {
			continue
		}
		propObj := schemaObject(prop)
		if schemaWriteOnly(propObj) && !requiredSet[key] {
			continue
		}
		out[key] = exampleValue(key, prop, depth)
	}
	return out
}

func exampleValue(field string, schema interface{}, depth int) interface{} {
	obj := schemaObject(schema)
	if len(schemaProperties(obj)) == 0 {
		obj = firstSchemaBranch(obj)
	}
	if enums := schemaEnums(obj); len(enums) > 0 {
		return enums[0]
	}
	switch schemaType(obj) {
	case "boolean":
		return false
	case "integer", "number":
		if min, ok := schemaNumber(obj["minimum"]); ok {
			return min
		}
		return 1
	case "array":
		item := exampleValue(field, obj["items"], depth+1)
		return []interface{}{item}
	case "object":
		return exampleArgsFromSchema(obj, depth+1)
	default:
		return exampleString(field)
	}
}

func exampleString(field string) string {
	name := strings.ToLower(strings.TrimSpace(field))
	switch {
	case strings.Contains(name, "url"):
		return "https://authorized.example/"
	case name == "uri":
		return "argus://example"
	default:
		return "<" + field + ">"
	}
}

func firstSchemaBranch(obj map[string]interface{}) map[string]interface{} {
	for _, key := range []string{"oneOf", "anyOf"} {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		switch branches := raw.(type) {
		case []interface{}:
			if len(branches) == 0 {
				continue
			}
			return schemaObject(branches[0])
		}
	}
	return obj
}

func schemaType(obj map[string]interface{}) string {
	switch raw := obj["type"].(type) {
	case string:
		return raw
	case []interface{}:
		for _, value := range raw {
			text, _ := value.(string)
			if text != "" && text != "null" {
				return text
			}
		}
	}
	if _, ok := obj["properties"]; ok {
		return "object"
	}
	if _, ok := obj["items"]; ok {
		return "array"
	}
	if _, ok := obj["enum"]; ok {
		return "string"
	}
	return "string"
}

func schemaWriteOnly(obj map[string]interface{}) bool {
	value, _ := obj["writeOnly"].(bool)
	return value
}

func schemaNumber(raw interface{}) (int, bool) {
	switch value := raw.(type) {
	case int:
		return value, true
	case int64:
		return int(value), true
	case float64:
		return int(value), true
	default:
		return 0, false
	}
}
