package mcp

import (
	"sort"
	"strings"
)

const (
	ToolCategoryRead    = "read"
	ToolCategoryDebug   = "debug"
	ToolCategoryDraft   = "draft"
	ToolCategoryPublish = "publish"
	ToolCategoryScan    = "scan"
	ToolCategoryExp     = "exp"
)

// ToolCatalogCallExample is a generated MCP JSON-RPC tools/call sketch.
type ToolCatalogCallExample struct {
	JSONRPC string                       `json:"jsonrpc"`
	ID      int                          `json:"id"`
	Method  string                       `json:"method"`
	Params  ToolCatalogCallExampleParams `json:"params"`
}

// ToolCatalogCallExampleParams is the tools/call params object.
type ToolCatalogCallExampleParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ToolCatalogEntry is a read-only admin projection of one runtime MCP tool.
// Values come from tools() / AuditableToolAction; this type does not keep a
// parallel list of names, copy, or argument examples.
type ToolCatalogEntry struct {
	Name        string                 `json:"name"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Auditable   bool                   `json:"auditable"`
	AuditWhen   string                 `json:"audit_when,omitempty"`
	InputSchema interface{}            `json:"input_schema,omitempty"`
	ExampleCall ToolCatalogCallExample `json:"example_call"`
}

// ToolCatalog returns the current runtime tool list for admin display.
func ToolCatalog() []ToolCatalogEntry {
	items := tools()
	out := make([]ToolCatalogEntry, 0, len(items))
	for _, tool := range items {
		if tool == nil || strings.TrimSpace(tool.Name) == "" {
			continue
		}
		auditable, when := toolAuditMeta(tool.Name, tool.InputSchema)
		out = append(out, ToolCatalogEntry{
			Name:        tool.Name,
			Title:       tool.Title,
			Description: tool.Description,
			Category:    toolCategory(tool.Name),
			Auditable:   auditable,
			AuditWhen:   when,
			InputSchema: tool.InputSchema,
			ExampleCall: exampleCallForTool(tool.Name, tool.InputSchema),
		})
	}
	return out
}

func toolCategory(name string) string {
	switch {
	case strings.HasPrefix(name, "argus_debug_"):
		return ToolCategoryDebug
	case strings.HasPrefix(name, "argus_save_"):
		return ToolCategoryDraft
	case strings.HasPrefix(name, "argus_scan_"):
		return ToolCategoryScan
	case strings.HasPrefix(name, "argus_yaksha_") || strings.HasPrefix(name, "argus_exp_"):
		return ToolCategoryExp
	case name == "argus_rule_apply":
		return ToolCategoryPublish
	default:
		return ToolCategoryRead
	}
}

func toolAuditMeta(name string, schema interface{}) (auditable bool, when string) {
	if _, ok := AuditableToolAction(name, nil); ok {
		return true, ""
	}
	var actions []string
	for _, value := range schemaEnumValues(schema, "action") {
		label, ok := AuditableToolAction(name, map[string]interface{}{"action": value})
		if !ok {
			continue
		}
		if strings.TrimSpace(label) == "" {
			label = value
		}
		actions = append(actions, label)
	}
	if len(actions) == 0 {
		return false, ""
	}
	return true, strings.Join(actions, ",")
}

func schemaEnumValues(schema interface{}, field string) []string {
	obj := schemaObject(schema)
	props := schemaProperties(obj)
	prop, ok := props[field]
	if !ok {
		return nil
	}
	return schemaEnums(schemaObject(prop))
}

func schemaEnums(prop map[string]interface{}) []string {
	raw, ok := prop["enum"]
	if !ok {
		return nil
	}
	switch values := raw.(type) {
	case []string:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				out = append(out, value)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(values))
		for _, value := range values {
			text, _ := value.(string)
			if strings.TrimSpace(text) != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func schemaObject(schema interface{}) map[string]interface{} {
	obj, _ := schema.(map[string]interface{})
	if obj == nil {
		return map[string]interface{}{}
	}
	return obj
}

func schemaProperties(obj map[string]interface{}) map[string]interface{} {
	props, _ := obj["properties"].(map[string]interface{})
	if props == nil {
		return map[string]interface{}{}
	}
	return props
}

func schemaRequired(obj map[string]interface{}) []string {
	switch raw := obj["required"].(type) {
	case []string:
		return append([]string{}, raw...)
	case []interface{}:
		out := make([]string, 0, len(raw))
		for _, value := range raw {
			text, _ := value.(string)
			if strings.TrimSpace(text) != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func sortedKeys(props map[string]interface{}) []string {
	keys := make([]string, 0, len(props))
	for key := range props {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
