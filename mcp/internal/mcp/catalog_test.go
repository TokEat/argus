package mcp

import (
	"strings"
	"testing"
	"unicode"
)

func TestToolCatalogMirrorsRuntimeTools(t *testing.T) {
	runtime := tools()
	catalog := ToolCatalog()
	if len(catalog) != len(runtime) {
		t.Fatalf("catalog len=%d tools len=%d", len(catalog), len(runtime))
	}
	seen := map[string]bool{}
	for i, tool := range runtime {
		item := catalog[i]
		if item.Name != tool.Name {
			t.Fatalf("index %d name=%s want %s", i, item.Name, tool.Name)
		}
		if item.Title != tool.Title {
			t.Fatalf("%s title=%q want %q", tool.Name, item.Title, tool.Title)
		}
		if item.Description != tool.Description {
			t.Fatalf("%s description diverged from tools()", tool.Name)
		}
		if item.Category == "" {
			t.Fatalf("%s missing category", tool.Name)
		}
		if item.ExampleCall.JSONRPC != "2.0" || item.ExampleCall.Method != "tools/call" {
			t.Fatalf("%s example_call %#v", tool.Name, item.ExampleCall)
		}
		if item.ExampleCall.Params.Name != tool.Name {
			t.Fatalf("%s example name=%s", tool.Name, item.ExampleCall.Params.Name)
		}
		if item.ExampleCall.Params.Arguments == nil {
			t.Fatalf("%s example arguments nil", tool.Name)
		}
		if seen[item.Name] {
			t.Fatalf("duplicate %s", item.Name)
		}
		seen[item.Name] = true
		assertExampleArgsMatchSchema(t, tool.Name, tool.InputSchema, item.ExampleCall.Params.Arguments)
	}
}

func TestToolCatalogCategoryFollowsNamePrefix(t *testing.T) {
	for _, item := range ToolCatalog() {
		got := toolCategory(item.Name)
		if item.Category != got {
			t.Fatalf("%s category=%s helper=%s", item.Name, item.Category, got)
		}
		switch {
		case strings.HasPrefix(item.Name, "argus_debug_") && item.Category != ToolCategoryDebug:
			t.Fatalf("%s", item.Name)
		case strings.HasPrefix(item.Name, "argus_save_") && item.Category != ToolCategoryDraft:
			t.Fatalf("%s", item.Name)
		case strings.HasPrefix(item.Name, "argus_scan_") && item.Category != ToolCategoryScan:
			t.Fatalf("%s", item.Name)
		}
	}
}

func TestToolCatalogAuditFlagsMatchAuditableToolAction(t *testing.T) {
	for _, item := range ToolCatalog() {
		always, alwaysOK := AuditableToolAction(item.Name, nil)
		if alwaysOK {
			if !item.Auditable || item.AuditWhen != "" {
				t.Fatalf("%s always-auditable catalog %#v action=%q", item.Name, item, always)
			}
			continue
		}
		var want []string
		for _, value := range schemaEnumValues(item.InputSchema, "action") {
			if label, ok := AuditableToolAction(item.Name, map[string]interface{}{"action": value}); ok {
				if strings.TrimSpace(label) == "" {
					label = value
				}
				want = append(want, label)
			}
		}
		if len(want) == 0 {
			if item.Auditable || item.AuditWhen != "" {
				t.Fatalf("unexpected audit flag %#v", item)
			}
			continue
		}
		if !item.Auditable || item.AuditWhen != strings.Join(want, ",") {
			t.Fatalf("%s catalog %#v want %s", item.Name, item, strings.Join(want, ","))
		}
	}
}

func TestExampleArgsFromSchemaUsesRequiredAndEnum(t *testing.T) {
	schema := objectSchema(map[string]interface{}{
		"action": enumSchema([]string{"publish", "deprecate"}),
		"name":   stringSchema("optional"),
	}, []string{"action"})
	args := exampleArgsFromSchema(schema, 0)
	if args["action"] != "publish" {
		t.Fatalf("enum example: %#v", args)
	}
	if _, ok := args["name"]; ok {
		t.Fatalf("optional field should be omitted when required is set: %#v", args)
	}
}

func TestExampleArgsFromSchemaSkipsOptionalWriteOnly(t *testing.T) {
	schema := objectSchema(map[string]interface{}{
		"name":   stringSchema("visible"),
		"secret": map[string]interface{}{"type": "string", "writeOnly": true},
	}, nil)
	args := exampleArgsFromSchema(schema, 0)
	if args["name"] != "<name>" {
		t.Fatalf("%#v", args)
	}
	if _, ok := args["secret"]; ok {
		t.Fatalf("writeOnly leaked: %#v", args)
	}
}

func TestToolCatalogExampleHasNoSecrets(t *testing.T) {
	for _, item := range ToolCatalog() {
		blob := strings.ToLower(item.Description + item.Title)
		if strings.Contains(blob, "sk-") {
			t.Fatalf("catalog copy must not include secrets: %s", item.Name)
		}
		for _, value := range item.ExampleCall.Params.Arguments {
			text, _ := value.(string)
			if strings.Contains(strings.ToLower(text), "sk-") || looksLikeSecretPlaceholder(text) {
				t.Fatalf("%s example leaked secret-like value %#v", item.Name, value)
			}
		}
	}
}

func TestToolTitlesPreferChinese(t *testing.T) {
	for _, tool := range tools() {
		if strings.TrimSpace(tool.Title) == "" {
			t.Fatalf("%s missing Title for admin catalog", tool.Name)
		}
		if !hasHan(tool.Title) {
			t.Fatalf("%s Title should be Chinese: %q", tool.Name, tool.Title)
		}
	}
}

func assertExampleArgsMatchSchema(t *testing.T, name string, schema interface{}, args map[string]interface{}) {
	t.Helper()
	props := schemaProperties(schemaObject(schema))
	required := schemaRequired(schemaObject(schema))
	for _, key := range required {
		if _, ok := args[key]; !ok {
			t.Fatalf("%s missing required example field %s", name, key)
		}
	}
	for key := range args {
		if _, ok := props[key]; !ok {
			t.Fatalf("%s example field %s is not in input schema", name, key)
		}
	}
}

func hasHan(value string) bool {
	for _, r := range value {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func looksLikeSecretPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "password=") || strings.Contains(lower, "token=")
}
