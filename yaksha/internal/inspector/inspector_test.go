package inspector

import (
	"testing"

	"github.com/TokEat/argus/yaksha/internal/protocol"
)

func TestInspectExtractsSupportedCLISchemaWithoutExecution(t *testing.T) {
	source := `
target = cli.String("target",
    cli.setVerboseName("目标地址"),
    cli.setHelp("授权测试目标"),
	cli.setInputType("url"),
    cli.setRequired(true),
    cli.setDefault("https://example.invalid"),
    cli.setCliGroup("目标"),
)
notes = cli.Text("notes")
threads = cli.Int("threads", cli.setDefault(5))
port = cli.Integer("port", cli.setDefault(443))
ratio = cli.Float("ratio", cli.setDefault(1.5))
verify = cli.Bool("verify", cli.setDefault(true))
	methods = cli.StringSlice("methods",
    cli.setSelectOption("GET", "GET"),
    cli.setSelectOption("POST", "POST"),
    cli.setMultipleSelect(true),
	    cli.setDefault("GET,POST"),
)
cli.check()
panic("inspect must not execute source")
`

	inspection := Inspect(source)
	if !inspection.Valid {
		t.Fatalf("inspection invalid: %#v", inspection.Diagnostics)
	}
	if inspection.SourceSHA256 == "" || inspection.SourceBytes != len(source) || inspection.SourceLines < 2 {
		t.Fatalf("unexpected source summary: %#v", inspection)
	}
	if len(inspection.Parameters) != 7 {
		t.Fatalf("parameters=%d, want 7: %#v", len(inspection.Parameters), inspection.Parameters)
	}
	target := inspection.Parameters[0]
	if target.Name != "target" || target.Type != "string" || !target.Required || !target.HasDefault || target.Default != "https://example.invalid" {
		t.Fatalf("unexpected target schema: %#v", target)
	}
	if target.VerboseName != "目标地址" || target.Help != "授权测试目标" || target.Group != "目标" || target.InputType != "url" {
		t.Fatalf("unexpected target UI metadata: %#v", target)
	}
	methods := inspection.Parameters[6]
	if methods.Type != "string_array" || !methods.MultipleSelect || len(methods.Options) != 2 || !methods.HasDefault {
		t.Fatalf("unexpected methods schema: %#v", methods)
	}
	defaultValues, ok := methods.Default.(string)
	if !ok || defaultValues != "GET,POST" {
		t.Fatalf("unexpected methods default: %#v", methods.Default)
	}
}

func TestInspectReturnsSyntaxDiagnostics(t *testing.T) {
	inspection := Inspect("target = cli.String(\"target\"\ncli.check()")
	if inspection.Valid {
		t.Fatal("invalid syntax reported as valid")
	}
	if !hasCode(inspection, "syntax_error") {
		t.Fatalf("missing syntax diagnostic: %#v", inspection.Diagnostics)
	}
	if inspection.Diagnostics[0].Line < 1 || inspection.Diagnostics[0].Column < 1 {
		t.Fatalf("diagnostic position is not one-based: %#v", inspection.Diagnostics[0])
	}
}

func TestInspectExtractsLiteralResolverReferences(t *testing.T) {
	inspection := Inspect(`cli.check(); result, err = yaksha.call("child", 3, {"x": 1}); value, assetErr = yaksha.asset("payload")`)
	if !inspection.Valid || len(inspection.Dependencies) != 1 || len(inspection.AssetRefs) != 1 {
		t.Fatalf("inspection=%#v", inspection)
	}
	if inspection.Dependencies[0].ExpID != "child" || inspection.Dependencies[0].Revision != 3 || inspection.AssetRefs[0].AssetID != "payload" {
		t.Fatalf("inspection=%#v", inspection)
	}
}

func TestInspectExtractsStaticControlAndDataFlow(t *testing.T) {
	source := `
target = cli.String("target", cli.setInputType("url"))
cli.check()
response, request_err = yaksha.httpRequest({"url": target})
matched, match_err = yaksha.regexMatch("ready", yaksha.toString(response))
if request_err != nil || match_err != nil || !matched {
    panic("probe failed")
}
yaksha.evidence("matched", matched)
yaksha.result({"vulnerable": matched})
`
	inspection := Inspect(source)
	if !inspection.Valid {
		t.Fatalf("inspection invalid: %#v", inspection.Diagnostics)
	}
	if len(inspection.ControlFlow) < 6 {
		t.Fatalf("control flow too short: %#v", inspection.ControlFlow)
	}
	request := inspection.ControlFlow[0]
	if request.Operation != "yaksha.httpRequest" || !containsAll(request.Inputs, "target") || !containsAll(request.Outputs, "response", "request_err") {
		t.Fatalf("unexpected request step: %#v", request)
	}
	match := inspection.ControlFlow[1]
	if match.Operation != "yaksha.regexMatch" || !containsAll(match.Inputs, "response") || !containsAll(match.Outputs, "matched", "match_err") || !containsAll(match.DependsOn, request.ID) {
		t.Fatalf("unexpected match step: %#v", match)
	}
	condition := inspection.ControlFlow[2]
	if condition.Kind != "condition" || !containsAll(condition.Inputs, "request_err", "match_err", "matched") || !containsAll(condition.DependsOn, request.ID, match.ID) {
		t.Fatalf("unexpected condition step: %#v", condition)
	}
}

func TestInspectRejectsDynamicResolverReferences(t *testing.T) {
	inspection := Inspect(`id = "child"; cli.check(); yaksha.call(id, 1, {}); yaksha.asset(id)`)
	if inspection.Valid || !hasCode(inspection, "dynamic_dependency_reference") || !hasCode(inspection, "dynamic_asset_reference") {
		t.Fatalf("inspection=%#v", inspection)
	}
}

func TestInspectEnforcesPublishableV1Contract(t *testing.T) {
	tests := []struct {
		name   string
		source string
		code   string
	}{
		{name: "missing check", source: `target = cli.String("target")`, code: "missing_cli_check"},
		{name: "duplicate check", source: `cli.check(); cli.check()`, code: "duplicate_cli_check"},
		{name: "nested declaration", source: `func declare() { target = cli.String("target") }; cli.check()`, code: "cli_parameter_not_top_level"},
		{name: "declaration after check", source: `cli.check(); target = cli.String("target")`, code: "cli_parameter_after_check"},
		{name: "dynamic name", source: `name = "target"; target = cli.String(name); cli.check()`, code: "cli_parameter_name"},
		{name: "invalid name", source: `target = cli.String("--target"); cli.check()`, code: "invalid_cli_parameter_name"},
		{name: "reserved name", source: `help = cli.Bool("help"); cli.check()`, code: "invalid_cli_parameter_name"},
		{name: "unsupported type", source: `target = cli.File("target"); cli.check()`, code: "unsupported_cli_type"},
		{name: "unsupported option", source: `target = cli.String("target", cli.setShortName("t")); cli.check()`, code: "unsupported_cli_option"},
		{name: "unsupported input type", source: `target = cli.String("target", cli.setInputType("socket")); cli.check()`, code: "unsupported_cli_input_type"},
		{name: "input type on wrong parameter", source: `target = cli.Text("target", cli.setInputType("host_port")); cli.check()`, code: "invalid_cli_option_target"},
		{name: "invalid input default", source: `target = cli.String("target", cli.setInputType("host_port"), cli.setDefault("tcp://host:23")); cli.check()`, code: "invalid_cli_input_default"},
		{name: "option on wrong type", source: `target = cli.String("target", cli.setMultipleSelect(true)); cli.check()`, code: "invalid_cli_option_target"},
		{name: "default type mismatch", source: `threads = cli.Int("threads", cli.setDefault("five")); cli.check()`, code: "invalid_cli_default"},
		{name: "default outside options", source: `methods = cli.StringSlice("methods", cli.setSelectOption("GET", "GET"), cli.setDefault("POST")); cli.check()`, code: "invalid_cli_default_option"},
		{name: "duplicate option", source: `methods = cli.StringSlice("methods", cli.setSelectOption("GET", "GET"), cli.setSelectOption("Get", "GET")); cli.check()`, code: "duplicate_cli_option"},
		{name: "duplicate parameter", source: `a = cli.String("target"); b = cli.String("target"); cli.check()`, code: "duplicate_cli_parameter"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inspection := Inspect(tc.source)
			if inspection.Valid {
				t.Fatalf("invalid contract reported as valid: %#v", inspection)
			}
			if !hasCode(inspection, tc.code) {
				t.Fatalf("missing %q diagnostic: %#v", tc.code, inspection.Diagnostics)
			}
		})
	}
}

func hasCode(inspection protocol.Inspection, code string) bool {
	for _, diagnostic := range inspection.Diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func containsAll(values []string, wants ...string) bool {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	for _, want := range wants {
		if _, ok := set[want]; !ok {
			return false
		}
	}
	return true
}
