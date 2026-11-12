package validator

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/TokEat/argus/yaksha/internal/protocol"
)

const contractSource = `
target = cli.String("target", cli.setRequired(true))
notes = cli.Text("notes", cli.setDefault("none"))
threads = cli.Int("threads", cli.setDefault(5))
ratio = cli.Float("ratio", cli.setDefault(1.5))
verify = cli.Bool("verify", cli.setDefault(true))
methods = cli.StringSlice("methods",
    cli.setSelectOption("GET", "GET"),
    cli.setSelectOption("POST", "POST"),
    cli.setMultipleSelect(true),
)
cli.check()
`

func TestValidateBuildsDeterministicCLIArguments(t *testing.T) {
	result := Validate(protocol.Request{
		Script: contractSource,
		Params: map[string]any{
			"target":  "https://example.invalid",
			"notes":   "authorized",
			"threads": float64(8),
			"ratio":   2,
			"methods": []any{"GET", "POST"},
		},
	})
	if !result.Validation.Valid {
		t.Fatalf("validation failed: %#v", result.Validation.Diagnostics)
	}
	want := []string{
		"--target", "https://example.invalid",
		"--notes", "authorized",
		"--threads", "8",
		"--ratio", "2",
		"--verify",
		"--methods", "GET,POST",
	}
	if !reflect.DeepEqual(result.CLIArgs, want) {
		t.Fatalf("CLIArgs=%#v, want %#v", result.CLIArgs, want)
	}
}

func TestValidateRejectsParameterErrors(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		code   string
		field  string
	}{
		{name: "missing required", params: map[string]any{}, code: "missing_required_parameter", field: "target"},
		{name: "unknown", params: map[string]any{"target": "ok", "extra": true}, code: "unknown_parameter", field: "extra"},
		{name: "wrong integer", params: map[string]any{"target": "ok", "threads": 1.5}, code: "parameter_type_mismatch", field: "threads"},
		{name: "wrong bool", params: map[string]any{"target": "ok", "verify": "yes"}, code: "parameter_type_mismatch", field: "verify"},
		{name: "wrong slice item", params: map[string]any{"target": "ok", "methods": []any{"GET", 1}}, code: "parameter_type_mismatch", field: "methods"},
		{name: "outside options", params: map[string]any{"target": "ok", "methods": []any{"DELETE"}}, code: "parameter_not_in_options", field: "methods"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := Validate(protocol.Request{Script: contractSource, Params: tc.params})
			if result.Validation.Valid {
				t.Fatalf("invalid parameters reported valid: %#v", result)
			}
			if !hasDiagnostic(result.Validation.Diagnostics, tc.code, tc.field) {
				t.Fatalf("missing %s/%s: %#v", tc.code, tc.field, result.Validation.Diagnostics)
			}
		})
	}
}

func TestValidateAppliesDeclaredInputType(t *testing.T) {
	source := `address = cli.String("address", cli.setInputType("host_port"), cli.setRequired(true)); cli.check()`
	valid := Validate(protocol.Request{Script: source, Params: map[string]any{"address": "telnet.internal:23"}})
	if !valid.Validation.Valid {
		t.Fatalf("valid host:port rejected: %#v", valid.Validation.Diagnostics)
	}
	invalid := Validate(protocol.Request{Script: source, Params: map[string]any{"address": "tcp://telnet.internal:23"}})
	if invalid.Validation.Valid || !hasDiagnostic(invalid.Validation.Diagnostics, "parameter_input_mismatch", "address") {
		t.Fatalf("scheme-prefixed host:port accepted: %#v", invalid.Validation.Diagnostics)
	}
}

func TestContractValidationAllowsMissingRuntimeParameters(t *testing.T) {
	result := Validate(protocol.Request{Action: protocol.ActionValidate, ValidationMode: protocol.ValidationContract, Script: contractSource})
	if !result.Validation.Valid {
		t.Fatalf("contract validation failed: %#v", result.Validation.Diagnostics)
	}
	execution := Validate(protocol.Request{Action: protocol.ActionValidate, ValidationMode: protocol.ValidationExecution, Script: contractSource})
	if execution.Validation.Valid || !hasDiagnostic(execution.Validation.Diagnostics, "missing_required_parameter", "target") {
		t.Fatalf("execution validation=%#v", execution.Validation)
	}
}

func TestValidationDoesNotEchoParameterValues(t *testing.T) {
	secret := "secret-value-must-not-be-returned"
	result := Validate(protocol.Request{Script: contractSource, Params: map[string]any{"target": secret}})
	raw, err := json.Marshal(result.Validation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("validation leaked parameter value: %s", raw)
	}
}

func TestValidateIncludesSourceDiagnostics(t *testing.T) {
	result := Validate(protocol.Request{Script: `target = cli.String("target")`})
	if result.Validation.Valid || !hasDiagnostic(result.Validation.Diagnostics, "missing_cli_check", "") {
		t.Fatalf("unexpected validation: %#v", result.Validation)
	}
	if len(result.CLIArgs) != 0 {
		t.Fatalf("invalid source produced CLI args: %#v", result.CLIArgs)
	}
}

func TestValidateAppliesProtocolLimits(t *testing.T) {
	result := Validate(protocol.Request{Script: `cli.check()`, TimeoutMS: protocol.MaxTimeoutMS + 1})
	if result.Validation.Valid || !hasDiagnostic(result.Validation.Diagnostics, "invalid_request", "") {
		t.Fatalf("unexpected validation: %#v", result.Validation)
	}
}

func hasDiagnostic(diagnostics []protocol.Diagnostic, code, field string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code && diagnostic.Field == field {
			return true
		}
	}
	return false
}
