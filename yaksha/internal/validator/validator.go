// Package validator checks an inspected EXP contract against request
// parameters without executing the EXP.
package validator

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/TokEat/argus/yaksha/internal/egress"
	"github.com/TokEat/argus/yaksha/internal/inspector"
	"github.com/TokEat/argus/yaksha/internal/protocol"
	"github.com/TokEat/argus/yaksha/internal/resolver"
)

// Result contains the public validation report plus the private CLI argument
// vector used by the engine. CLIArgs never appears in the wire response.
type Result struct {
	Inspection protocol.Inspection
	Validation protocol.Validation
	CLIArgs    []string
	Bundle     *resolver.Bundle
}

// Validate checks source, parameter names/types and protocol-level execution
// limits. It does not compile or execute the source.
func Validate(req protocol.Request) Result {
	return validate(req, true)
}

// ValidateChild validates one already-resolved child EXP without re-validating
// the top-level sealed bundle. The parent validation owns graph integrity.
func ValidateChild(req protocol.Request) Result {
	return validate(req, false)
}

func validate(req protocol.Request, validateResolver bool) Result {
	if err := protocol.ValidateRequest(req); err != nil {
		return Result{Validation: protocol.Validation{
			Checks: []string{"request", "execution_limits"},
			Diagnostics: []protocol.Diagnostic{{
				Severity: "error",
				Code:     "invalid_request",
				Message:  err.Error(),
			}},
		}}
	}
	inspection := inspector.Inspect(req.Script)
	result := Result{
		Inspection: inspection,
		Validation: protocol.Validation{
			SourceSHA256: inspection.SourceSHA256,
			Checks:       []string{"source", "parameters", "execution_limits"},
			Diagnostics:  append([]protocol.Diagnostic(nil), inspection.Diagnostics...),
		},
	}
	if !inspection.Valid {
		return result
	}

	declared := make(map[string]protocol.CLIParameter, len(inspection.Parameters))
	for _, parameter := range inspection.Parameters {
		declared[parameter.Name] = parameter
	}
	unknown := make([]string, 0)
	for name := range req.Params {
		if _, ok := declared[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(unknown)
	for _, name := range unknown {
		addParameterError(&result, name, "unknown_parameter", fmt.Sprintf("parameter %q is not declared by the EXP", name))
	}

	for _, parameter := range inspection.Parameters {
		value, provided := req.Params[parameter.Name]
		if !provided {
			if parameter.Required && !parameter.HasDefault && req.ValidationMode != protocol.ValidationContract {
				addParameterError(&result, parameter.Name, "missing_required_parameter", fmt.Sprintf("required parameter %q is missing", parameter.Name))
				continue
			}
			if parameter.Type == "boolean" && parameter.HasDefault {
				if defaultValue, ok := parameter.Default.(bool); ok && defaultValue {
					result.CLIArgs = append(result.CLIArgs, "--"+parameter.Name)
				}
			}
			continue
		}

		encoded, selectedValues, ok := encodeValue(parameter.Type, value)
		if !ok {
			addParameterError(&result, parameter.Name, "parameter_type_mismatch", fmt.Sprintf("parameter %q must have type %s", parameter.Name, parameter.Type))
			continue
		}
		if parameter.InputType != "" && !protocol.ValidateCLIInputValue(parameter.InputType, encoded) {
			addParameterError(&result, parameter.Name, "parameter_input_mismatch", fmt.Sprintf("parameter %q must match input type %s", parameter.Name, parameter.InputType))
			continue
		}
		if len(parameter.Options) > 0 && !valuesAllowed(selectedValues, parameter.Options) {
			addParameterError(&result, parameter.Name, "parameter_not_in_options", fmt.Sprintf("parameter %q contains a value outside its declared options", parameter.Name))
			continue
		}
		if parameter.Type == "boolean" {
			if encoded == "true" {
				result.CLIArgs = append(result.CLIArgs, "--"+parameter.Name)
			}
			continue
		}
		result.CLIArgs = append(result.CLIArgs, "--"+parameter.Name, encoded)
	}

	if validateResolver {
		bundle, resolverDiagnostics := resolver.Validate(req, inspection)
		result.Bundle = bundle
		result.Validation.Checks = append(result.Validation.Checks, "resolver")
		result.Validation.Diagnostics = append(result.Validation.Diagnostics, resolverDiagnostics...)
	}
	result.Validation.Checks = append(result.Validation.Checks, "network_targets")
	if err := egress.ValidateTargets(req.NetworkTargets); err != nil {
		result.Validation.Diagnostics = append(result.Validation.Diagnostics, protocol.Diagnostic{Severity: "error", Code: "invalid_network_target", Message: err.Error(), Line: 1, Column: 1})
	}

	result.Validation.Valid = !hasErrors(result.Validation.Diagnostics)
	return result
}

func encodeValue(schemaType string, value any) (encoded string, selectedValues []string, ok bool) {
	switch schemaType {
	case "string", "text":
		text, ok := value.(string)
		return text, nil, ok
	case "integer":
		integer, ok := asInt64(value)
		if !ok {
			return "", nil, false
		}
		return strconv.FormatInt(integer, 10), nil, true
	case "number":
		number, ok := asFloat64(value)
		if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
			return "", nil, false
		}
		return strconv.FormatFloat(number, 'g', -1, 64), nil, true
	case "boolean":
		boolean, ok := value.(bool)
		if !ok {
			return "", nil, false
		}
		return strconv.FormatBool(boolean), nil, true
	case "string_array":
		values, ok := asStringSlice(value)
		if !ok {
			return "", nil, false
		}
		return strings.Join(values, ","), values, true
	default:
		return "", nil, false
	}
}

func asInt64(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int8:
		return int64(number), true
	case int16:
		return int64(number), true
	case int32:
		return int64(number), true
	case int64:
		return number, true
	case uint:
		if uint64(number) <= math.MaxInt64 {
			return int64(number), true
		}
	case uint8:
		return int64(number), true
	case uint16:
		return int64(number), true
	case uint32:
		return int64(number), true
	case uint64:
		if number <= math.MaxInt64 {
			return int64(number), true
		}
	case float64:
		if number >= float64(math.MinInt64) && number < float64(math.MaxInt64) && math.Trunc(number) == number {
			return int64(number), true
		}
	case json.Number:
		integer, err := number.Int64()
		return integer, err == nil
	}
	return 0, false
}

func asFloat64(value any) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, true
	case float32:
		return float64(number), true
	case json.Number:
		parsed, err := number.Float64()
		return parsed, err == nil
	default:
		integer, ok := asInt64(value)
		return float64(integer), ok
	}
}

func asStringSlice(value any) ([]string, bool) {
	switch values := value.(type) {
	case string:
		if values == "" {
			return []string{}, true
		}
		parts := strings.Split(values, ",")
		for index := range parts {
			parts[index] = strings.TrimSpace(parts[index])
		}
		return parts, true
	case []string:
		return append([]string(nil), values...), true
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			result = append(result, text)
		}
		return result, true
	default:
		return nil, false
	}
}

func valuesAllowed(values []string, options []protocol.CLIOption) bool {
	allowed := make(map[string]struct{}, len(options))
	for _, option := range options {
		allowed[option.Value] = struct{}{}
	}
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			return false
		}
	}
	return true
}

func addParameterError(result *Result, field, code, message string) {
	result.Validation.Diagnostics = append(result.Validation.Diagnostics, protocol.Diagnostic{
		Severity: "error",
		Code:     code,
		Message:  message,
		Field:    field,
	})
}

func hasErrors(diagnostics []protocol.Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "error" {
			return true
		}
	}
	return false
}
