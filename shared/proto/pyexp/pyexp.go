package pyexp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const RuntimeEngine = "python"

var AllowedCapabilities = map[string]bool{
	"http.request":   true,
	"tcp.connect":    true,
	"evidence.write": true,
	"cleanup.defer":  true,
	"result.write":   true,
}

var ValidRiskLevels = map[string]bool{
	"low":         true,
	"medium":      true,
	"high":        true,
	"destructive": true,
}

var ValidParamTypes = map[string]bool{
	"string":  true,
	"int":     true,
	"integer": true,
	"float":   true,
	"number":  true,
	"bool":    true,
	"boolean": true,
	"json":    true,
	"object":  true,
	"array":   true,
}

type Param struct {
	Type        string        `json:"type"`
	Required    bool          `json:"required"`
	Default     interface{}   `json:"default,omitempty"`
	Description string        `json:"description,omitempty"`
	Enum        []interface{} `json:"enum,omitempty"`
	Example     interface{}   `json:"example,omitempty"`
	Pattern     string        `json:"pattern,omitempty"`
	Min         *float64      `json:"min,omitempty"`
	Max         *float64      `json:"max,omitempty"`
	Format      string        `json:"format,omitempty"`
	Sensitive   bool          `json:"sensitive,omitempty"`
	Source      string        `json:"source,omitempty"`
	Flag        string        `json:"flag,omitempty"`
	Position    int           `json:"position,omitempty"`
	Placeholder string        `json:"placeholder,omitempty"`
	ValueName   string        `json:"value_name,omitempty"`
}

type Policy struct {
	RequiresAuth     bool     `json:"requires_auth"`
	CleanupSupported bool     `json:"cleanup_supported"`
	CleanupRequired  bool     `json:"cleanup_required"`
	DryRunSupported  bool     `json:"dry_run_supported"`
	TimeoutSec       int      `json:"timeout_sec"`
	Capabilities     []string `json:"capabilities"`
	SideEffects      []string `json:"side_effects"`
}

type Template struct {
	ID               string
	Name             string
	Description      string
	TargetProduct    string
	CVE              string
	LinkedPocs       []string
	RiskLevel        string
	Policy           Policy
	Params           map[string]Param
	Requirements     []string
	RequirementsHash string
	RuntimeEngine    string
	Script           string
	HasRun           bool
	HasCleanup       bool
	HasMain          bool
}

func ParseTemplate(content []byte) (*Template, error) {
	source := string(content)
	if strings.Contains(source, "kind: argus-exp/") {
		return nil, fmt.Errorf("YAML EXP packages are no longer supported; use a Python .py EXP")
	}
	literal, err := extractArgusExpLiteral(source)
	if err != nil {
		return nil, err
	}
	root, ok := literal.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("ARGUS_EXP must be a dict literal")
	}
	params := paramMapField(root, "params")
	for name, inferred := range InferRuntimeParams(source) {
		if existing, exists := params[name]; exists {
			params[name] = mergeExplicitParam(existing, inferred)
		} else {
			params[name] = inferred
		}
	}
	tmpl := &Template{
		ID:            stringField(root, "id"),
		Name:          stringField(root, "name"),
		Description:   stringField(root, "description"),
		TargetProduct: stringField(root, "target_product"),
		CVE:           stringField(root, "cve"),
		LinkedPocs:    stringSliceField(root, "linked_pocs"),
		RiskLevel:     strings.ToLower(stringField(root, "risk_level")),
		Params:        params,
		Requirements:  stringSliceField(root, "requirements"),
		RuntimeEngine: RuntimeEngine,
		Script:        source,
	}
	tmpl.Policy = policyField(root, "policy")
	if tmpl.Policy.TimeoutSec <= 0 {
		tmpl.Policy.TimeoutSec = 60
	}
	if tmpl.RiskLevel == "" {
		tmpl.RiskLevel = "medium"
	}
	tmpl.RequirementsHash = RequirementsHash(tmpl.Requirements)
	tmpl.HasRun = hasTopLevelFunction(source, "run")
	tmpl.HasCleanup = hasTopLevelFunction(source, "cleanup")
	tmpl.HasMain = hasTopLevelFunctionAnyArgs(source, "main")
	return tmpl, nil
}

func Validate(content []byte, strict bool) error {
	tmpl, err := ParseTemplate(content)
	if err != nil {
		return err
	}
	if strings.TrimSpace(tmpl.ID) == "" {
		return fmt.Errorf("ARGUS_EXP.id is required")
	}
	if strings.TrimSpace(tmpl.Name) == "" {
		return fmt.Errorf("ARGUS_EXP.name is required")
	}
	if !ValidRiskLevels[tmpl.RiskLevel] {
		return fmt.Errorf("invalid ARGUS_EXP.risk_level %q", tmpl.RiskLevel)
	}
	for name, param := range tmpl.Params {
		if !validParamNamePattern.MatchString(name) {
			return fmt.Errorf("ARGUS_EXP.params.%s name must match [A-Za-z_][A-Za-z0-9_]*", name)
		}
		paramType := strings.ToLower(strings.TrimSpace(param.Type))
		if paramType == "" {
			return fmt.Errorf("ARGUS_EXP.params.%s.type is required", name)
		}
		if !ValidParamTypes[paramType] {
			return fmt.Errorf("ARGUS_EXP.params.%s.type %q is not supported", name, param.Type)
		}
		if param.Pattern != "" {
			if _, err := regexp.Compile(param.Pattern); err != nil {
				return fmt.Errorf("ARGUS_EXP.params.%s.pattern is invalid: %w", name, err)
			}
		}
		if param.Min != nil && param.Max != nil && *param.Min > *param.Max {
			return fmt.Errorf("ARGUS_EXP.params.%s.min must be <= max", name)
		}
		if param.Default != nil {
			if _, err := normalizeParamValue(name, paramType, param.Default); err != nil {
				return fmt.Errorf("ARGUS_EXP.params.%s.default %v", name, err)
			}
		}
		for _, item := range param.Enum {
			if _, err := normalizeParamValue(name, paramType, item); err != nil {
				return fmt.Errorf("ARGUS_EXP.params.%s.enum value %v", name, err)
			}
		}
	}
	if !tmpl.HasRun && !tmpl.HasMain {
		return fmt.Errorf("Python EXP must define run(ctx) or main()")
	}
	if tmpl.Policy.CleanupRequired && !tmpl.HasCleanup {
		return fmt.Errorf("cleanup_required=true but cleanup(ctx) is not defined")
	}
	for _, req := range tmpl.Requirements {
		if err := ValidateRequirement(req); err != nil {
			return err
		}
	}
	return nil
}

func RequirementsHash(requirements []string) string {
	if len(requirements) == 0 {
		return ""
	}
	normalized := append([]string(nil), requirements...)
	sort.Strings(normalized)
	sum := sha256.Sum256([]byte(strings.Join(normalized, "\n")))
	return hex.EncodeToString(sum[:])
}

var requirementPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+\-]+(?:\s+--hash=sha256:[a-fA-F0-9]{64})+$`)
var validParamNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func ValidateRequirement(req string) error {
	req = strings.TrimSpace(req)
	if req == "" {
		return fmt.Errorf("empty requirement is not allowed")
	}
	if !requirementPattern.MatchString(req) {
		return fmt.Errorf("requirement %q must pin version with == and include --hash=sha256:<64 hex>", req)
	}
	return nil
}

func ParamSchema(params map[string]Param) map[string]interface{} {
	out := make(map[string]interface{}, len(params))
	for key, param := range params {
		def := map[string]interface{}{
			"type":        normalizeParamType(param.Type),
			"required":    param.Required,
			"description": param.Description,
		}
		if param.Default != nil && !param.Sensitive {
			def["default"] = param.Default
		}
		if len(param.Enum) > 0 {
			def["enum"] = param.Enum
		}
		if param.Example != nil {
			def["example"] = param.Example
		}
		if param.Pattern != "" {
			def["pattern"] = param.Pattern
		}
		if param.Min != nil {
			def["min"] = *param.Min
		}
		if param.Max != nil {
			def["max"] = *param.Max
		}
		if param.Format != "" {
			def["format"] = param.Format
		}
		if param.Sensitive {
			def["sensitive"] = true
		}
		if param.Source != "" {
			def["source"] = param.Source
		}
		if param.Flag != "" {
			def["flag"] = param.Flag
		}
		if param.Position > 0 {
			def["position"] = param.Position
		}
		if param.Placeholder != "" {
			def["placeholder"] = param.Placeholder
		}
		if param.ValueName != "" {
			def["value_name"] = param.ValueName
		}
		out[key] = def
	}
	return out
}

// NormalizeRuntimeParams applies the ARGUS_EXP params schema to user-provided
// execution parameters. It is the single runtime contract for dry-run, debug,
// formal execution and cleanup dispatch.
func NormalizeRuntimeParams(schema map[string]interface{}, params map[string]interface{}) (map[string]interface{}, []string) {
	if params == nil {
		params = map[string]interface{}{}
	}
	if len(schema) == 0 {
		return copyParams(params), nil
	}
	errs := []string{}
	out := map[string]interface{}{}
	for key := range params {
		if _, exists := schema[key]; !exists {
			errs = append(errs, fmt.Sprintf("param %q is not declared in ARGUS_EXP.params", key))
		}
	}
	for key, raw := range schema {
		def, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		paramType := normalizeParamType(stringField(def, "type"))
		required, _ := def["required"].(bool)
		value, provided := params[key]
		if !provided || value == nil {
			if defaultValue, hasDefault := def["default"]; hasDefault {
				value = defaultValue
			} else {
				if required {
					errs = append(errs, fmt.Sprintf("param %q is required", key))
				}
				continue
			}
		}
		normalized, err := normalizeParamValue(key, paramType, value)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		errs = append(errs, validateParamConstraints(key, paramType, normalized, def)...)
		out[key] = normalized
	}
	if len(errs) > 0 {
		return out, errs
	}
	return out, nil
}

func copyParams(params map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(params))
	for key, value := range params {
		out[key] = value
	}
	return out
}

// InferRuntimeParams recognizes lightweight CLI-style Python scripts such as:
//
//	用法:
//	  python3 script.py <payload>
//	  python3 script.py --file Payload.class
//
// It also scans simple sys.argv patterns so generated EXPs can expose runtime
// params without maintaining a second parameter list by hand. Explicit
// ARGUS_EXP.params entries always win when ParseTemplate merges the result.
func InferRuntimeParams(source string) map[string]Param {
	out := map[string]Param{}
	mergeParamMap(out, inferArgparseParams(source))
	mergeParamMap(out, inferUsageParams(source))
	mergeParamMap(out, inferSysArgvParams(source))
	return out
}

func inferArgparseParams(source string) map[string]Param {
	constants := inferPythonConstants(source)
	out := map[string]Param{}
	positionalIndex := 0
	for _, call := range extractFunctionCalls(source, "add_argument") {
		args := splitTopLevelArgs(call)
		optionFlags := []string{}
		positionalName := ""
		keywords := map[string]string{}
		for _, arg := range args {
			name, value, ok := splitKeywordArg(arg)
			if ok {
				keywords[name] = value
				continue
			}
			if text, ok := parseLiteralString(arg, constants); ok {
				if strings.HasPrefix(text, "-") {
					optionFlags = append(optionFlags, text)
				} else if positionalName == "" {
					positionalName = text
				}
			}
		}
		if len(optionFlags) == 0 && positionalName == "" {
			continue
		}
		name := ""
		if dest, ok := parseLiteralString(keywords["dest"], constants); ok && dest != "" {
			name = dest
		}
		flag := ""
		position := 0
		if len(optionFlags) > 0 {
			flag = preferredCLIFlag(optionFlags)
			if name == "" {
				name = strings.TrimLeft(flag, "-")
			}
		} else {
			positionalIndex++
			position = positionalIndex
			if name == "" {
				name = positionalName
			}
		}
		name = sanitizeParamName(name, fmt.Sprintf("arg%d", len(out)+1))
		paramType := "string"
		if rawType, ok := keywords["type"]; ok {
			paramType = argparseTypeName(rawType)
		}
		if action, ok := parseLiteralString(keywords["action"], constants); ok {
			switch action {
			case "store_true":
				paramType = "bool"
			case "store_false":
				paramType = "bool"
			}
		}
		placeholder := literalStringOrEmpty(keywords["metavar"], constants)
		if placeholder == "" && position > 0 {
			placeholder = positionalName
		}
		required := boolLiteral(keywords["required"])
		if position > 0 {
			required = true
			if nargs, ok := parseLiteralString(keywords["nargs"], constants); ok && (nargs == "?" || nargs == "*") {
				required = false
			}
		}
		param := Param{
			Type:        paramType,
			Required:    required,
			Description: literalStringOrEmpty(keywords["help"], constants),
			Source:      "argparse",
			Flag:        flag,
			Position:    position,
			Placeholder: placeholder,
			ValueName:   placeholder,
			Sensitive:   isSensitiveParamName(name),
		}
		if choices := literalStringList(keywords["choices"], constants); len(choices) > 0 {
			param.Enum = make([]interface{}, 0, len(choices))
			for _, choice := range choices {
				param.Enum = append(param.Enum, choice)
			}
		}
		if defaultValue, ok := parseLiteralValue(keywords["default"], constants); ok {
			if !param.Sensitive {
				param.Default = defaultValue
			}
		} else if action, ok := parseLiteralString(keywords["action"], constants); ok {
			if action == "store_true" && !param.Sensitive {
				param.Default = false
			} else if action == "store_false" && !param.Sensitive {
				param.Default = true
			}
		}
		out[name] = param
	}
	for _, name := range inferArgparseRequiredNames(source) {
		if param, ok := out[name]; ok {
			param.Required = true
			out[name] = param
		}
	}
	return out
}

func inferPythonConstants(source string) map[string]interface{} {
	constants := map[string]interface{}{}
	pattern := regexp.MustCompile(`(?m)^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.+?)\s*$`)
	for _, match := range pattern.FindAllStringSubmatch(source, -1) {
		if value, ok := parseLiteralValue(match[2], constants); ok {
			constants[match[1]] = value
		}
	}
	return constants
}

func extractFunctionCalls(source, name string) []string {
	calls := []string{}
	needle := "." + name + "("
	for offset := 0; offset < len(source); {
		idx := strings.Index(source[offset:], needle)
		if idx < 0 {
			break
		}
		open := offset + idx + len(needle) - 1
		if body, end, ok := extractParenBody(source, open); ok {
			calls = append(calls, body)
			offset = end + 1
		} else {
			offset = open + 1
		}
	}
	return calls
}

func extractParenBody(source string, open int) (string, int, bool) {
	if open < 0 || open >= len(source) || source[open] != '(' {
		return "", open, false
	}
	depth := 0
	inString := byte(0)
	triple := false
	escaped := false
	for i := open; i < len(source); i++ {
		ch := source[i]
		if inString != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if triple {
				if ch == inString && i+2 < len(source) && source[i+1] == inString && source[i+2] == inString {
					inString = 0
					triple = false
					i += 2
				}
				continue
			}
			if ch == inString {
				inString = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inString = ch
			triple = i+2 < len(source) && source[i+1] == ch && source[i+2] == ch
			if triple {
				i += 2
			}
			continue
		}
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 {
				return source[open+1 : i], i, true
			}
		}
	}
	return "", open, false
}

func splitTopLevelArgs(raw string) []string {
	args := []string{}
	start := 0
	depth := 0
	inString := byte(0)
	escaped := false
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if inString != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == inString {
				inString = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inString = ch
			continue
		}
		switch ch {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				if item := strings.TrimSpace(raw[start:i]); item != "" {
					args = append(args, item)
				}
				start = i + 1
			}
		}
	}
	if item := strings.TrimSpace(raw[start:]); item != "" {
		args = append(args, item)
	}
	return args
}

func splitKeywordArg(arg string) (string, string, bool) {
	depth := 0
	inString := byte(0)
	escaped := false
	for i := 0; i < len(arg); i++ {
		ch := arg[i]
		if inString != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == inString {
				inString = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inString = ch
			continue
		}
		switch ch {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '=':
			if depth == 0 {
				name := strings.TrimSpace(arg[:i])
				if validParamNamePattern.MatchString(name) {
					return name, strings.TrimSpace(arg[i+1:]), true
				}
			}
		}
	}
	return "", "", false
}

func preferredCLIFlag(flags []string) string {
	for _, flag := range flags {
		if strings.HasPrefix(flag, "--") {
			return flag
		}
	}
	return flags[0]
}

func argparseTypeName(raw string) string {
	raw = strings.TrimSpace(raw)
	switch raw {
	case "int":
		return "int"
	case "float":
		return "number"
	case "bool":
		return "bool"
	default:
		return "string"
	}
}

func inferArgparseRequiredNames(source string) []string {
	out := []string{}
	pattern := regexp.MustCompile(`if\s+not\s+args\.([A-Za-z_][A-Za-z0-9_]*)\s*:\s*\n\s*parser\.error\(`)
	for _, match := range pattern.FindAllStringSubmatch(source, -1) {
		out = append(out, match[1])
	}
	return out
}

func boolLiteral(raw string) bool {
	switch strings.TrimSpace(raw) {
	case "True", "true":
		return true
	default:
		return false
	}
}

func literalStringOrEmpty(raw string, constants map[string]interface{}) string {
	value, _ := parseLiteralString(raw, constants)
	return value
}

func parseLiteralString(raw string, constants map[string]interface{}) (string, bool) {
	value, ok := parseLiteralValue(raw, constants)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func parseLiteralValue(raw string, constants map[string]interface{}) (interface{}, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	if value, ok := constants[raw]; ok {
		return value, true
	}
	if strings.HasPrefix(raw, "f\"") || strings.HasPrefix(raw, "f'") {
		raw = raw[1:]
	}
	if strings.HasPrefix(raw, "\"") || strings.HasPrefix(raw, "'") {
		p := newParser(raw)
		value, err := p.parseString()
		return value, err == nil
	}
	if raw == "True" || raw == "true" {
		return true, true
	}
	if raw == "False" || raw == "false" {
		return false, true
	}
	if raw == "None" {
		return nil, true
	}
	if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return int(parsed), true
	}
	if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
		return parsed, true
	}
	return nil, false
}

func literalStringList(raw string, constants map[string]interface{}) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "[") {
		return nil
	}
	p := newParser(raw)
	value, err := p.parseValue()
	if err != nil {
		return nil
	}
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}
	out := []string{}
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func isSensitiveParamName(name string) bool {
	name = strings.ToLower(name)
	for _, token := range []string{"password", "passwd", "secret", "token", "apikey", "api_key", "key"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func mergeParamMap(dst, src map[string]Param) {
	for name, param := range src {
		if existing, ok := dst[name]; ok {
			dst[name] = mergeExplicitParam(existing, param)
			continue
		}
		dst[name] = param
	}
}

func mergeExplicitParam(explicit, inferred Param) Param {
	merged := explicit
	finalSensitive := explicit.Sensitive || inferred.Sensitive
	if merged.Type == "" {
		merged.Type = inferred.Type
	}
	merged.Required = explicit.Required || inferred.Required
	if merged.Default == nil && !finalSensitive && inferred.Default != nil {
		merged.Default = inferred.Default
	}
	if merged.Description == "" {
		merged.Description = inferred.Description
	}
	if len(merged.Enum) == 0 && len(inferred.Enum) > 0 {
		merged.Enum = append([]interface{}(nil), inferred.Enum...)
	}
	if merged.Example == nil {
		merged.Example = inferred.Example
	}
	if merged.Pattern == "" {
		merged.Pattern = inferred.Pattern
	}
	if merged.Min == nil {
		merged.Min = inferred.Min
	}
	if merged.Max == nil {
		merged.Max = inferred.Max
	}
	if merged.Format == "" {
		merged.Format = inferred.Format
	}
	merged.Sensitive = finalSensitive
	if merged.Source == "" {
		merged.Source = inferred.Source
	}
	if merged.Flag == "" {
		merged.Flag = inferred.Flag
	}
	if merged.Position == 0 {
		merged.Position = inferred.Position
	}
	if merged.Placeholder == "" {
		merged.Placeholder = inferred.Placeholder
	}
	if merged.ValueName == "" {
		merged.ValueName = inferred.ValueName
	}
	return merged
}

func inferUsageParams(source string) map[string]Param {
	lines := strings.Split(source, "\n")
	usageLines := [][]string{}
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) < 2 || !strings.HasPrefix(strings.ToLower(tokens[0]), "python") {
			continue
		}
		usageLines = append(usageLines, tokens[2:])
	}
	out := map[string]Param{}
	for _, tokens := range usageLines {
		for idx := 0; idx < len(tokens); idx++ {
			token := strings.Trim(tokens[idx], "[]")
			position := idx + 1
			if strings.HasPrefix(token, "--") {
				name := sanitizeParamName(strings.TrimLeft(token, "-"), fmt.Sprintf("arg%d", position))
				valueName := ""
				if idx+1 < len(tokens) && !strings.HasPrefix(tokens[idx+1], "-") {
					valueName = strings.Trim(tokens[idx+1], "<>[]")
					idx++
				}
				out[name] = Param{
					Type:        "string",
					Required:    len(usageLines) == 1,
					Description: fmt.Sprintf("CLI option %s", token),
					Source:      "usage",
					Flag:        token,
					Position:    position,
					Placeholder: valueName,
					ValueName:   valueName,
				}
				continue
			}
			if strings.HasPrefix(token, "<") && strings.HasSuffix(token, ">") {
				placeholder := strings.Trim(token, "<>")
				name := sanitizeParamName(placeholder, fmt.Sprintf("arg%d", position))
				out[name] = Param{
					Type:        "string",
					Required:    len(usageLines) == 1,
					Description: placeholder,
					Source:      "usage",
					Position:    position,
					Placeholder: placeholder,
				}
			}
		}
	}
	return out
}

func inferSysArgvParams(source string) map[string]Param {
	out := map[string]Param{}
	flagPattern := regexp.MustCompile(`sys\.argv\[(\d+)\]\s*==\s*["'](--?[A-Za-z0-9_-]+)["']`)
	for _, match := range flagPattern.FindAllStringSubmatch(source, -1) {
		position, _ := strconv.Atoi(match[1])
		flag := match[2]
		name := sanitizeParamName(strings.TrimLeft(flag, "-"), fmt.Sprintf("arg%d", position))
		out[name] = Param{
			Type:        "string",
			Description: fmt.Sprintf("CLI option %s", flag),
			Source:      "sys.argv",
			Flag:        flag,
			Position:    position,
		}
	}
	argvPattern := regexp.MustCompile(`sys\.argv\[(\d+)\]`)
	for _, match := range argvPattern.FindAllStringSubmatch(source, -1) {
		position, _ := strconv.Atoi(match[1])
		if position <= 0 {
			continue
		}
		if hasParamAtPosition(out, position) {
			continue
		}
		name := fmt.Sprintf("arg%d", position)
		out[name] = Param{
			Type:        "string",
			Required:    position == 1,
			Description: fmt.Sprintf("CLI positional argument %d", position),
			Source:      "sys.argv",
			Position:    position,
			Placeholder: name,
		}
	}
	return out
}

func hasParamAtPosition(params map[string]Param, position int) bool {
	for _, param := range params {
		if param.Position == position && param.Flag == "" {
			return true
		}
	}
	return false
}

func sanitizeParamName(raw, fallback string) string {
	raw = strings.TrimSpace(strings.Trim(raw, "<>[]"))
	var b strings.Builder
	for _, r := range raw {
		if r == '-' || r == ' ' {
			b.WriteRune('_')
		} else if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			b.WriteRune(r)
		}
	}
	name := b.String()
	if name == "" {
		name = fallback
	}
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		name = "arg_" + name
	}
	if !validParamNamePattern.MatchString(name) {
		return fallback
	}
	return name
}

func normalizeParamType(paramType string) string {
	switch strings.ToLower(strings.TrimSpace(paramType)) {
	case "integer":
		return "int"
	case "float":
		return "number"
	case "boolean":
		return "bool"
	default:
		return strings.ToLower(strings.TrimSpace(paramType))
	}
}

func normalizeParamValue(name, paramType string, value interface{}) (interface{}, error) {
	switch normalizeParamType(paramType) {
	case "string":
		typed, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("param %q must be a string", name)
		}
		return typed, nil
	case "int":
		switch typed := value.(type) {
		case int:
			return typed, nil
		case int64:
			return int(typed), nil
		case float64:
			if typed != float64(int64(typed)) {
				return nil, fmt.Errorf("param %q must be an integer", name)
			}
			return int(typed), nil
		case string:
			if strings.TrimSpace(typed) == "" {
				return nil, fmt.Errorf("param %q must be an integer", name)
			}
			parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("param %q must be an integer", name)
			}
			return int(parsed), nil
		default:
			return nil, fmt.Errorf("param %q must be an integer", name)
		}
	case "number":
		switch typed := value.(type) {
		case int:
			return float64(typed), nil
		case int64:
			return float64(typed), nil
		case float64:
			return typed, nil
		case string:
			if strings.TrimSpace(typed) == "" {
				return nil, fmt.Errorf("param %q must be a number", name)
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
			if err != nil {
				return nil, fmt.Errorf("param %q must be a number", name)
			}
			return parsed, nil
		default:
			return nil, fmt.Errorf("param %q must be a number", name)
		}
	case "bool":
		switch typed := value.(type) {
		case bool:
			return typed, nil
		case string:
			parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
			if err != nil {
				return nil, fmt.Errorf("param %q must be a boolean", name)
			}
			return parsed, nil
		default:
			return nil, fmt.Errorf("param %q must be a boolean", name)
		}
	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return nil, fmt.Errorf("param %q must be an object", name)
		}
		return value, nil
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return nil, fmt.Errorf("param %q must be an array", name)
		}
		return value, nil
	case "json":
		return value, nil
	default:
		return nil, fmt.Errorf("param %q has unsupported type %q", name, paramType)
	}
}

func validateParamConstraints(name, paramType string, value interface{}, def map[string]interface{}) []string {
	errs := []string{}
	if enumRaw, ok := def["enum"].([]interface{}); ok && len(enumRaw) > 0 {
		matched := false
		for _, item := range enumRaw {
			normalizedItem, err := normalizeParamValue(name, paramType, item)
			if err == nil && reflect.DeepEqual(normalizedItem, value) {
				matched = true
				break
			}
		}
		if !matched {
			errs = append(errs, fmt.Sprintf("param %q must be one of declared enum values", name))
		}
	}
	if pattern := stringField(def, "pattern"); pattern != "" {
		text, ok := value.(string)
		if !ok {
			errs = append(errs, fmt.Sprintf("param %q pattern can only validate string values", name))
		} else if matched, err := regexp.MatchString(pattern, text); err != nil {
			errs = append(errs, fmt.Sprintf("param %q pattern is invalid: %v", name, err))
		} else if !matched {
			errs = append(errs, fmt.Sprintf("param %q does not match pattern", name))
		}
	}
	if min, ok := numericField(def, "min"); ok {
		if err := validateMinMax(name, paramType, value, min, true); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if max, ok := numericField(def, "max"); ok {
		if err := validateMinMax(name, paramType, value, max, false); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

func validateMinMax(name, paramType string, value interface{}, limit float64, isMin bool) error {
	var actual float64
	switch normalizeParamType(paramType) {
	case "string":
		text, _ := value.(string)
		actual = float64(len(text))
	case "int":
		typed, _ := value.(int)
		actual = float64(typed)
	case "number":
		typed, _ := value.(float64)
		actual = typed
	default:
		return nil
	}
	if isMin && actual < limit {
		return fmt.Errorf("param %q must be >= %v", name, trimFloat(limit))
	}
	if !isMin && actual > limit {
		return fmt.Errorf("param %q must be <= %v", name, trimFloat(limit))
	}
	return nil
}

func trimFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func ScanForbiddenSymbols(source string) error {
	// Native Python EXPs are intentionally not constrained by symbol deny-lists.
	// The function remains for callers that still invoke the old review hook.
	return nil
}

func ScanCapabilities(source string, declared map[string]bool) error {
	// policy.capabilities is display metadata only; ctx helpers are compatibility
	// conveniences and do not require declaration.
	return nil
}

func stringField(root map[string]interface{}, key string) string {
	value, _ := root[key].(string)
	return strings.TrimSpace(value)
}

func stringSliceField(root map[string]interface{}, key string) []string {
	raw, ok := root[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func policyField(root map[string]interface{}, key string) Policy {
	raw, _ := root[key].(map[string]interface{})
	return Policy{
		RequiresAuth:     boolMapField(raw, "requires_auth"),
		CleanupSupported: boolMapField(raw, "cleanup_supported"),
		CleanupRequired:  boolMapField(raw, "cleanup_required"),
		DryRunSupported:  boolMapField(raw, "dry_run_supported"),
		TimeoutSec:       intMapField(raw, "timeout_sec"),
		Capabilities:     stringSliceField(raw, "capabilities"),
		SideEffects:      stringSliceField(raw, "side_effects"),
	}
}

func boolMapField(root map[string]interface{}, key string) bool {
	value, _ := root[key].(bool)
	return value
}

func intMapField(root map[string]interface{}, key string) int {
	switch value := root[key].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func numericField(root map[string]interface{}, key string) (float64, bool) {
	switch value := root[key].(type) {
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	case float64:
		return value, true
	default:
		return 0, false
	}
}

func numericPtrField(root map[string]interface{}, key string) *float64 {
	value, ok := numericField(root, key)
	if !ok {
		return nil
	}
	return &value
}

func paramMapField(root map[string]interface{}, key string) map[string]Param {
	raw, ok := root[key].(map[string]interface{})
	if !ok {
		return map[string]Param{}
	}
	out := make(map[string]Param, len(raw))
	for name, value := range raw {
		def, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		out[name] = Param{
			Type:        stringField(def, "type"),
			Required:    boolMapField(def, "required"),
			Default:     def["default"],
			Description: stringField(def, "description"),
			Enum:        interfaceSliceField(def, "enum"),
			Example:     def["example"],
			Pattern:     stringField(def, "pattern"),
			Min:         numericPtrField(def, "min"),
			Max:         numericPtrField(def, "max"),
			Format:      stringField(def, "format"),
			Sensitive:   boolMapField(def, "sensitive"),
			Source:      stringField(def, "source"),
			Flag:        stringField(def, "flag"),
			Position:    intMapField(def, "position"),
			Placeholder: stringField(def, "placeholder"),
			ValueName:   stringField(def, "value_name"),
		}
	}
	return out
}

func interfaceSliceField(root map[string]interface{}, key string) []interface{} {
	raw, ok := root[key].([]interface{})
	if !ok {
		return nil
	}
	return append([]interface{}(nil), raw...)
}

func hasTopLevelFunction(source, name string) bool {
	pattern := regexp.MustCompile(`(?m)^def\s+` + regexp.QuoteMeta(name) + `\s*\(\s*ctx\s*\)\s*:`)
	return pattern.FindStringIndex(source) != nil
}

func hasTopLevelFunctionAnyArgs(source, name string) bool {
	pattern := regexp.MustCompile(`(?m)^def\s+` + regexp.QuoteMeta(name) + `\s*\([^)]*\)\s*:`)
	return pattern.FindStringIndex(source) != nil
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func extractArgusExpLiteral(source string) (interface{}, error) {
	idx := findTopLevelIdentifier(source, "ARGUS_EXP")
	if idx < 0 {
		return nil, fmt.Errorf("ARGUS_EXP dict literal is required")
	}
	p := newParser(source[idx+len("ARGUS_EXP"):])
	p.skipSpaceAndComments()
	if !p.consume("=") {
		return nil, fmt.Errorf("ARGUS_EXP must be assigned with =")
	}
	value, err := p.parseValue()
	if err != nil {
		return nil, fmt.Errorf("parse ARGUS_EXP: %w", err)
	}
	return value, nil
}

func findTopLevelIdentifier(source, ident string) int {
	atLineStart := true
	inString := byte(0)
	triple := false
	escaped := false
	lineHasIndent := false
	for i := 0; i < len(source); {
		r, size := utf8.DecodeRuneInString(source[i:])
		if inString != 0 {
			if escaped {
				escaped = false
				i += size
				continue
			}
			if source[i] == '\\' {
				escaped = true
				i += size
				continue
			}
			if triple {
				if source[i] == inString && i+2 < len(source) && source[i+1] == inString && source[i+2] == inString {
					inString = 0
					triple = false
					i += 3
					continue
				}
				if r == '\n' || r == '\r' {
					atLineStart = true
					lineHasIndent = false
				}
				i += size
				continue
			}
			if source[i] == inString {
				inString = 0
			}
			i += size
			continue
		}
		if atLineStart {
			j := i
			for j < len(source) && (source[j] == ' ' || source[j] == '\t') {
				j++
			}
			lineHasIndent = j > i
			if !lineHasIndent && strings.HasPrefix(source[j:], ident) && isIdentBoundary(source, j-1) && isIdentBoundary(source, j+len(ident)) {
				return j
			}
			atLineStart = false
		}
		if source[i] == '#' {
			for i < len(source) && source[i] != '\n' && source[i] != '\r' {
				i++
			}
			continue
		}
		if source[i] == '\'' || source[i] == '"' {
			inString = source[i]
			triple = i+2 < len(source) && source[i+1] == inString && source[i+2] == inString
			if triple {
				i += 3
				continue
			}
			i += size
			continue
		}
		if r == '\n' || r == '\r' {
			atLineStart = true
			lineHasIndent = false
		}
		i += size
	}
	return -1
}

func isIdentBoundary(source string, idx int) bool {
	if idx < 0 || idx >= len(source) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(source[idx:])
	return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_')
}

type parser struct {
	input string
	pos   int
}

func newParser(input string) *parser {
	return &parser{input: input}
}

func (p *parser) skipSpaceAndComments() {
	for p.pos < len(p.input) {
		r := rune(p.input[p.pos])
		if unicode.IsSpace(r) {
			p.pos++
			continue
		}
		if p.input[p.pos] == '#' {
			for p.pos < len(p.input) && p.input[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		return
	}
}

func (p *parser) consume(token string) bool {
	p.skipSpaceAndComments()
	if strings.HasPrefix(p.input[p.pos:], token) {
		p.pos += len(token)
		return true
	}
	return false
}

func (p *parser) parseValue() (interface{}, error) {
	p.skipSpaceAndComments()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unexpected end")
	}
	switch p.input[p.pos] {
	case '{':
		return p.parseDict()
	case '[':
		return p.parseList(']')
	case '(':
		return p.parseList(')')
	case '\'', '"':
		return p.parseString()
	default:
		if isIdentStart(rune(p.input[p.pos])) {
			return p.parseName()
		}
		if p.input[p.pos] == '-' || (p.input[p.pos] >= '0' && p.input[p.pos] <= '9') {
			return p.parseNumber()
		}
		return nil, fmt.Errorf("unexpected token %q", p.input[p.pos])
	}
}

func (p *parser) parseDict() (interface{}, error) {
	if !p.consume("{") {
		return nil, fmt.Errorf("expected {")
	}
	out := map[string]interface{}{}
	for {
		p.skipSpaceAndComments()
		if p.consume("}") {
			return out, nil
		}
		keyValue, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		key, ok := keyValue.(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		if !p.consume(":") {
			return nil, fmt.Errorf("expected : after dict key")
		}
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		out[key] = value
		p.skipSpaceAndComments()
		if p.consume("}") {
			return out, nil
		}
		if !p.consume(",") {
			return nil, fmt.Errorf("expected , or }")
		}
	}
}

func (p *parser) parseList(close byte) (interface{}, error) {
	open := byte('[')
	if close == ')' {
		open = '('
	}
	if !p.consume(string(open)) {
		return nil, fmt.Errorf("expected %c", open)
	}
	out := []interface{}{}
	for {
		p.skipSpaceAndComments()
		if p.consume(string(close)) {
			return out, nil
		}
		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		out = append(out, value)
		p.skipSpaceAndComments()
		if p.consume(string(close)) {
			return out, nil
		}
		if !p.consume(",") {
			return nil, fmt.Errorf("expected , or %c", close)
		}
	}
}

func (p *parser) parseString() (string, error) {
	quote := p.input[p.pos]
	triple := strings.HasPrefix(p.input[p.pos:], strings.Repeat(string(quote), 3))
	if triple {
		p.pos += 3
		start := p.pos
		endToken := strings.Repeat(string(quote), 3)
		end := strings.Index(p.input[p.pos:], endToken)
		if end < 0 {
			return "", fmt.Errorf("unterminated triple-quoted string")
		}
		raw := p.input[start : p.pos+end]
		p.pos += end + 3
		return decodeEscapes(raw, quote), nil
	}
	p.pos++
	var b strings.Builder
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		p.pos++
		if ch == quote {
			return b.String(), nil
		}
		if ch == '\\' && p.pos < len(p.input) {
			escaped := p.input[p.pos]
			p.pos++
			switch escaped {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\\', '\'', '"':
				b.WriteByte(escaped)
			default:
				b.WriteByte(escaped)
			}
			continue
		}
		b.WriteByte(ch)
	}
	return "", fmt.Errorf("unterminated string")
}

func decodeEscapes(raw string, quote byte) string {
	raw = strings.ReplaceAll(raw, `\n`, "\n")
	raw = strings.ReplaceAll(raw, `\r`, "\r")
	raw = strings.ReplaceAll(raw, `\t`, "\t")
	raw = strings.ReplaceAll(raw, `\\`, `\`)
	raw = strings.ReplaceAll(raw, `\`+string(quote), string(quote))
	return raw
}

func (p *parser) parseName() (interface{}, error) {
	start := p.pos
	for p.pos < len(p.input) {
		r := rune(p.input[p.pos])
		if !isIdentPart(r) {
			break
		}
		p.pos++
	}
	switch p.input[start:p.pos] {
	case "True":
		return true, nil
	case "False":
		return false, nil
	case "None":
		return nil, nil
	default:
		return nil, fmt.Errorf("only True, False and None names are allowed in ARGUS_EXP")
	}
}

func (p *parser) parseNumber() (interface{}, error) {
	start := p.pos
	if p.input[p.pos] == '-' {
		p.pos++
	}
	for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
		p.pos++
	}
	if p.pos < len(p.input) && p.input[p.pos] == '.' {
		p.pos++
		for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
			p.pos++
		}
		value, err := strconv.ParseFloat(p.input[start:p.pos], 64)
		if err != nil {
			return nil, err
		}
		return value, nil
	}
	value, err := strconv.ParseInt(p.input[start:p.pos], 10, 64)
	if err != nil {
		return nil, err
	}
	return int(value), nil
}

func isIdentStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

func isIdentPart(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}
