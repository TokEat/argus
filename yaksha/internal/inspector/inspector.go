// Package inspector derives the publishable EXP input contract from Yak
// source without executing that source.
package inspector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
	"github.com/yaklang/antlr/v4"
	"github.com/yaklang/yaklang/common/utils/yakunquote"
	"github.com/yaklang/yaklang/common/yak/antlr4yak/parser"
)

var parameterTypes = map[string]string{
	"cli.String":      "string",
	"cli.Text":        "text",
	"cli.Int":         "integer",
	"cli.Integer":     "integer",
	"cli.Float":       "number",
	"cli.Bool":        "boolean",
	"cli.StringSlice": "string_array",
}

var parameterNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
var identifierPattern = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

const maxControlFlowSteps = 128

// Inspect parses source and extracts the deliberately small Yaksha V1 subset
// of Yaklang's cli declarations. It never compiles or evaluates the program.
func Inspect(source string) protocol.Inspection {
	sum := sha256.Sum256([]byte(source))
	result := protocol.Inspection{
		SourceSHA256: hex.EncodeToString(sum[:]),
		SourceBytes:  len(source),
		SourceLines:  strings.Count(source, "\n") + 1,
		Parameters:   []protocol.CLIParameter{},
		Dependencies: []protocol.DependencyReference{},
		AssetRefs:    []protocol.AssetReference{},
		ControlFlow:  []protocol.ControlFlowStep{},
		Diagnostics:  []protocol.Diagnostic{},
	}

	listener := newSyntaxListener(&result.Diagnostics)
	input := antlr.NewInputStream(source)
	lexer := parser.NewYaklangLexer(input)
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(listener)
	tokens := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	yakParser := parser.NewYaklangParser(tokens)
	yakParser.RemoveErrorListeners()
	yakParser.AddErrorListener(listener)
	tree := yakParser.Program()

	if hasErrors(result.Diagnostics) {
		return result
	}

	checkCount := 0
	checkSeen := false
	seen := make(map[string]struct{})
	walk(tree, func(expr *parser.ExpressionContext) {
		name, args, ok := call(expr)
		if !ok {
			return
		}

		if name == "cli.check" {
			checkCount++
			if !isTopLevel(expr) {
				addDiagnostic(&result, expr, "error", "cli_check_not_top_level", "cli.check() must be declared at top level")
			} else {
				checkSeen = true
			}
			if len(args) != 0 {
				addDiagnostic(&result, expr, "error", "cli_check_arguments", "cli.check() must not have arguments")
			}
			return
		}
		if name == "yaksha.call" {
			inspectDependencyCall(&result, expr, args)
			return
		}
		if name == "yaksha.asset" {
			inspectAssetCall(&result, expr, args)
			return
		}

		schemaType, supported := parameterTypes[name]
		if !supported {
			if isCLIParameterLike(name) {
				addDiagnostic(&result, expr, "error", "unsupported_cli_type", fmt.Sprintf("%s is not supported by the Yaksha V1 EXP contract", name))
			}
			return
		}
		if !isTopLevel(expr) {
			addDiagnostic(&result, expr, "error", "cli_parameter_not_top_level", fmt.Sprintf("%s must be declared at top level", name))
			return
		}
		if checkSeen {
			addDiagnostic(&result, expr, "error", "cli_parameter_after_check", fmt.Sprintf("%s must be declared before cli.check()", name))
			return
		}
		if len(args) == 0 {
			addDiagnostic(&result, expr, "error", "cli_parameter_name", fmt.Sprintf("%s requires a literal parameter name", name))
			return
		}
		paramName, ok := literalString(args[0])
		if !ok || strings.TrimSpace(paramName) == "" {
			addDiagnostic(&result, args[0], "error", "cli_parameter_name", fmt.Sprintf("%s parameter name must be a non-empty string literal", name))
			return
		}
		if !parameterNamePattern.MatchString(paramName) || paramName == "help" {
			addDiagnostic(&result, args[0], "error", "invalid_cli_parameter_name", fmt.Sprintf("parameter name %q must match %s and must not be reserved", paramName, parameterNamePattern.String()))
			return
		}

		param := protocol.CLIParameter{Name: paramName, Type: schemaType}
		for _, optionExpr := range args[1:] {
			parseOption(&result, &param, optionExpr)
		}
		if param.HasDefault && !validDefault(param.Type, param.Default) {
			addDiagnostic(&result, expr, "error", "invalid_cli_default", fmt.Sprintf("default value for parameter %q does not match type %s", paramName, schemaType))
		}
		if param.HasDefault && param.InputType != "" {
			if value, ok := param.Default.(string); ok && !protocol.ValidateCLIInputValue(param.InputType, value) {
				addDiagnostic(&result, expr, "error", "invalid_cli_input_default", fmt.Sprintf("default value for parameter %q does not match input type %s", paramName, param.InputType))
			}
		}
		if param.Type == "string_array" {
			validateSelectContract(&result, expr, param)
		}
		if _, exists := seen[paramName]; exists {
			addDiagnostic(&result, expr, "error", "duplicate_cli_parameter", fmt.Sprintf("parameter %q is declared more than once", paramName))
			return
		}
		seen[paramName] = struct{}{}
		result.Parameters = append(result.Parameters, param)
	})

	if checkCount == 0 {
		result.Diagnostics = append(result.Diagnostics, protocol.Diagnostic{
			Severity: "error",
			Code:     "missing_cli_check",
			Message:  "exactly one top-level cli.check() declaration is required",
			Line:     1,
			Column:   1,
		})
	} else if checkCount > 1 {
		result.Diagnostics = append(result.Diagnostics, protocol.Diagnostic{
			Severity: "error",
			Code:     "duplicate_cli_check",
			Message:  "cli.check() must appear exactly once",
			Line:     1,
			Column:   1,
		})
	}

	result.Valid = !hasErrors(result.Diagnostics)
	result.ControlFlow = extractControlFlow(tree, result.Parameters)
	return result
}

func inspectDependencyCall(result *protocol.Inspection, ctx *parser.ExpressionContext, args []parser.IExpressionContext) {
	if len(args) != 3 {
		addDiagnostic(result, ctx, "error", "invalid_dependency_call", "yaksha.call requires literal exp_id, literal revision, and params")
		return
	}
	expID, expOK := literalString(args[0])
	revisionValue, revisionOK := literalValue(args[1])
	revision, intOK := revisionValue.(int64)
	if !expOK || !revisionOK || !intOK || revision < 1 {
		addDiagnostic(result, ctx, "error", "dynamic_dependency_reference", "yaksha.call exp_id and positive revision must be literals")
		return
	}
	line, column := position(ctx)
	result.Dependencies = append(result.Dependencies, protocol.DependencyReference{ExpID: expID, Revision: int(revision), Line: line, Column: column})
}

func inspectAssetCall(result *protocol.Inspection, ctx *parser.ExpressionContext, args []parser.IExpressionContext) {
	if len(args) != 1 {
		addDiagnostic(result, ctx, "error", "invalid_asset_call", "yaksha.asset requires one literal asset_id")
		return
	}
	assetID, ok := literalString(args[0])
	if !ok || strings.TrimSpace(assetID) == "" {
		addDiagnostic(result, ctx, "error", "dynamic_asset_reference", "yaksha.asset asset_id must be a non-empty literal")
		return
	}
	line, column := position(ctx)
	result.AssetRefs = append(result.AssetRefs, protocol.AssetReference{AssetID: assetID, Line: line, Column: column})
}

func position(ctx antlr.ParserRuleContext) (int, int) {
	if start := ctx.GetStart(); start != nil {
		return start.GetLine(), start.GetColumn() + 1
	}
	return 1, 1
}

func validateSelectContract(result *protocol.Inspection, ctx antlr.ParserRuleContext, parameter protocol.CLIParameter) {
	allowed := make(map[string]struct{}, len(parameter.Options))
	for _, option := range parameter.Options {
		if option.Value == "" {
			addDiagnostic(result, ctx, "error", "empty_cli_option", fmt.Sprintf("parameter %q contains an empty select option value", parameter.Name))
			continue
		}
		if _, exists := allowed[option.Value]; exists {
			addDiagnostic(result, ctx, "error", "duplicate_cli_option", fmt.Sprintf("parameter %q declares select option %q more than once", parameter.Name, option.Value))
		}
		allowed[option.Value] = struct{}{}
	}
	if !parameter.HasDefault || len(allowed) == 0 {
		return
	}
	defaultValue, ok := parameter.Default.(string)
	if !ok {
		return
	}
	for _, value := range strings.Split(defaultValue, ",") {
		value = strings.TrimSpace(value)
		if _, exists := allowed[value]; !exists {
			addDiagnostic(result, ctx, "error", "invalid_cli_default_option", fmt.Sprintf("default value %q for parameter %q is outside its declared options", value, parameter.Name))
		}
	}
}

func parseOption(result *protocol.Inspection, param *protocol.CLIParameter, expr parser.IExpressionContext) {
	ctx, ok := expr.(*parser.ExpressionContext)
	if !ok {
		return
	}
	name, args, ok := call(ctx)
	if !ok || !strings.HasPrefix(name, "cli.set") {
		addDiagnostic(result, ctx, "error", "invalid_cli_option", "CLI parameter options must use supported literal cli.set* calls")
		return
	}

	requireArgs := func(count int) bool {
		if len(args) == count {
			return true
		}
		addDiagnostic(result, ctx, "error", "invalid_cli_option_arguments", fmt.Sprintf("%s requires %d literal argument(s)", name, count))
		return false
	}
	stringArg := func(index int) (string, bool) {
		value, ok := literalString(args[index])
		if !ok {
			addDiagnostic(result, args[index], "error", "non_literal_cli_option", fmt.Sprintf("%s arguments must be string literals", name))
		}
		return value, ok
	}
	boolArg := func(index int) (bool, bool) {
		value, ok := literalValue(args[index])
		if !ok {
			addDiagnostic(result, args[index], "error", "non_literal_cli_option", fmt.Sprintf("%s arguments must be boolean literals", name))
			return false, false
		}
		boolean, ok := value.(bool)
		if !ok {
			addDiagnostic(result, args[index], "error", "invalid_cli_option_type", fmt.Sprintf("%s arguments must be boolean literals", name))
		}
		return boolean, ok
	}

	switch name {
	case "cli.setRequired":
		if requireArgs(1) {
			if value, ok := boolArg(0); ok {
				param.Required = value
			}
		}
	case "cli.setDefault":
		if requireArgs(1) {
			if value, ok := literalValue(args[0]); ok {
				param.Default = value
				param.HasDefault = true
			} else {
				addDiagnostic(result, args[0], "error", "non_literal_cli_option", "cli.setDefault arguments must be scalar or list literals")
			}
		}
	case "cli.setHelp":
		if requireArgs(1) {
			param.Help, _ = stringArg(0)
		}
	case "cli.setVerboseName":
		if requireArgs(1) {
			param.VerboseName, _ = stringArg(0)
		}
	case "cli.setCliGroup":
		if requireArgs(1) {
			param.Group, _ = stringArg(0)
		}
	case "cli.setInputType":
		if requireArgs(1) {
			if param.Type != "string" {
				addDiagnostic(result, ctx, "error", "invalid_cli_option_target", "cli.setInputType is only valid for cli.String")
				return
			}
			value, ok := stringArg(0)
			if ok {
				switch value {
				case "host_port", "url":
					param.InputType = value
				default:
					addDiagnostic(result, ctx, "error", "unsupported_cli_input_type", fmt.Sprintf("input type %q is not supported by the Yaksha V1 EXP contract", value))
				}
			}
		}
	case "cli.setMultipleSelect":
		if requireArgs(1) {
			if param.Type != "string_array" {
				addDiagnostic(result, ctx, "error", "invalid_cli_option_target", "cli.setMultipleSelect is only valid for cli.StringSlice")
				return
			}
			if value, ok := boolArg(0); ok {
				param.MultipleSelect = value
			}
		}
	case "cli.setSelectOption":
		if requireArgs(2) {
			if param.Type != "string_array" {
				addDiagnostic(result, ctx, "error", "invalid_cli_option_target", "cli.setSelectOption is only valid for cli.StringSlice")
				return
			}
			label, labelOK := stringArg(0)
			value, valueOK := stringArg(1)
			if labelOK && valueOK {
				param.Options = append(param.Options, protocol.CLIOption{Label: label, Value: value})
			}
		}
	default:
		addDiagnostic(result, ctx, "error", "unsupported_cli_option", fmt.Sprintf("%s is not supported by the Yaksha V1 EXP contract", name))
	}
}

func validDefault(schemaType string, value any) bool {
	if value == nil {
		return true
	}
	switch schemaType {
	case "string", "text":
		_, ok := value.(string)
		return ok
	case "integer":
		_, ok := value.(int64)
		return ok
	case "number":
		switch value.(type) {
		case int64, float64:
			return true
		default:
			return false
		}
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "string_array":
		_, ok := value.(string)
		return ok
	default:
		return false
	}
}

func call(expr *parser.ExpressionContext) (string, []parser.IExpressionContext, bool) {
	functionCall := expr.FunctionCall()
	if functionCall == nil || len(expr.AllExpression()) == 0 {
		return "", nil, false
	}
	name := qualifiedName(expr.Expression(0))
	if name == "" {
		return "", nil, false
	}
	ordinary := functionCall.OrdinaryArguments()
	if ordinary == nil {
		return name, nil, true
	}
	return name, ordinary.AllExpression(), true
}

func qualifiedName(expr parser.IExpressionContext) string {
	ctx, ok := expr.(*parser.ExpressionContext)
	if !ok {
		return ""
	}
	if identifier := ctx.Identifier(); identifier != nil {
		return identifier.GetText()
	}
	if paren := ctx.ParenExpression(); paren != nil {
		return qualifiedName(paren.Expression())
	}
	if member := ctx.MemberCall(); member != nil && len(ctx.AllExpression()) > 0 {
		identifier := member.Identifier()
		if identifier == nil {
			identifier = member.IdentifierWithDollar()
		}
		if identifier == nil {
			return ""
		}
		base := qualifiedName(ctx.Expression(0))
		if base != "" {
			return base + "." + identifier.GetText()
		}
	}
	return ""
}

func literalString(expr parser.IExpressionContext) (string, bool) {
	value, ok := literalValue(expr)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func literalValue(expr parser.IExpressionContext) (any, bool) {
	ctx, ok := expr.(*parser.ExpressionContext)
	if !ok {
		return nil, false
	}
	if paren := ctx.ParenExpression(); paren != nil {
		return literalValue(paren.Expression())
	}
	literal := ctx.Literal()
	if literal == nil {
		text := strings.ReplaceAll(ctx.GetText(), "_", "")
		if (strings.HasPrefix(text, "-") || strings.HasPrefix(text, "+")) && len(ctx.AllExpression()) == 1 {
			if strings.ContainsAny(text, ".eE") {
				value, err := strconv.ParseFloat(text, 64)
				return value, err == nil
			}
			value, err := strconv.ParseInt(text, 0, 64)
			return value, err == nil
		}
		return nil, false
	}
	if stringLiteral := literal.StringLiteral(); stringLiteral != nil {
		value, err := yakunquote.Unquote(stringLiteral.GetText())
		return value, err == nil
	}
	if numeric := literal.NumericLiteral(); numeric != nil {
		text := strings.ReplaceAll(numeric.GetText(), "_", "")
		if numeric.FloatLiteral() != nil {
			value, err := strconv.ParseFloat(text, 64)
			return value, err == nil
		}
		value, err := strconv.ParseInt(text, 0, 64)
		return value, err == nil
	}
	if boolean := literal.BoolLiteral(); boolean != nil {
		return boolean.GetText() == "true", true
	}
	if literal.NilLiteral() != nil {
		return nil, true
	}
	if slice := literal.SliceLiteral(); slice != nil {
		list := slice.ExpressionListMultiline()
		if list == nil {
			return []any{}, true
		}
		values := make([]any, 0, len(list.AllExpression()))
		for _, element := range list.AllExpression() {
			value, ok := literalValue(element)
			if !ok {
				return nil, false
			}
			values = append(values, value)
		}
		return values, true
	}
	return nil, false
}

func isCLIParameterLike(name string) bool {
	if !strings.HasPrefix(name, "cli.") {
		return false
	}
	method := strings.TrimPrefix(name, "cli.")
	return method != "" && unicode.IsUpper([]rune(method)[0])
}

func isTopLevel(ctx antlr.Tree) bool {
	for parent := ctx.GetParent(); parent != nil; parent = parent.GetParent() {
		if _, nested := parent.(*parser.BlockContext); nested {
			return false
		}
	}
	return true
}

func walk(tree antlr.Tree, visit func(*parser.ExpressionContext)) {
	if expr, ok := tree.(*parser.ExpressionContext); ok {
		visit(expr)
	}
	for _, child := range tree.GetChildren() {
		walk(child, visit)
	}
}

type flowCandidate struct {
	step      protocol.ControlFlowStep
	rawInputs []string
}

func extractControlFlow(tree antlr.Tree, parameters []protocol.CLIParameter) []protocol.ControlFlowStep {
	candidates := make([]flowCandidate, 0)
	var collect func(antlr.Tree)
	collect = func(node antlr.Tree) {
		if panicStatement, ok := node.(*parser.PanicStmtContext); ok {
			line, column := position(panicStatement)
			expression := ""
			if value := panicStatement.Expression(); value != nil {
				expression = value.GetText()
			}
			candidates = append(candidates, flowCandidate{step: protocol.ControlFlowStep{
				Kind: "failure", Operation: "panic", Label: "终止并报告失败", Expression: expression, Line: line, Column: column,
			}, rawInputs: identifiers(expression)})
		}
		if condition, ok := node.(*parser.IfStmtContext); ok {
			expressions := condition.AllExpression()
			if len(expressions) > 0 {
				line, column := position(condition)
				expression := expressions[0].GetText()
				candidates = append(candidates, flowCandidate{step: protocol.ControlFlowStep{
					Kind: "condition", Operation: "if", Label: "条件判断", Expression: expression, Line: line, Column: column,
				}, rawInputs: identifiers(expression)})
			}
		}
		if expression, ok := node.(*parser.ExpressionContext); ok {
			if name, args, ok := call(expression); ok {
				kind, label, include := flowOperation(name)
				if include {
					line, column := position(expression)
					argumentText := make([]string, 0, len(args))
					for _, argument := range args {
						argumentText = append(argumentText, argument.GetText())
					}
					candidates = append(candidates, flowCandidate{step: protocol.ControlFlowStep{
						Kind: kind, Operation: name, Label: label, Expression: expression.GetText(),
						Outputs: assignedOutputs(expression), Line: line, Column: column,
					}, rawInputs: identifiers(strings.Join(argumentText, ","))})
				}
			}
		}
		for _, child := range node.GetChildren() {
			collect(child)
		}
	}
	collect(tree)
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].step.Line == candidates[j].step.Line {
			return candidates[i].step.Column < candidates[j].step.Column
		}
		return candidates[i].step.Line < candidates[j].step.Line
	})
	if len(candidates) > maxControlFlowSteps {
		candidates = candidates[:maxControlFlowSteps]
	}

	known := make(map[string]struct{}, len(parameters))
	for _, parameter := range parameters {
		known[parameter.Name] = struct{}{}
	}
	producer := make(map[string]string)
	steps := make([]protocol.ControlFlowStep, 0, len(candidates))
	for index, candidate := range candidates {
		candidate.step.ID = fmt.Sprintf("step-%d", index+1)
		seenInput := make(map[string]struct{})
		seenDependency := make(map[string]struct{})
		for _, input := range candidate.rawInputs {
			if _, exists := known[input]; !exists {
				continue
			}
			if _, exists := seenInput[input]; !exists {
				candidate.step.Inputs = append(candidate.step.Inputs, input)
				seenInput[input] = struct{}{}
			}
			if dependency := producer[input]; dependency != "" {
				if _, exists := seenDependency[dependency]; !exists {
					candidate.step.DependsOn = append(candidate.step.DependsOn, dependency)
					seenDependency[dependency] = struct{}{}
				}
			}
		}
		for _, output := range candidate.step.Outputs {
			known[output] = struct{}{}
			producer[output] = candidate.step.ID
		}
		steps = append(steps, candidate.step)
	}
	return steps
}

func flowOperation(name string) (kind, label string, include bool) {
	switch name {
	case "yaksha.httpRequest", "yaksha.httpGet":
		return "request", "HTTP 请求", true
	case "yaksha.tcpExchange", "yaksha.dial":
		return "request", "TCP 交互", true
	case "yaksha.call":
		return "compose", "调用子 EXP", true
	case "yaksha.asset":
		return "asset", "读取 Asset", true
	case "yaksha.regexMatch":
		return "transform", "条件计算", true
	case "yaksha.evidence":
		return "evidence", "记录证据", true
	case "yaksha.result":
		return "result", "输出结果", true
	case "panic":
		return "failure", "终止并报告失败", true
	}
	if strings.HasPrefix(name, "codec.") {
		return "transform", "编码或加解密", true
	}
	if strings.HasPrefix(name, "yso.") {
		return "transform", "生成反序列化 Payload", true
	}
	return "", "", false
}

func assignedOutputs(expression *parser.ExpressionContext) []string {
	for parent := expression.GetParent(); parent != nil; parent = parent.GetParent() {
		assignment, ok := parent.(*parser.AssignExpressionContext)
		if !ok {
			continue
		}
		left := assignment.LeftExpressionList()
		if left == nil || (assignment.AssignEq() == nil && assignment.ColonAssignEq() == nil) {
			continue
		}
		outputs := identifiers(left.GetText())
		if len(outputs) > 0 {
			return outputs
		}
	}
	return nil
}

func identifiers(text string) []string {
	return identifierPattern.FindAllString(text, -1)
}

func addDiagnostic(result *protocol.Inspection, ctx antlr.ParserRuleContext, severity, code, message string) {
	diagnostic := protocol.Diagnostic{Severity: severity, Code: code, Message: message, Line: 1, Column: 1}
	if start := ctx.GetStart(); start != nil {
		diagnostic.Line = start.GetLine()
		diagnostic.Column = start.GetColumn() + 1
	}
	if stop := ctx.GetStop(); stop != nil {
		diagnostic.EndLine = stop.GetLine()
		diagnostic.EndColumn = stop.GetColumn() + len([]rune(stop.GetText()))
	}
	result.Diagnostics = append(result.Diagnostics, diagnostic)
}

func hasErrors(diagnostics []protocol.Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "error" {
			return true
		}
	}
	return false
}

type syntaxListener struct {
	*antlr.DefaultErrorListener
	diagnostics *[]protocol.Diagnostic
}

func newSyntaxListener(diagnostics *[]protocol.Diagnostic) *syntaxListener {
	return &syntaxListener{DefaultErrorListener: antlr.NewDefaultErrorListener(), diagnostics: diagnostics}
}

func (l *syntaxListener) SyntaxError(_ antlr.Recognizer, _ any, line, column int, message string, _ antlr.RecognitionException) {
	*l.diagnostics = append(*l.diagnostics, protocol.Diagnostic{
		Severity: "error",
		Code:     "syntax_error",
		Message:  message,
		Line:     line,
		Column:   column + 1,
	})
}
