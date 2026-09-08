package ddfinger

import (
	"container/list"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/projectdiscovery/gologger"
	"regexp"
	"strconv"
	"strings"
)

// 判断优先级 非运算符返回0
func advance(ch int) int {
	// !
	if ch == 33 {
		return 3
	}
	// &
	if ch == 38 {
		return 2
	}
	// |
	if ch == 124 {
		return 1
	}
	return 0
}

func listBackInt(stack *list.List) (int, bool) {
	if stack == nil || stack.Back() == nil {
		return 0, false
	}
	value, ok := stack.Back().Value.(int)
	return value, ok
}

func popInt(stack *list.List) (int, bool) {
	value, ok := listBackInt(stack)
	if !ok {
		return 0, false
	}
	stack.Remove(stack.Back())
	return value, true
}

// 计算纯bool表达式，支持 ! && & || | ( )
func boolEval(expression string) bool {
	if strings.Count(expression, "(") != strings.Count(expression, ")") {
		gologger.Warning().Msgf("[-] 纯布尔表达式 [%s] 左右括号不匹配", expression)
		return false
	}
	for strings.Contains(expression, " ") {
		expression = strings.ReplaceAll(expression, " ", "")
	}
	for strings.Contains(expression, "()") {
		expression = strings.ReplaceAll(expression, "()", "")
	}
	for strings.Contains(expression, "&&") {
		expression = strings.ReplaceAll(expression, "&&", "&")
	}
	for strings.Contains(expression, "||") {
		expression = strings.ReplaceAll(expression, "||", "|")
	}
	if !strings.Contains(expression, "T") && !strings.Contains(expression, "F") {
		return false
	}

	expr := list.New()
	operator_stack := list.New()
	for _, ch := range expression {
		if ch == 84 || ch == 70 {
			expr.PushBack(int(ch))
			continue
		}
		if advance(int(ch)) > 0 {
			if operator_stack.Len() == 0 {
				operator_stack.PushBack(int(ch))
				continue
			}
			top, ok := listBackInt(operator_stack)
			if !ok {
				return false
			}
			if ch == 33 && top == 33 {
				operator_stack.Remove(operator_stack.Back())
				continue
			}
			for operator_stack.Len() != 0 {
				top, ok = listBackInt(operator_stack)
				if !ok || top == 40 || advance(top) < advance(int(ch)) {
					break
				}
				expr.PushBack(top)
				operator_stack.Remove(operator_stack.Back())
			}
			operator_stack.PushBack(int(ch))
			continue
		}
		if ch == 40 {
			operator_stack.PushBack(int(ch))
			continue
		}
		if ch == 41 {
			for {
				top, ok := listBackInt(operator_stack)
				if !ok {
					return false
				}
				if top == 40 {
					break
				}
				expr.PushBack(top)
				operator_stack.Remove(operator_stack.Back())
			}
			operator_stack.Remove(operator_stack.Back())
		}
	}
	for operator_stack.Len() != 0 {
		top, ok := popInt(operator_stack)
		if !ok {
			return false
		}
		if top == 40 {
			return false
		}
		expr.PushBack(top)
	}

	tf_stack := list.New()
	for expr.Len() != 0 {
		e := expr.Front()
		ch, ok := e.Value.(int)
		expr.Remove(e)
		if !ok {
			return false
		}
		if ch == 84 || ch == 70 {
			tf_stack.PushBack(ch)
			continue
		}
		if ch == 38 { // &
			a, okA := popInt(tf_stack)
			b, okB := popInt(tf_stack)
			if !okA || !okB {
				return false
			}
			if a == 84 && b == 84 {
				tf_stack.PushBack(84)
			} else {
				tf_stack.PushBack(70)
			}
			continue
		}
		if ch == 124 { // |
			a, okA := popInt(tf_stack)
			b, okB := popInt(tf_stack)
			if !okA || !okB {
				return false
			}
			if a == 70 && b == 70 {
				tf_stack.PushBack(70)
			} else {
				tf_stack.PushBack(84)
			}
			continue
		}
		if ch == 33 { // !
			a, okA := popInt(tf_stack)
			if !okA {
				return false
			}
			if a == 70 {
				tf_stack.PushBack(84)
			} else if a == 84 {
				tf_stack.PushBack(70)
			}
		}
	}
	result, ok := listBackInt(tf_stack)
	if !ok || tf_stack.Len() != 1 {
		return false
	}
	return result == 84
}

func getRuleData(rule string) structs.RuleData {
	if !strings.Contains(rule, "=\"") {
		return structs.RuleData{}
	}
	pos := strings.Index(rule, "=\"")
	if pos == 0 {
		return structs.RuleData{}
	}

	op := 0
	switch rule[pos-1] {
	case 33:
		op = 1
	case 61:
		op = 2
	case 62:
		op = 3
	case 60:
		op = 4
	case 126:
		op = 5
	}

	start := 0
	ti := 0
	if op > 0 {
		ti = 1
	}
	for i := pos - 1 - ti; i >= 0; i-- {
		if (rule[i] > 122 || rule[i] < 97) && rule[i] != 95 {
			start = i + 1
			break
		}

	}
	if start >= pos-ti {
		return structs.RuleData{}
	}
	key := rule[start : pos-ti]

	if pos+2 >= len(rule) {
		return structs.RuleData{}
	}

	end := pos + 2
	if pos+2 < len(rule) && rule[pos+2] == 34 {
		end = pos + 3
	} else {
		for i := pos + 2; i < len(rule)-1; i++ {
			if rule[i] != 92 && rule[i+1] == 34 {
				end = i + 2
				break
			}
		}
	}
	if end-1 < pos+2 {
		end = len(rule)
	}
	if pos+2 >= end {
		return structs.RuleData{}
	}
	value := rule[pos+2 : end-1]
	all := rule[start:end]

	return structs.RuleData{Start: start, End: end, Op: int16(op), Key: key, Value: value, All: all}
}

func ParseRule(rule string) []structs.RuleData {
	var result []structs.RuleData
	empty := structs.RuleData{}

	for {
		data := getRuleData(rule)
		if data == empty {
			break
		}
		result = append(result, data)
		rule = rule[:data.Start] + "T" + rule[data.End:]
	}
	return result
}

func regexMatch(pattern string, s string) (bool, error) {
	matched, err := regexp.MatchString(pattern, s)
	if err != nil {
		return false, err
	}
	return matched, nil
}

// body="123"  op=0  dataSource为http.body dataRule=123
func dataCheckString(op int16, dataSource string, dataRule string) bool {
	dataSource = strings.ToLower(dataSource)

	dataRule = strings.ToLower(dataRule)
	dataRule = strings.ReplaceAll(dataRule, "\\\"", "\"")
	if op == 0 {
		if strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 1 {
		if !strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 2 {
		if dataSource == dataRule {
			return true
		}
	} else if op == 5 {
		rs, err := regexMatch(dataRule, dataSource)
		if err == nil && rs {
			return true
		}
	}
	return false
}

func dataCheckInt(op int16, dataSource int, dataRule int) bool {
	if op == 0 || op == 2 { // 数字相等（= 或 ==）
		if dataSource == dataRule {
			return true
		}
	} else if op == 1 { // 数字不相等
		if dataSource != dataRule {
			return true
		}
	} else if op == 3 { // 大于等于
		if dataSource >= dataRule {
			return true
		}
	} else if op == 4 {
		if dataSource <= dataRule {
			return true
		}
	}
	return false
}

func SingleCheck(finger structs.FingerPEntity, Protocol string, headerString string, body string,
	Server string, Title string, Cert string, Port int, Path string, Hash string, IconHash string, StatusCode int,
	ContentType string, Banner string) bool {
	return evalFinger(finger, Protocol, headerString, body, Server, Title, Cert, Port, Path, Hash, IconHash, StatusCode, ContentType, Banner, false)
}

// DirProbeCheck evaluates a fingerprint against a directory-probe response.
// The scanner chose the path, so path= clauses and body/title values derived
// from that path are never evidence. A product must still prove itself with
// path-independent content (title, cookie/header, icon, distinctive body).
func DirProbeCheck(finger structs.FingerPEntity, Protocol string, headerString string, body string,
	Server string, Title string, Cert string, Port int, Path string, Hash string, IconHash string, StatusCode int,
	ContentType string, Banner string) bool {
	return evalFinger(finger, Protocol, headerString, body, Server, Title, Cert, Port, Path, Hash, IconHash, StatusCode, ContentType, Banner, true)
}

func isContentEvidenceKey(key string) bool {
	switch key {
	case "body", "title", "header", "server", "cert", "icon_hash", "body_hash", "banner":
		return true
	default:
		return false
	}
}

func normalizeProbePath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimSuffix(path, "/")
}

func isProbePathReflection(ruleValue, probePath string) bool {
	value := strings.ToLower(strings.TrimSpace(strings.Trim(ruleValue, `"'`)))
	path := normalizeProbePath(probePath)
	if value == "" || path == "" || path == "/" {
		return false
	}
	value = strings.TrimSuffix(value, "/")
	if value == "" {
		return false
	}
	if value == path {
		return true
	}
	if strings.Contains(value, path+"/") || strings.HasSuffix(value, path) || strings.Contains(value, path+"?") {
		return true
	}
	if strings.HasPrefix(value, "/") && (strings.HasPrefix(path, value) || strings.HasPrefix(value, path) || value == strings.TrimPrefix(path, "/")) {
		return true
	}
	return false
}

func isProbePathBodyToken(ruleValue, probePath string) bool {
	value := strings.ToLower(strings.TrimSpace(strings.Trim(ruleValue, `"'`)))
	path := normalizeProbePath(probePath)
	if value == "" || path == "" || path == "/" {
		return false
	}
	if strings.ContainsAny(value, "/?#") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || !isSignificantProbeToken(part) {
			continue
		}
		if value == part {
			return true
		}
	}
	return false
}

func isSignificantProbeToken(value string) bool {
	if strings.ContainsAny(value, "/._-") {
		return len(value) >= 2
	}
	return len([]rune(value)) >= 4
}

func evalFinger(finger structs.FingerPEntity, Protocol string, headerString string, body string,
	Server string, Title string, Cert string, Port int, Path string, Hash string, IconHash string, StatusCode int,
	ContentType string, Banner string, dirProbe bool) bool {
	rules := finger.Rule
	expr := finger.AllString
	contentEvidence := false

	for _, singleRule := range rules {
		if singleRule.Start < 0 || singleRule.End > len(expr) || singleRule.Start > singleRule.End {
			return false
		}
		singleRuleResult := false
		if singleRule.Key == "header" {
			if dataCheckString(singleRule.Op, headerString, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "body" {
			if dataCheckString(singleRule.Op, body, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "server" {
			if dataCheckString(singleRule.Op, Server, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "title" {
			if dataCheckString(singleRule.Op, Title, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "cert" {
			if dataCheckString(singleRule.Op, Cert, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "port" {
			value, err := strconv.Atoi(singleRule.Value)
			if err == nil && dataCheckInt(singleRule.Op, Port, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "protocol" {
			if singleRule.Op == 0 {
				if Protocol == singleRule.Value {
					singleRuleResult = true
				}
			} else if singleRule.Op == 1 {
				if Protocol != singleRule.Value {
					singleRuleResult = true
				}
			}
		} else if singleRule.Key == "path" {
			if dataCheckString(singleRule.Op, Path, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "body_hash" {

			if dataCheckString(singleRule.Op, Hash, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "icon_hash" {
			value, err := strconv.Atoi(singleRule.Value)
			hashIcon, errHash := strconv.Atoi(IconHash)
			if err == nil && errHash == nil && dataCheckInt(singleRule.Op, hashIcon, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "status" {
			value, err := strconv.Atoi(singleRule.Value)
			if err == nil && dataCheckInt(singleRule.Op, StatusCode, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "content_type" {
			if dataCheckString(singleRule.Op, ContentType, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "banner" {
			if dataCheckString(singleRule.Op, Banner, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "type" {
			if singleRule.Value == "service" {
				singleRuleResult = true
			}
		}
		if dirProbe && singleRule.Op != 1 {
			switch singleRule.Key {
			case "title":
				if isProbePathReflection(singleRule.Value, Path) {
					singleRuleResult = false
				}
			case "body":
				if isProbePathReflection(singleRule.Value, Path) || isProbePathBodyToken(singleRule.Value, Path) {
					singleRuleResult = false
				}
			}
		}
		if singleRuleResult && isContentEvidenceKey(singleRule.Key) {
			contentEvidence = true
		}
		if singleRuleResult {
			expr = expr[:singleRule.Start] + "T" + expr[singleRule.End:]
		} else {
			expr = expr[:singleRule.Start] + "F" + expr[singleRule.End:]
		}
	}

	if !boolEval(expr) {
		return false
	}
	if dirProbe && !contentEvidence {
		return false
	}
	return true
}
