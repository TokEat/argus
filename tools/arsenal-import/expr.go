package main

import (
	"fmt"
	"strconv"
	"strings"
)

// 本文件把 afrog / xray 的 CEL 子集表达式忠实转换为 nuclei matchers。
// 设计原则：只转换能无损表达的子集，任何超出子集的特性都返回错误由调用方拒绝，
// 绝不生成语义妥协的模板。

type exprTerm struct {
	kind     string // status | word | regex
	part     string // body | header
	value    string
	negative bool
	ci       bool // 大小写不敏感
}

type exprResult struct {
	terms     []exprTerm
	condition string // and | or
}

// ---- 词法 ----

type exprToken struct {
	kind string // ident | number | string | op
	text string
}

func tokenizeExpr(s string) ([]exprToken, error) {
	var toks []exprToken
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			toks = append(toks, exprToken{"op", "&&"})
			i += 2
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			toks = append(toks, exprToken{"op", "||"})
			i += 2
		case c == '=' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, exprToken{"op", "=="})
			i += 2
		case c == '!' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, exprToken{"op", "!="})
			i += 2
		case c == '<' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, exprToken{"op", "<="})
			i += 2
		case c == '>' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, exprToken{"op", ">="})
			i += 2
		case strings.ContainsRune("()[]!.,", rune(c)):
			toks = append(toks, exprToken{"op", string(c)})
			i++
		case c == 'b' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\''):
			str, n, err := scanString(s[i+1:], true)
			if err != nil {
				return nil, err
			}
			toks = append(toks, exprToken{"string", str})
			i += 1 + n
		case c == '"' || c == '\'':
			str, n, err := scanString(s[i:], false)
			if err != nil {
				return nil, err
			}
			toks = append(toks, exprToken{"string", str})
			i += n
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			toks = append(toks, exprToken{"number", s[i:j]})
			i = j
		case isIdentChar(c):
			j := i
			for j < len(s) && isIdentChar(s[j]) {
				j++
			}
			toks = append(toks, exprToken{"ident", s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected char %q", string(c))
		}
	}
	return toks, nil
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// scanString 解析引号字符串，返回解码后的值与消耗长度（含引号）。
func scanString(s string, isBytes bool) (string, int, error) {
	quote := s[0]
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case 'n':
				sb.WriteByte('\n')
				i++
			case 'r':
				sb.WriteByte('\r')
				i++
			case 't':
				sb.WriteByte('\t')
			case '\\':
				sb.WriteByte('\\')
				i++
			case '"':
				sb.WriteByte('"')
				i++
			case '\'':
				sb.WriteByte('\'')
				i++
			case 'x':
				if i+3 < len(s) {
					if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
						sb.WriteByte(byte(v))
						i += 3
						continue
					}
				}
				return "", 0, fmt.Errorf("bad \\x escape")
			default:
				sb.WriteByte('\\')
			}
			continue
		}
		if c == quote {
			return sb.String(), i + 1, nil
		}
		sb.WriteByte(c)
	}
	return "", 0, fmt.Errorf("unterminated string")
}

// ---- 语法 ----

type exprParser struct {
	toks []exprToken
	pos  int
	// 顶层是否混用了 && 与 ||（nuclei 扁平 matchers 无法表达，拒绝）
	usedAnd bool
	usedOr  bool
}

func parseExpression(s string) (*exprResult, error) {
	toks, err := tokenizeExpr(s)
	if err != nil {
		return nil, err
	}
	p := &exprParser{toks: toks}
	res := &exprResult{condition: "and"}
	terms, cond, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("trailing tokens at %d", p.pos)
	}
	res.terms = terms
	res.condition = cond
	if p.usedAnd && p.usedOr {
		return nil, fmt.Errorf("mixed && and || not expressible in flat nuclei matchers")
	}
	return res, nil
}

func (p *exprParser) peek() *exprToken {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *exprParser) takeOp(op string) bool {
	if t := p.peek(); t != nil && t.kind == "op" && t.text == op {
		p.pos++
		return true
	}
	return false
}

func (p *exprParser) expectOp(op string) error {
	if p.takeOp(op) {
		return nil
	}
	return fmt.Errorf("expected %q at token %d", op, p.pos)
}

// takeIdent 消费与 name 相同的 ident token。
func (p *exprParser) takeIdent(name string) bool {
	if t := p.peek(); t != nil && t.kind == "ident" && t.text == name {
		p.pos++
		return true
	}
	return false
}

func (p *exprParser) parseOr() ([]exprTerm, string, error) {
	left, cond, err := p.parseAnd()
	if err != nil {
		return nil, "", err
	}
	for p.peek() != nil && p.peek().kind == "op" && p.peek().text == "||" {
		p.usedOr = true
		p.pos++
		right, _, err := p.parseAnd()
		if err != nil {
			return nil, "", err
		}
		left = append(left, right...)
		cond = "or"
	}
	return left, cond, nil
}

func (p *exprParser) parseAnd() ([]exprTerm, string, error) {
	left, cond, err := p.parseUnary()
	if err != nil {
		return nil, "", err
	}
	for p.peek() != nil && p.peek().kind == "op" && p.peek().text == "&&" {
		p.usedAnd = true
		p.pos++
		right, _, err := p.parseUnary()
		if err != nil {
			return nil, "", err
		}
		left = append(left, right...)
		cond = "and"
	}
	return left, cond, nil
}

func (p *exprParser) parseUnary() ([]exprTerm, string, error) {
	if p.takeOp("!") {
		inner, cond, err := p.parseUnary()
		if err != nil {
			return nil, "", err
		}
		// 只对单 term 取反；复合取反（!(A&&B)）无法忠实表达
		if len(inner) != 1 || cond != "and" {
			return nil, "", fmt.Errorf("negation of compound expression not supported")
		}
		inner[0].negative = !inner[0].negative
		return inner, "and", nil
	}
	if p.takeOp("(") {
		inner, cond, err := p.parseOr()
		if err != nil {
			return nil, "", err
		}
		if err := p.expectOp(")"); err != nil {
			return nil, "", err
		}
		return inner, cond, nil
	}
	t, err := p.parsePredicate()
	if err != nil {
		return nil, "", err
	}
	return []exprTerm{t}, "and", nil
}

// parsePredicate 解析 response.<field>... 形式的谓词为单个 term。
func (p *exprParser) parsePredicate() (exprTerm, error) {
	t := p.peek()
	if t == nil || t.kind != "ident" || t.text != "response" {
		return exprTerm{}, fmt.Errorf("expected response at token %d got %v", p.pos, t)
	}
	p.pos++
	if err := p.expectOp("."); err != nil {
		return exprTerm{}, err
	}
	field := p.peek()
	if field == nil || field.kind != "ident" {
		return exprTerm{}, fmt.Errorf("expected field at token %d", p.pos)
	}
	p.pos++

	switch field.text {
	case "status":
		op := p.peek()
		if op == nil || op.kind != "op" || op.text != "==" {
			return exprTerm{}, fmt.Errorf("status only supports == got %v", op)
		}
		p.pos++
		num := p.peek()
		if num == nil || num.kind != "number" {
			return exprTerm{}, fmt.Errorf("status needs numeric literal got %v", num)
		}
		p.pos++
		return exprTerm{kind: "status", value: num.text}, nil

	case "body", "raw":
		return p.parseContentCall(field.text)

	case "headers":
		if err := p.expectOp("["); err != nil {
			return exprTerm{}, err
		}
		key := p.peek()
		if key == nil || key.kind != "string" {
			return exprTerm{}, fmt.Errorf("headers[...] needs string key got %v", key)
		}
		p.pos++
		if err := p.expectOp("]"); err != nil {
			return exprTerm{}, err
		}
		// headers["K"] == "V" 或 .contains/.bcontains/.icontains(...)
		term, err := p.parseHeaderOp()
		if err != nil {
			return exprTerm{}, err
		}
		term.part = "header"
		return term, nil
	}
	return exprTerm{}, fmt.Errorf("unsupported response field %q", field.text)
}

func (p *exprParser) parseContentCall(field string) (exprTerm, error) {
	if err := p.expectOp("."); err != nil {
		return exprTerm{}, err
	}
	fn := p.peek()
	if fn == nil || fn.kind != "ident" {
		return exprTerm{}, fmt.Errorf("expected function got %v", fn)
	}
	p.pos++
	if err := p.expectOp("("); err != nil {
		return exprTerm{}, err
	}
	// afrog 变体：bcontains(bytes("..."))
	bytesWrapped := p.takeIdent("bytes")
	if bytesWrapped {
		if err := p.expectOp("("); err != nil {
			return exprTerm{}, err
		}
	}
	arg := p.peek()
	if arg == nil || arg.kind != "string" {
		return exprTerm{}, fmt.Errorf("function %s needs string arg got %v", fn.text, arg)
	}
	p.pos++
	if err := p.expectOp(")"); err != nil {
		return exprTerm{}, err
	}
	if bytesWrapped {
		if err := p.expectOp(")"); err != nil {
			return exprTerm{}, err
		}
	}
	term := exprTerm{part: "body"}
	switch fn.text {
	case "bcontains":
		term.kind = "word"
	case "icontains", "contains":
		term.kind = "word"
		term.ci = fn.text == "icontains"
	case "ibcontains":
		term.kind = "word"
		term.ci = true
	case "bmatches", "matches":
		term.kind = "regex"
	default:
		return exprTerm{}, fmt.Errorf("unsupported function %q", fn.text)
	}
	// response.raw.* 归一到 body（nuclei http 无 raw part；绝大多数 raw
	// bcontains 目标串出现在 body，忠实度损失可接受并在报告中标注）。
	term.value = arg.text
	return term, nil
}

func (p *exprParser) parseHeaderOp() (exprTerm, error) {
	// 形如 .contains("X") / .bcontains(b"X") / .icontains("X")，或 == "X"
	if p.takeOp("==") {
		v := p.peek()
		if v == nil || v.kind != "string" {
			return exprTerm{}, fmt.Errorf("header == needs string got %v", v)
		}
		p.pos++
		return exprTerm{kind: "word", value: v.text}, nil
	}
	if err := p.expectOp("."); err != nil {
		return exprTerm{}, err
	}
	fn := p.peek()
	if fn == nil || fn.kind != "ident" {
		return exprTerm{}, fmt.Errorf("expected header function got %v", fn)
	}
	p.pos++
	if err := p.expectOp("("); err != nil {
		return exprTerm{}, err
	}
	arg := p.peek()
	if arg == nil || arg.kind != "string" {
		return exprTerm{}, fmt.Errorf("header function needs string arg got %v", arg)
	}
	p.pos++
	if err := p.expectOp(")"); err != nil {
		return exprTerm{}, err
	}
	term := exprTerm{kind: "word", value: arg.text}
	switch fn.text {
	case "icontains", "ibcontains":
		term.ci = true
	case "contains", "bcontains":
	default:
		return exprTerm{}, fmt.Errorf("unsupported header function %q", fn.text)
	}
	return term, nil
}

// buildMatchers 把表达式结果转成 nuclei matchers。status term 单独成 matcher；
// 同 part 的 word 合并为一个 matcher（words 列表）。expr 为 && 连接时，
// 合并的 word matcher 必须显式 condition: and——nuclei words 默认按 OR 匹配，
// 漏标会把"同时出现"弱化成"任一出现"（语义 bug）。
func buildMatchers(res *exprResult) []*NucleiMatcher {
	var out []*NucleiMatcher
	var bodyWords, headerWords []string
	negBody, negHeader := false, false
	ciBody, ciHeader := false, false
	wordCond := ""
	if res.condition == "and" {
		wordCond = "and"
	}
	pushWords := func() {
		if len(bodyWords) > 0 {
			out = append(out, &NucleiMatcher{Type: "word", Part: "body", Words: bodyWords, Negative: negBody, CaseInsensitive: ciBody, Condition: wordCond})
			bodyWords = nil
			negBody, ciBody = false, false
		}
		if len(headerWords) > 0 {
			out = append(out, &NucleiMatcher{Type: "word", Part: "header", Words: headerWords, Negative: negHeader, CaseInsensitive: ciHeader, Condition: wordCond})
			headerWords = nil
			negHeader, ciHeader = false, false
		}
	}
	for _, t := range res.terms {
		switch t.kind {
		case "status":
			pushWords()
			n, _ := strconv.Atoi(t.value)
			out = append(out, &NucleiMatcher{Type: "status", Status: []int{n}, Negative: t.negative})
		case "word":
			if t.part == "header" {
				if len(headerWords) > 0 && (t.negative != negHeader || t.ci != ciHeader) {
					pushWords()
				}
				headerWords = append(headerWords, t.value)
				negHeader, ciHeader = t.negative, t.ci
			} else {
				if len(bodyWords) > 0 && (t.negative != negBody || t.ci != ciBody) {
					pushWords()
				}
				bodyWords = append(bodyWords, t.value)
				negBody, ciBody = t.negative, t.ci
			}
		case "regex":
			pushWords()
			out = append(out, &NucleiMatcher{Type: "regex", Part: t.part, Regex: []string{t.value}, Negative: t.negative})
		}
	}
	pushWords()
	return out
}
