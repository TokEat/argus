package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// deriveFofaExpr 把单请求 nuclei tech/panel 模板的 matchers 忠实翻译为
// ddfinger 可解析的 FOFA 表达式。无法无损表达的模板返回错误（由调用方拒绝）。
func deriveFofaExpr(t *NucleiTemplate) (string, error) {
	reqs := t.AllHTTP()
	if len(reqs) != 1 {
		return "", fmt.Errorf("multi-request template")
	}
	r := reqs[0]
	if len(r.Raw) > 0 {
		return "", fmt.Errorf("raw request")
	}
	if r.Attack != "" || len(r.Payloads) > 0 {
		return "", fmt.Errorf("payload fuzzing")
	}
	if len(r.Matchers) == 0 {
		return "", fmt.Errorf("no matchers")
	}
	var groups []string
	for _, m := range r.Matchers {
		g, err := matcherToFofa(m)
		if err != nil {
			return "", err
		}
		if g != "" {
			groups = append(groups, "("+g+")")
		}
	}
	if len(groups) == 0 {
		return "", fmt.Errorf("no translatable matchers")
	}
	cond := " || "
	if strings.EqualFold(strings.TrimSpace(r.MatchersCondition), "and") {
		cond = " && "
	}
	// 组去重
	seen := map[string]bool{}
	uniq := groups[:0:0]
	for _, g := range groups {
		if !seen[g] {
			seen[g] = true
			uniq = append(uniq, g)
		}
	}
	if len(uniq) == 1 {
		return strings.TrimPrefix(strings.TrimSuffix(uniq[0], ")"), "("), nil
	}
	return strings.Join(uniq, cond), nil
}

var containsDSLRe = regexp.MustCompile(`^contains\(\s*(body|title|header|all_headers)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)$`)
var statusDSLRe = regexp.MustCompile(`^status_code\s*==\s*(\d{3})$`)

// dslToFofaAtoms 支持 nuclei tech 模板常见 dsl 子集：
// contains(part,"x") 与 status_code == N 以 && 连接（|| 组合不保真，拒绝）。
func dslToFofaAtoms(expr, defaultPart, op string) ([]string, error) {
	expr = strings.TrimSpace(expr)
	if strings.Contains(expr, "||") {
		return nil, fmt.Errorf("dsl subset (||): %q", expr)
	}
	var atoms []string
	for _, term := range strings.Split(expr, "&&") {
		term = strings.TrimSpace(term)
		if sub := containsDSLRe.FindStringSubmatch(term); sub != nil {
			p := sub[1]
			if p == "all_headers" {
				p = "header"
			}
			word := strings.ReplaceAll(sub[2], `\"`, `"`)
			if strings.Contains(word, "{{") {
				return nil, fmt.Errorf("dynamic variable in dsl")
			}
			if strings.ContainsAny(word, "\n\r") {
				return nil, fmt.Errorf("multiline dsl word")
			}
			atoms = append(atoms, p+op+"\""+escapeFofaValue(word)+"\"")
			continue
		}
		if sub := statusDSLRe.FindStringSubmatch(term); sub != nil {
			atoms = append(atoms, "status=\""+sub[1]+"\"")
			continue
		}
		return nil, fmt.Errorf("dsl subset: %q", expr)
	}
	return atoms, nil
}

func matcherToFofa(m *NucleiMatcher) (string, error) {
	part := strings.TrimSpace(m.Part)
	switch part {
	case "", "body":
		part = "body"
	case "title", "header", "all_headers":
	case "all":
		return "", fmt.Errorf("part=all not expressible")
	default:
		return "", fmt.Errorf("unsupported part %q", m.Part)
	}
	op := "="
	if m.Negative {
		op = "!="
	}
	inner := " || "
	if strings.EqualFold(strings.TrimSpace(m.Condition), "and") {
		inner = " && "
	}

	var atoms []string
	addWord := func(v string, negate bool) error {
		if strings.Contains(v, "{{") {
			return fmt.Errorf("dynamic variable in matcher word")
		}
		if strings.ContainsAny(v, "\n\r") {
			return fmt.Errorf("multiline matcher word")
		}
		o := op
		if negate {
			o = "!="
		}
		atoms = append(atoms, part+o+"\""+escapeFofaValue(v)+"\"")
		return nil
	}

	switch m.Type {
	case "word":
		for _, w := range m.Words {
			if err := addWord(w, m.Negative); err != nil {
				return "", err
			}
		}
	case "regex":
		if m.Negative {
			return "", fmt.Errorf("negative regex not expressible")
		}
		for _, re := range m.Regex {
			if strings.Contains(re, "{{") {
				return "", fmt.Errorf("dynamic variable in matcher regex")
			}
			if _, err := regexp.Compile(re); err != nil {
				return "", fmt.Errorf("invalid regex: %w", err)
			}
			atoms = append(atoms, part+"~=\""+escapeFofaValue(re)+"\"")
		}
	case "status":
		if m.Negative {
			return "", fmt.Errorf("negative status not expressible")
		}
		for _, code := range m.Status {
			atoms = append(atoms, "status=\""+strconv.Itoa(code)+"\"")
		}
	case "dsl":
		for _, expr := range m.DSL {
			atomsIn, err := dslToFofaAtoms(expr, part, op)
			if err != nil {
				return "", err
			}
			atoms = append(atoms, atomsIn...)
		}
	default:
		return "", fmt.Errorf("unsupported matcher type %q", m.Type)
	}
	return strings.Join(atoms, inner), nil
}

// escapeFofaValue 转义 fofa 双引号字符串值（ddfinger 会把 \" 还原为 "）。
func escapeFofaValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return v
}

// activeFPEligible 判定 nuclei tech/panel 模板是否可转换为自动安全主动指纹：
// 单请求 GET {{BaseURL}} + word/regex/status matcher（ddfinger 语义对齐）。
func activeFPEligible(t *NucleiTemplate) (bool, string) {
	reqs := t.AllHTTP()
	if len(reqs) != 1 {
		return false, "multi-request"
	}
	r := reqs[0]
	if len(r.Raw) > 0 {
		return false, "raw request"
	}
	if r.Attack != "" || len(r.Payloads) > 0 {
		return false, "payloads"
	}
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	if method != "GET" && method != "HEAD" && method != "" {
		return false, "method " + method
	}
	if len(r.Path) != 1 || strings.TrimSpace(r.Path[0]) != "{{BaseURL}}" {
		return false, "path is not bare {{BaseURL}}"
	}
	if len(r.Matchers) == 0 {
		return false, "no matchers"
	}
	for _, m := range r.Matchers {
		if m.Type != "word" && m.Type != "regex" && m.Type != "status" {
			return false, "matcher type " + m.Type
		}
		part := strings.TrimSpace(m.Part)
		if part != "" && part != "body" && part != "title" && part != "header" && part != "all_headers" {
			return false, "matcher part " + part
		}
		for _, w := range m.Words {
			if strings.Contains(w, "{{") {
				return false, "dynamic matcher word"
			}
		}
		for _, re := range m.Regex {
			if strings.Contains(re, "{{") {
				return false, "dynamic matcher regex"
			}
		}
	}
	if r.MaxRedirects > 2 {
		return false, "redirects > 2"
	}
	return true, ""
}

// buildActiveFPYaml 生成 argus 主动指纹 YAML（受 contract 约束）。
// 注入 X-Argus-Rp 探测头满足 behavior-kind=header 的 {{randstr}} 探针要求；
// profile 标 controlled——auto-safe 名额有限，默认不占，由 select 阶段精选。
func buildActiveFPYaml(t *NucleiTemplate, product string) (string, error) {
	r := t.AllHTTP()[0]
	var matchers []map[string]interface{}
	for _, m := range r.Matchers {
		part := strings.TrimSpace(m.Part)
		if part == "" {
			part = "body"
		}
		if part == "all_headers" {
			part = "header"
		}
		mm := map[string]interface{}{"type": m.Type, "part": part}
		switch m.Type {
		case "word":
			mm["words"] = m.Words
		case "regex":
			mm["regex"] = m.Regex
		case "status":
			mm["status"] = m.Status
		}
		if m.Negative {
			mm["negative"] = true
		}
		if m.CaseInsensitive {
			mm["case-insensitive"] = true
		}
		matchers = append(matchers, mm)
	}
	req := map[string]interface{}{
		"method":  "GET",
		"path":    []string{"{{BaseURL}}"},
		"headers": map[string]string{"X-Argus-Rp": "{{randstr}}"},
		"matchers": matchers,
	}
	if strings.EqualFold(strings.TrimSpace(r.MatchersCondition), "and") {
		req["matchers-condition"] = "and"
	}

	info := map[string]interface{}{
		"name":     firstNonEmpty(t.Info.Name, t.ID) + " - Active Fingerprint",
		"author":   firstNonEmpty(t.Info.Author, "argus-import"),
		"severity": "info",
		"metadata": map[string]string{
			"argus-rule-kind":       "active-fingerprint",
			"argus-product":         product,
			"argus-behavior-kind":   "header",
			"argus-auto-profile":    "controlled",
			"argus-import-source":   "nuclei-templates",
			"max-request":           "1",
		},
	}
	if len(t.Info.Tags) > 0 {
		info["tags"] = t.Info.Tags + ",argus-import"
	}

	doc := map[string]interface{}{
		"id":   "afp-" + t.ID,
		"info": info,
		"http": []interface{}{req},
	}
	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	return "# 来源: nuclei-templates（tech/panel 模板转换为主动指纹）\n" + sb.String(), nil
}
