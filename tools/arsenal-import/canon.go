package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/TokEat/argus/scanner/lib/ddfinger"
)

// ---- POC 规范形 ----
// 目标：把"语义等价"的检测逻辑归一到同一表示，使精确重复落到同一哈希桶、
// 近重复在 token 集合上呈现高 Jaccard。请求侧脱敏（模板变量/数字串），
// matcher 侧取 type+part+token 小写排序。

var (
	tmplVarRe = regexp.MustCompile(`\{\{[^}]*\}\}`)
	digitRunRe = regexp.MustCompile(`\d+`)
)

func maskValue(s string) string {
	s = tmplVarRe.ReplaceAllString(s, "{}")
	s = digitRunRe.ReplaceAllString(s, "N")
	return strings.ToLower(s)
}

func normalizePath(p string) string {
	p = maskValue(p)
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func matcherCanonTokens(m *NucleiMatcher) []string {
	part := strings.ToLower(strings.TrimSpace(m.Part))
	if part == "" {
		part = "body"
	}
	mt := strings.ToLower(strings.TrimSpace(m.Type))
	var toks []string
	add := func(v string) { toks = append(toks, mt+":"+part+":"+strings.ToLower(v)) }
	for _, w := range m.Words {
		add(w)
	}
	for _, re := range m.Regex {
		add(re)
	}
	for _, s := range m.Status {
		add("s" + strconv.Itoa(s))
	}
	for _, b := range m.Binary {
		add("bin:" + b)
	}
	for _, d := range m.DSL {
		add("dsl:" + d)
	}
	return toks
}

// pocCanon 返回精确规范串与 token 集合；无法提取 http 请求返回 ok=false。
func pocCanon(t *NucleiTemplate) (string, []string, bool) {
	reqs := t.AllHTTP()
	if len(reqs) == 0 {
		return "", nil, false
	}
	var sb strings.Builder
	var tokens []string
	for _, r := range reqs {
		method := strings.ToUpper(strings.TrimSpace(r.Method))
		if method == "" {
			method = "GET"
		}
		sb.WriteString("M:" + method + ";")
		var paths []string
		for _, p := range r.Path {
			np := normalizePath(p)
			paths = append(paths, np)
			tokens = append(tokens, "p:"+np)
		}
		for _, raw := range r.Raw {
			mr := maskValue(raw)
			// raw 请求取首行（请求行）作 path token，整段进精确串
			first := mr
			if i := strings.IndexByte(mr, '\n'); i >= 0 {
				first = strings.TrimSpace(mr[:i])
			}
			paths = append(paths, "raw:"+first)
			sb.WriteString("RAW:" + mr + ";")
		}
		sb.WriteString("P:" + strings.Join(uniqueSorted(paths), ",") + ";")
		var hdrs []string
		for k, v := range r.Headers {
			hdrs = append(hdrs, strings.ToLower(strings.TrimSpace(k))+"="+maskValue(v))
		}
		sb.WriteString("H:" + strings.Join(uniqueSorted(hdrs), ",") + ";")
		sb.WriteString("B:" + maskValue(r.Body) + ";")
		var mtoks []string
		for _, m := range r.Matchers {
			mtoks = append(mtoks, matcherCanonTokens(m)...)
		}
		mtoks = uniqueSorted(mtoks)
		sb.WriteString("MT:" + strings.Join(mtoks, ",") + ";")
		sb.WriteString("MC:" + strings.ToLower(strings.TrimSpace(r.MatchersCondition)))
		tokens = append(tokens, mtoks...)
	}
	return sb.String(), uniqueSorted(tokens), true
}

// ---- fofa 规范形 ----

var fofaOpSym = map[int16]string{0: "=", 1: "!=", 2: "==", 3: ">=", 4: "<=", 5: "~="}

// fofaCanon 返回精确规范串（整体小写去空白，ddfinger 匹配大小写不敏感）与
// 归一原子集合（key+op+unescape(value) 小写，用于近重复 Jaccard）。
func fofaCanon(expr string) (string, []string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || strings.Count(expr, "(") != strings.Count(expr, ")") {
		return "", nil, false
	}
	atoms := ddfinger.ParseRule(expr)
	if len(atoms) == 0 {
		return "", nil, false
	}
	exact := strings.ToLower(strings.Join(strings.Fields(expr), ""))
	var toks []string
	for _, a := range atoms {
		v := strings.ToLower(unescapeFofaValue(a.Value))
		op, ok := fofaOpSym[a.Op]
		if !ok {
			op = "="
		}
		toks = append(toks, a.Key+op+v)
	}
	return exact, uniqueSorted(toks), true
}

// unescapeFofaValue 还原 ddfinger 值里被 escapeFofaValue 加的反斜杠转义。
func unescapeFofaValue(v string) string {
	v = strings.ReplaceAll(v, `\"`, `"`)
	v = strings.ReplaceAll(v, `\\`, `\`)
	return v
}

// ---- 现有库加载 ----

// loadExistingPocs 解析 config/pocs 下全部 nuclei POC，返回 文件名→(canon, tokens)。
func loadExistingPocs(configDir string) map[string]existingCanon {
	out := map[string]existingCanon{}
	files, err := filepath.Glob(filepath.Join(configDir, "pocs", "*.yaml"))
	if err != nil {
		return out
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		t, err := parseNucleiTemplate(data)
		if err != nil {
			continue
		}
		canon, toks, ok := pocCanon(t)
		if !ok {
			continue
		}
		out[filepath.Base(f)] = existingCanon{canon: canon, tokens: toks}
	}
	return out
}

type existingCanon struct {
	canon  string
	tokens []string
}

// loadExistingFingers 解析 config/finger.yaml，返回 产品→表达式列表（原文）。
func loadExistingFingers(configDir string) map[string][]string {
	out := map[string][]string{}
	data, err := os.ReadFile(filepath.Join(configDir, "finger.yaml"))
	if err != nil {
		return out
	}
	var m map[string][]string
	if err := yaml.Unmarshal(data, &m); err != nil {
		return out
	}
	return m
}
