package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RejectRow 记录被拒绝的源文件及原因（进入报告）。
type RejectRow struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type convertResult struct {
	Candidates []Candidate `json:"candidates"`
	Rejected   []RejectRow `json:"rejected"`
}

func runConvert(opt *options) error {
	var manifest FetchManifest
	if err := readPhase(opt.workdir, "fetch", &manifest); err != nil {
		return err
	}
	res := convertResult{}
	for _, src := range manifest.Sources {
		if src.Err != "" {
			continue
		}
		before := len(res.Candidates)
		for _, rel := range src.Files {
			full := filepath.Join(src.Dir, filepath.FromSlash(rel))
			data, err := os.ReadFile(full)
			if err != nil {
				res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "read: " + err.Error()})
				continue
			}
			switch src.Spec.Name {
			case "nuclei-templates":
				convertNucleiFile(src, rel, data, &res)
			case "afrog", "xray":
				convertExprFile(src, rel, data, &res)
			}
		}
		fmt.Printf("[convert] %-16s +%-5d (%s)\n", src.Spec.Name, len(res.Candidates)-before, src.Spec.Repo)
	}
	if err := writePhase(opt.workdir, "convert", res); err != nil {
		return err
	}
	fmt.Printf("\n候选 %d，拒绝 %d → %s\n", len(res.Candidates), len(res.Rejected), phasePath(opt.workdir, "convert"))
	return printRejectSummary(res.Rejected)
}

func printRejectSummary(rejects []RejectRow) error {
	byReason := map[string]int{}
	for _, r := range rejects {
		byReason[r.Reason]++
	}
	type kv struct {
		reason string
		n      int
	}
	var rows []kv
	for reason, n := range byReason {
		rows = append(rows, kv{reason, n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
	fmt.Println("\n拒绝原因 Top10:")
	for i, row := range rows {
		if i >= 10 {
			break
		}
		fmt.Printf("  %5d  %s\n", row.n, row.reason)
	}
	return nil
}

// ---- nuclei-templates：POC 透传 + 指纹派生 ----

func convertNucleiFile(src SourceFetch, rel string, data []byte, res *convertResult) {
	t, err := parseNucleiTemplate(data)
	if err != nil {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "yaml parse: " + err.Error()})
		return
	}
	if strings.TrimSpace(t.ID) == "" {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "missing id"})
		return
	}
	if block := t.NonHTTPBlocked(); block != "" {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "blocked: " + block})
		return
	}
	if len(t.AllHTTP()) == 0 {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "no http block"})
		return
	}

	base := Candidate{
		Kind:    KindPoc,
		Source:  src.Spec.Name,
		License: src.License,
		SrcPath: rel,
		ID:      t.ID,
		FileName: t.ID + ".yaml",
		Content: t.Raw,
		Severity: strings.ToLower(strings.TrimSpace(t.Info.Severity)),
		Tags:    splitTags(t.Info.Tags),
		Product: t.Info.MetaString("product"),
		Vendor:  t.Info.MetaString("vendor"),
	}
	if cves := t.Info.CVEs(); len(cves) > 0 {
		base.CVE = cves[0]
	}
	res.Candidates = append(res.Candidates, base)

	// 指纹派生（technologies / exposed-panels 目录）
	if isFingerSourceDir(rel) {
		deriveFingerprints(src, rel, t, res)
	}
}

func isFingerSourceDir(rel string) bool {
	return strings.HasPrefix(rel, "http/technologies/") || strings.HasPrefix(rel, "http/exposed-panels/")
}

func splitTags(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// deriveFingerprints 从 nuclei tech/panel 模板派生指纹候选。
func deriveFingerprints(src SourceFetch, rel string, t *NucleiTemplate, res *convertResult) {
	product := canonProduct(t.Info.MetaString("vendor"), t.Info.MetaString("product"), t.Info.Name)
	if product == "" {
		return
	}
	// 被动 fofa 表达式
	if expr, err := deriveFofaExpr(t); err == nil {
		res.Candidates = append(res.Candidates, Candidate{
			Kind:      KindFinger,
			Source:    src.Spec.Name,
			License:   src.License,
			SrcPath:   rel,
			ID:        "finger-" + t.ID,
			ProductName: product,
			RuleExpr:  expr,
			Product:   t.Info.MetaString("product"),
			Vendor:    t.Info.MetaString("vendor"),
		})
	} else {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "fofa derive: " + err.Error()})
	}
	// 主动指纹（单 GET {{BaseURL}} 子集，数量在 select 阶段限额）
	if ok, reason := activeFPEligible(t); ok {
		content, err := buildActiveFPYaml(t, product)
		if err == nil {
			res.Candidates = append(res.Candidates, Candidate{
				Kind:        KindActiveFP,
				Source:      src.Spec.Name,
				License:     src.License,
				SrcPath:     rel,
				ID:          "afp-" + t.ID,
				FileName:    "afp-" + t.ID + ".yaml",
				Content:     content,
				ProductName: product,
				Product:     t.Info.MetaString("product"),
				Vendor:      t.Info.MetaString("vendor"),
			})
		}
	} else {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "active fp: " + reason})
	}
}

// canonProduct 归一化产品键：Vendor-Product 风格，对齐现有 finger.yaml 命名习惯。
func canonProduct(vendor, product, fallbackName string) string {
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.ReplaceAll(s, "_", "-")
		s = strings.Join(strings.Fields(s), "-")
		return s
	}
	vendor = clean(vendor)
	product = clean(product)
	if product == "" {
		// 从模板名兜底："Apache Tomcat - Detect" → "Apache-Tomcat"
		name := strings.TrimSpace(fallbackName)
		name = strings.TrimSuffix(name, "- Detect")
		name = strings.TrimSuffix(name, "- Panel")
		product = clean(name)
	}
	if product == "" {
		return ""
	}
	if vendor == "" {
		return upperFirst(product)
	}
	return upperFirst(vendor) + "-" + upperFirst(product)
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---- afrog / xray → nuclei ----

func convertExprFile(src SourceFetch, rel string, data []byte, res *convertResult) {
	p, err := parseExprPoc(data)
	if err != nil {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "yaml parse: " + err.Error()})
		return
	}
	id := p.TemplateID()
	if id == "" {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "missing id/name"})
		return
	}
	if p.Transport != "" && p.Transport != "http" {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "blocked: " + p.Transport + " transport"})
		return
	}
	rule, _, err := p.SingleRule()
	if err != nil {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "expr: " + err.Error()})
		return
	}
	exprRes, err := parseExpression(strings.TrimSpace(rule.Expression))
	if err != nil {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "expr: " + err.Error()})
		return
	}
	matchers := buildMatchers(exprRes)
	if len(matchers) == 0 {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "expr: no matchers produced"})
		return
	}

	method := strings.ToUpper(strings.TrimSpace(rule.Request.Method))
	if method == "" {
		method = "GET"
	}
	path := strings.TrimSpace(rule.Request.Path)
	if path == "" {
		path = "/"
	}
	body := rule.Request.Body
	if body == "" {
		body = rule.Request.Content
	}
	// xray 在路径/体内联求值函数（如 md5(99999999)），必须重写为 nuclei
	// {{md5(...)}}；无法映射的内联函数在此拒绝。
	path, err = rewriteInlineFuncs(path)
	if err != nil {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "xray func: " + err.Error()})
		return
	}
	if body != "" {
		body, err = rewriteInlineFuncs(body)
		if err != nil {
			res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "xray func: " + err.Error()})
			return
		}
	}
	headers, err := rewriteHeadersInlineFuncs(rule.Request.Headers)
	if err != nil {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "xray func: " + err.Error()})
		return
	}
	if hasUnknownVars(path) || hasUnknownVars(body) || headersHaveUnknownVars(headers) {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "unresolvable template variables"})
		return
	}

	author := p.Info.Author
	if author == "" {
		author = p.Detail.Author
	}
	severity := strings.ToLower(strings.TrimSpace(p.Info.Severity))
	if severity == "" {
		severity = "medium" // xray 无 severity 字段，默认 medium 供精选层判断
	}
	content, err := emitConvertedNuclei(emitInput{
		ID:          id,
		Name:        firstNonEmpty(p.Info.Name, id),
		Author:      author,
		Severity:    severity,
		Description: p.Info.Description,
		Source:      src.Spec.Name,
		License:     src.License,
		Reference:   p.Detail.Links,
		Tags:        splitTags(p.Info.Tags),
		Method:      method,
		Path:        fullURLPath(path),
		Headers:     headers,
		Body:        body,
		Condition:   exprRes.condition,
		Matchers:    matchers,
	})
	if err != nil {
		res.Rejected = append(res.Rejected, RejectRow{src.Spec.Name, rel, "emit: " + err.Error()})
		return
	}

	res.Candidates = append(res.Candidates, Candidate{
		Kind:     KindPoc,
		Source:   src.Spec.Name,
		License:  src.License,
		SrcPath:  rel,
		ID:       id,
		FileName: id + ".yaml",
		Content:  content,
		Severity: severity,
		Tags:     splitTags(p.Info.Tags),
	})
}

// xrayFuncMap 把 xray/afrog 在路径/请求体里内联求值的函数映射为 nuclei 等价
// DSL 函数。只收录语义一致的对；无法无损映射的函数调用一律拒绝——否则会把
// 字面量 `md5(99999999)` 发出，而 matcher 期待哈希值，造成假阴性。
var xrayFuncMap = map[string]string{
	"md5":          "md5",
	"sha1":         "sha1",
	"sha256":       "sha256",
	"base64":       "base64",
	"base64encode": "base64_encode",
	"base64decode": "base64_decode",
	"urlencode":    "url_encode",
	"urldecode":    "url_decode",
	"hex":          "hex_encode",
	"hexencode":    "hex_encode",
	"hexdecode":    "hex_decode",
	"randomint":    "rand_int",
	"randomstring": "rand_text_alphanumeric",
}

// rewriteInlineFuncs 把 s 中 xray 会内联求值的函数调用 fn(args) 重写为 nuclei
// 的 {{fn(args)}}。xray 只对白名单内的函数求值；其余 ident(...)（如 SQLi 的
// updatexml(...)、XSS 的 alert(...)）是载荷文本，原样透传。已处于 {{...}} 内
// 的跨段保留。args 内部递归重写以支持嵌套求值。
func rewriteInlineFuncs(s string) (string, error) {
	var sb strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '{' && i+1 < len(s) && s[i+1] == '{' {
			j := strings.Index(s[i+2:], "}}")
			if j < 0 {
				sb.WriteString(s[i:])
				break
			}
			sb.WriteString(s[i : i+2+j+2])
			i += 2 + j + 2
			continue
		}
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			j := i
			for j < len(s) && isIdentChar(s[j]) {
				j++
			}
			ident := s[i:j]
			mapped, ok := xrayFuncMap[strings.ToLower(ident)]
			// 仅当 ident 后紧跟 ( 且是已知求值函数时才重写；否则是载荷文本。
			if !ok || j >= len(s) || s[j] != '(' {
				sb.WriteString(ident)
				i = j
				continue
			}
			depth := 0
			k := j
			for k < len(s) {
				if s[k] == '(' {
					depth++
				} else if s[k] == ')' {
					depth--
					if depth == 0 {
						break
					}
				}
				k++
			}
			if k >= len(s) {
				return "", fmt.Errorf("unterminated call %q", ident)
			}
			inner, err := rewriteInlineFuncs(s[j+1 : k])
			if err != nil {
				return "", err
			}
			sb.WriteString("{{" + mapped + "(" + inner + ")}}")
			i = k + 1
			continue
		}
		sb.WriteByte(c)
		i++
	}
	return sb.String(), nil
}

func rewriteHeadersInlineFuncs(h map[string]string) (map[string]string, error) {
	if len(h) == 0 {
		return h, nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		nk, err := rewriteInlineFuncs(k)
		if err != nil {
			return nil, err
		}
		nv, err := rewriteInlineFuncs(v)
		if err != nil {
			return nil, err
		}
		out[nk] = nv
	}
	return out, nil
}

var knownVars = map[string]bool{
	"BaseURL": true, "Hostname": true, "Host": true, "Port": true, "Scheme": true,
	"RootURL": true, "Path": true, "File": true,
}

func hasUnknownVars(s string) bool {
	for _, v := range templateVars(s) {
		if !knownVars[v] && !isNucleiBuiltin(v) {
			return true
		}
	}
	return false
}

func headersHaveUnknownVars(h map[string]string) bool {
	for k, v := range h {
		if hasUnknownVars(k) || hasUnknownVars(v) {
			return true
		}
	}
	return false
}

func templateVars(s string) []string {
	var out []string
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			break
		}
		out = append(out, strings.TrimSpace(s[i+2:i+j]))
		s = s[i+j:]
	}
	return out
}

// isNucleiBuiltin 允许 nuclei 内建函数变量（randstr/md5 等生成器与转换器）。
func isNucleiBuiltin(v string) bool {
	name := v
	if i := strings.Index(v, "("); i > 0 {
		name = v[:i]
	}
	switch name {
	case "randstr", "rand", "rand_base", "rand_text_alpha", "rand_text_alphanumeric", "rand_text_numeric",
		"rand_int", "rand_char", "rand_ip", "rand_mac", "rand_slug", "rand_base64", "rand_hex",
		"uuid", "md5", "sha256", "sha1", "hex", "hex_encode", "hex_decode", "base64", "base64_encode",
		"base64_decode", "url_encode", "url_decode", "html_escape", "html_unescape", "toupper", "tolower",
		"trim", "trim_left", "trim_right", "concat", "contains", "to_number":
		return true
	}
	return false
}

func fullURLPath(path string) string {
	if strings.HasPrefix(path, "{{BaseURL}}") || strings.HasPrefix(path, "{{RootURL}}") || strings.HasPrefix(path, "http") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "{{BaseURL}}" + path
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// emitInput 组装转换后的 nuclei 模板。
type emitInput struct {
	ID, Name, Author, Severity, Description string
	Source, License string
	Reference []string
	Tags []string
	Method, Path string
	Headers map[string]string
	Body string
	Condition string
	Matchers []*NucleiMatcher
}

// emitConvertedNuclei 生成带治理 metadata 的 nuclei YAML。
func emitConvertedNuclei(in emitInput) (string, error) {
	meta := map[string]string{
		"argus-execution-class": "detection",
		"argus-risk-level":      riskFromSeverity(in.Severity),
		"argus-import-source":   in.Source,
	}
	if in.License != "" {
		meta["argus-import-license"] = in.License
	}
	info := map[string]interface{}{
		"name":        in.Name,
		"author":      firstNonEmpty(in.Author, "argus-import"),
		"severity":    in.Severity,
		"description": in.Description,
		"metadata":    meta,
	}
	if len(in.Reference) > 0 {
		info["reference"] = in.Reference
	}
	if len(in.Tags) > 0 {
		info["tags"] = strings.Join(append(in.Tags, "argus-import"), ",")
	} else {
		info["tags"] = "argus-import"
	}

	req := map[string]interface{}{
		"method":   in.Method,
		"path":     []string{in.Path},
		"matchers": in.Matchers,
	}
	if in.Condition == "or" {
		req["matchers-condition"] = "or"
	}
	if len(in.Headers) > 0 {
		req["headers"] = in.Headers
	}
	if strings.TrimSpace(in.Body) != "" {
		req["body"] = in.Body
	}

	doc := map[string]interface{}{
		"id":   in.ID,
		"info": info,
		"http": []interface{}{req},
	}
	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	return "# 来源: " + in.Source + "（转换自 afrog/xray 表达式 POC）\n" + sb.String(), nil
}

func riskFromSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "info":
		return "low"
	default:
		return "unknown"
	}
}
