package main

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ruleRefRe 匹配顶层表达式 "r0()" 形式的单 rule 引用。
var ruleRefRe = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)\(\)$`)

// ---- Nuclei 模板解析（用于元数据提取、指纹派生与去重；POC 本体原样透传）----

type TemplateInfo struct {
	Name        string                 `yaml:"name"`
	Author      string                 `yaml:"author"`
	Severity    string                 `yaml:"severity"`
	Description string                 `yaml:"description"`
	Tags        string                 `yaml:"tags"`
	Metadata    map[string]interface{} `yaml:"metadata"`
	Classification struct {
		CVEID interface{} `yaml:"cve-id"`
	} `yaml:"classification"`
}

// NucleiMatcher 的 yaml tag 全部带 omitempty——本结构同时用于解析源模板与
// 发射转换产物，发射时绝不允许吐出 regex: []/status: []/negative: false 等空字段。
type NucleiMatcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part,omitempty"`
	Words           []string `yaml:"words,omitempty"`
	Regex           []string `yaml:"regex,omitempty"`
	Status          []int    `yaml:"status,omitempty"`
	Binary          []string `yaml:"binary,omitempty"`
	DSL             []string `yaml:"dsl,omitempty"`
	Negative        bool     `yaml:"negative,omitempty"`
	CaseInsensitive bool     `yaml:"case-insensitive,omitempty"`
	Condition       string   `yaml:"condition,omitempty"`
}

type NucleiHTTPRequest struct {
	Method            string              `yaml:"method"`
	Path              []string            `yaml:"path"`
	Raw               []string            `yaml:"raw"`
	Headers           map[string]string   `yaml:"headers"`
	Body              string              `yaml:"body"`
	Matchers          []*NucleiMatcher    `yaml:"matchers"`
	MatchersCondition string              `yaml:"matchers-condition"`
	Extractors        []map[string]interface{} `yaml:"extractors"`
	Redirects         bool                `yaml:"redirects"`
	MaxRedirects      int                 `yaml:"max-redirects"`
	StopAtFirstMatch  bool                `yaml:"stop-at-first-match"`
	CookieReuse       bool                `yaml:"cookie-reuse"`
	Attack            string              `yaml:"attack"`
	Payloads          map[string]interface{} `yaml:"payloads"`
}

type NucleiTemplate struct {
	ID          string               `yaml:"id"`
	Info        TemplateInfo         `yaml:"info"`
	HTTP        []*NucleiHTTPRequest `yaml:"http"`
	Requests    []*NucleiHTTPRequest `yaml:"requests"` // 旧版键
	Variables   map[string]string    `yaml:"variables"`
	Flow        string               `yaml:"flow"`
	Extractors  []map[string]interface{} `yaml:"extractors"`
	// 非 http 协议块存在即拒绝（本工具只收集 http 检测类）。
	TCP  []map[string]interface{} `yaml:"tcp"`
	DNS  []map[string]interface{} `yaml:"dns"`
	SSL  []map[string]interface{} `yaml:"ssl"`
	File []map[string]interface{} `yaml:"file"`
	Headless []map[string]interface{} `yaml:"headless"`
	Code []map[string]interface{} `yaml:"code"`
	// 原始文件内容（POC 透传用）
	Raw string `yaml:"-"`
}

func (t *NucleiTemplate) AllHTTP() []*NucleiHTTPRequest {
	if len(t.HTTP) > 0 {
		return t.HTTP
	}
	return t.Requests
}

// NonHTTPBlocked 返回模板是否包含非 http 协议或 headless/code 块。
func (t *NucleiTemplate) NonHTTPBlocked() string {
	switch {
	case len(t.TCP) > 0:
		return "tcp protocol"
	case len(t.DNS) > 0:
		return "dns protocol"
	case len(t.SSL) > 0:
		return "ssl protocol"
	case len(t.File) > 0:
		return "file protocol"
	case len(t.Headless) > 0:
		return "headless"
	case len(t.Code) > 0:
		return "code template"
	}
	return ""
}

func parseNucleiTemplate(content []byte) (*NucleiTemplate, error) {
	var t NucleiTemplate
	if err := yaml.Unmarshal(content, &t); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	t.Raw = string(content)
	return &t, nil
}

// CVE 可能是字符串或列表。
func (info *TemplateInfo) CVEs() []string {
	switch v := info.Classification.CVEID.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			return []string{strings.TrimSpace(v)}
		}
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

func (info *TemplateInfo) MetaString(key string) string {
	if info.Metadata == nil {
		return ""
	}
	v, ok := info.Metadata[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// ---- afrog / xray 表达式式 POC（两者结构同构）----

type ExprRequest struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Content         string            `yaml:"content"` // xray 请求体别名
	FollowRedirects bool              `yaml:"follow_redirects"`
}

type ExprRule struct {
	Request    ExprRequest `yaml:"request"`
	Expression string      `yaml:"expression"`
}

type ExprPoc struct {
	ID        string               `yaml:"id"`   // afrog
	Name      string               `yaml:"name"` // xray
	Transport string               `yaml:"transport"`
	Info      TemplateInfo         `yaml:"info"`
	Rules     map[string]*ExprRule `yaml:"rules"`
	Expression string              `yaml:"expression"`
	Detail    struct {
		Author string   `yaml:"author"`
		Links  []string `yaml:"links"`
	} `yaml:"detail"`
	Raw string `yaml:"-"`
}

func parseExprPoc(content []byte) (*ExprPoc, error) {
	var p ExprPoc
	if err := yaml.Unmarshal(content, &p); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	p.Raw = string(content)
	return &p, nil
}

func (p *ExprPoc) TemplateID() string {
	if strings.TrimSpace(p.ID) != "" {
		return strings.TrimSpace(p.ID)
	}
	name := strings.TrimSpace(p.Name)
	name = strings.TrimPrefix(name, "poc-yaml-")
	return name
}

// SingleRule 校验表达式为单 rule 形式（r0() 或直接表达式），返回该 rule。
// 多 rule 链（r0()||r1()、output 传参）超出可忠实转换子集，调用方应拒绝。
func (p *ExprPoc) SingleRule() (*ExprRule, string, error) {
	expr := strings.TrimSpace(p.Expression)
	if expr == "" {
		// 无顶层 expression 的 afrog 变体：仅当恰好一个 rule 时取它。
		if len(p.Rules) == 1 {
			for _, r := range p.Rules {
				return r, "", nil
			}
		}
		return nil, "", fmt.Errorf("no expression and %d rules", len(p.Rules))
	}
	if m := ruleRefRe.FindStringSubmatch(expr); m != nil {
		ruleName := m[1]
		r, ok := p.Rules[ruleName]
		if !ok {
			return nil, "", fmt.Errorf("expression references missing rule %q", ruleName)
		}
		if len(p.Rules) != 1 {
			return nil, "", fmt.Errorf("multi-rule chain %q not convertible", expr)
		}
		return r, ruleName, nil
	}
	// 顶层就是原子表达式（xray 常见变体直接写表达式）。
	if len(p.Rules) == 0 {
		return &ExprRule{Expression: expr}, "", nil
	}
	return nil, "", fmt.Errorf("unsupported top expression %q", expr)
}
