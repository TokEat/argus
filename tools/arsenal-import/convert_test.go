package main

import (
	"strings"
	"testing"
)

func TestRewriteInlineFuncs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"md5 路径求值", `/a?x={{md5(99999999)}}`, `/a?x={{md5(99999999)}}`},
		{"裸 md5 重写", `/a?x=md5(99999999)`, `/a?x={{md5(99999999)}}`},
		{"SQLi 载荷透传", `/a?x=updatexml(1,concat(0x7e,md5(8888)),1)`, `/a?x=updatexml(1,concat(0x7e,{{md5(8888)}}),1)`},
		{"XSS alert 透传", `/a?q=<script>alert(1)</script>`, `/a?q=<script>alert(1)</script>`},
		{"已包裹保留", `/a?x={{randstr}}&y=sha1(abc)`, `/a?x={{randstr}}&y={{sha1(abc)}}`},
		{"大小写归一", `MD5(abc)`, `{{md5(abc)}}`},
		{"未知函数纯文本", `/index(1)`, `/index(1)`},
		{"randomInt 映射", `randomInt(1000,9999)`, `{{rand_int(1000,9999)}}`},
	}
	for _, c := range cases {
		got, err := rewriteInlineFuncs(c.in)
		if err != nil {
			t.Fatalf("%s: unexpected err %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s:\n  in   %q\n  got  %q\n  want %q", c.name, c.in, got, c.want)
		}
	}
}

// buildMatchers 必须把 expr 的 and/or 传播到合并的 word matcher，
// 否则 nuclei words 默认 OR 会把"同时出现"弱化成"任一出现"。
func TestBuildMatchersConditionPropagation(t *testing.T) {
	and := &exprResult{condition: "and", terms: []exprTerm{
		{kind: "word", part: "body", value: "A"},
		{kind: "word", part: "body", value: "B"},
	}}
	ms := buildMatchers(and)
	if len(ms) != 1 || ms[0].Condition != "and" {
		t.Fatalf("and: 期望单 word matcher condition=and, got %+v", ms)
	}

	or := &exprResult{condition: "or", terms: []exprTerm{
		{kind: "word", part: "body", value: "A"},
		{kind: "word", part: "body", value: "B"},
	}}
	ms = buildMatchers(or)
	if len(ms) != 1 || ms[0].Condition != "" {
		t.Fatalf("or: 期望单 word matcher 默认(or) condition 空, got %+v", ms)
	}

	// status 与 word 混合：status 单独成 matcher，word 合并且 condition=and
	mix := &exprResult{condition: "and", terms: []exprTerm{
		{kind: "status", value: "200"},
		{kind: "word", part: "body", value: "A"},
		{kind: "word", part: "body", value: "B"},
	}}
	ms = buildMatchers(mix)
	if len(ms) != 2 {
		t.Fatalf("mix: 期望 2 matchers, got %d", len(ms))
	}
	var status, word *NucleiMatcher
	for _, m := range ms {
		if m.Type == "status" {
			status = m
		} else {
			word = m
		}
	}
	if status == nil || word == nil || word.Condition != "and" {
		t.Fatalf("mix: status/word 拆分或 condition 错误: %+v", ms)
	}
}

// negative / ci 不同的 word 不能合并进同一 matcher（会互相污染语义）。
func TestBuildMatchersNegativeSplit(t *testing.T) {
	res := &exprResult{condition: "and", terms: []exprTerm{
		{kind: "word", part: "body", value: "A"},
		{kind: "word", part: "body", value: "B", negative: true},
	}}
	ms := buildMatchers(res)
	if len(ms) != 2 {
		t.Fatalf("期望 negative 拆分 2 matchers, got %d", len(ms))
	}
}

func TestEscapeFofaValueRoundTrip(t *testing.T) {
	in := `a"b\c`
	got := escapeFofaValue(in)
	// ddfinger 解析时 \" → " 、\\ → \，应还原回原值
	back := strings.ReplaceAll(strings.ReplaceAll(got, `\\`, "\x00"), `\"`, `"`)
	back = strings.ReplaceAll(back, "\x00", `\`)
	if back != in {
		t.Errorf("escapeFofaValue 往返失败: in=%q got=%q back=%q", in, got, back)
	}
}

func TestDSLToFofaAtoms(t *testing.T) {
	got, err := dslToFofaAtoms(`contains(body,"uid=") && status_code == 200`, "body", "=")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1] != `status="200"` {
		t.Fatalf("dsl 原子错误: %v", got)
	}
	if _, err := dslToFofaAtoms(`a || b`, "body", "="); err == nil {
		t.Fatal("期望 || 被拒绝")
	}
}

func TestCanonProduct(t *testing.T) {
	if got := canonProduct("apache", "tomcat", ""); got != "Apache-Tomcat" {
		t.Errorf("got %q", got)
	}
	// 无 vendor/product 时从模板名兜底
	if got := canonProduct("", "", "Apache Tomcat - Detect"); got != "Apache-Tomcat" {
		t.Errorf("fallback got %q", got)
	}
}

func TestRiskFromSeverity(t *testing.T) {
	for in, want := range map[string]string{
		"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low", "": "unknown",
	} {
		if got := riskFromSeverity(in); got != want {
			t.Errorf("riskFromSeverity(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPocGate(t *testing.T) {
	// severity 门控
	if r := pocGate(Candidate{Kind: KindPoc, Severity: "high", SrcPath: "http/cves/x.yaml"}); r != "" {
		t.Errorf("high 应通过, got %q", r)
	}
	if r := pocGate(Candidate{Kind: KindPoc, Severity: "info", SrcPath: "http/cves/x.yaml"}); r == "" {
		t.Error("非产品识别目录 info 应拒绝")
	}
	if r := pocGate(Candidate{Kind: KindPoc, Severity: "info", SrcPath: "http/exposed-panels/x.yaml"}); r != "" {
		t.Errorf("产品识别目录 info 应通过, got %q", r)
	}
	// OOB / exploit / 噪声
	if r := pocGate(Candidate{Kind: KindPoc, Severity: "critical", Content: "path: {{interactsh-url}}"}); r == "" {
		t.Error("interactsh 依赖应拒绝")
	}
	if r := pocGate(Candidate{Kind: KindPoc, Severity: "critical", Tags: []string{"intrusive"}}); r == "" {
		t.Error("intrusive 应拒绝")
	}
	if r := pocGate(Candidate{Kind: KindPoc, Severity: "high", Tags: []string{"iot"}}); r == "" {
		t.Error("iot 噪声 tag 应拒绝")
	}
}

func TestValidateFofaExpr(t *testing.T) {
	for _, ok := range []string{
		`body="content=\"08CMS" || body="typeof(_08cms)"`,
		`title="登录" && status="200"`,
		`(body="a" || header="b") && icon_hash="1300107149"`,
	} {
		if err := validateFofaExpr(ok); err != nil {
			t.Errorf("合法表达式被判非法: %q → %v", ok, err)
		}
	}
	for _, bad := range []string{
		``,                                  // 空
		`body="a" && (title="b"`,            // 括号不平衡（会触发 boolEval Fatal，必须先拦）
		`foo="a"`,                           // 未知键
		`no atoms here`,                     // 无可解析原子
	} {
		if err := validateFofaExpr(bad); err == nil {
			t.Errorf("非法表达式被判合法: %q", bad)
		}
	}
}
