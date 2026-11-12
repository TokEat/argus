package crawler

import (
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u := normalizeURL(raw)
	if u == nil {
		t.Fatalf("normalizeURL(%q) returned nil", raw)
	}
	return u
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"HTTP://Example.COM:80/a?b=1#frag": "http://example.com/a?b=1",
		"https://example.com:443/":         "https://example.com/",
		"http://example.com:8080/x":        "http://example.com:8080/x",
	}
	for in, want := range cases {
		if got := mustURL(t, in).String(); got != want {
			t.Errorf("normalizeURL(%q)=%q want %q", in, got, want)
		}
	}
	if normalizeURL("notaurl") != nil {
		t.Error("normalizeURL(notaurl) should be nil")
	}
	if normalizeURL("ftp://example.com/x") == nil {
		t.Error("normalizeURL should parse ftp host")
	}
}

func TestSameHostPort(t *testing.T) {
	a := mustURL(t, "http://example.com:80/")
	b := mustURL(t, "http://example.com/login")
	if !sameHostPort(a, b) {
		t.Error("same host:port expected (default port normalized)")
	}
	c := mustURL(t, "http://example.com:8080/")
	if sameHostPort(a, c) {
		t.Error("different port must not match")
	}
	d := mustURL(t, "https://example.com/")
	if sameHostPort(a, d) {
		t.Error("different scheme must not match")
	}
}

func TestParentDomain(t *testing.T) {
	if got := parentDomain("www.example.com"); got != "example.com" {
		t.Errorf("parentDomain(www.example.com)=%q", got)
	}
	// 多层级子域收敛到同一父域（爬虫只依赖兄弟子域共享父域这一不变量）。
	if parentDomain("a.example.com") == "" || parentDomain("a.example.com") != parentDomain("b.example.com") {
		t.Error("sibling subdomains must share a parent")
	}
	if got := parentDomain("127.0.0.1"); got != "" {
		t.Errorf("parentDomain(IP)=%q want empty", got)
	}
}

func TestClassifyLink(t *testing.T) {
	seed := mustURL(t, "http://example.com:80/")

	if got := classifyLink(mustURL(t, "http://example.com/about"), seed, "1.2.3.4"); got != classInScope {
		t.Errorf("same host:port => %v want in-scope", got)
	}
	// 同 IP 其他端口。
	if got := classifyLink(mustURL(t, "http://1.2.3.4:8080/"), seed, "1.2.3.4"); got != classRelated {
		t.Errorf("same IP other port => %v want related", got)
	}
	// 同主域兄弟子域。
	if got := classifyLink(mustURL(t, "http://admin.example.com/"), seed, "1.2.3.4"); got != classRelated {
		t.Errorf("sibling subdomain => %v want related", got)
	}
	// 外部域名。
	if got := classifyLink(mustURL(t, "http://other.org/"), seed, "1.2.3.4"); got != classOutOfScope {
		t.Errorf("external domain => %v want out-of-scope", got)
	}
	// 种子为 IP：同 IP 不同端口关联，其他 IP 忽略。
	ipSeed := mustURL(t, "http://1.2.3.4:80/")
	if got := classifyLink(mustURL(t, "http://1.2.3.4:9090/"), ipSeed, "1.2.3.4"); got != classRelated {
		t.Errorf("IP seed same-IP other port => %v want related", got)
	}
	if got := classifyLink(mustURL(t, "http://5.6.7.8:80/"), ipSeed, "1.2.3.4"); got != classOutOfScope {
		t.Errorf("IP seed other IP => %v want out-of-scope", got)
	}
}

func TestExtractLinks(t *testing.T) {
	base := mustURL(t, "http://example.com/")
	body := `<html><body>
		<a href="/a">A</a>
		<a href="http://example.com/b" title="bee">B</a>
		<a href="mailto:x@example.com">mail</a>
		<script src="/static/app.js"></script>
		<a href="/a">dup</a>
		<form action="/login"></form>
	</body></html>`
	links := extractLinks(base, body)
	var hrefs []string
	for _, l := range links {
		hrefs = append(hrefs, l.URL.String())
	}
	joined := strings.Join(hrefs, " ")
	for _, want := range []string{"http://example.com/a", "http://example.com/b", "http://example.com/static/app.js", "http://example.com/login"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected link %q in %v", want, hrefs)
		}
	}
	if strings.Contains(joined, "mailto:") {
		t.Errorf("mailto link should be skipped: %v", hrefs)
	}
	// 去重：/a 只出现一次。
	if strings.Count(joined, "http://example.com/a") != 1 {
		t.Errorf("duplicate link not deduped: %v", hrefs)
	}
	// 锚文本上下文。
	for _, l := range links {
		if l.URL.String() == "http://example.com/b" && l.Context != "bee" {
			t.Errorf("link context=%q want bee", l.Context)
		}
	}
}

func TestExtractJSRefs(t *testing.T) {
	base := mustURL(t, "http://example.com/")
	body := `<script src="/a.js"></script><script src="http://example.com/b.js"></script><script src="/page"></script>`
	js := extractJSRefs(base, body)
	if len(js) != 2 {
		t.Fatalf("expected 2 js refs, got %d: %v", len(js), js)
	}
}

func TestExtractFromJS(t *testing.T) {
	base := mustURL(t, "http://example.com/")
	body := `const a="https://api.example.com:8443/v1"; const b="/internal/path"; const c="http://cdn.other.net/x.js";`
	urls := extractFromJS(base, body)
	var got []string
	for _, u := range urls {
		got = append(got, u.String())
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "https://api.example.com:8443/v1") {
		t.Errorf("missing abs url: %v", got)
	}
	if !strings.Contains(joined, "http://example.com/internal/path") {
		t.Errorf("missing resolved relative path: %v", got)
	}
}

func TestSensitiveScan(t *testing.T) {
	body := `contact admin@example.com or 13800138000; id 110101199003077758; password="secret123" token: abcdef`
	hits := sensitiveScan(body)
	kinds := map[string]bool{}
	for _, h := range hits {
		kinds[h.Kind] = true
		if h.Snippet == "" {
			t.Errorf("kind %s missing snippet", h.Kind)
		}
	}
	for _, want := range []string{"email", "phone", "idcard", "account"} {
		if !kinds[want] {
			t.Errorf("expected kind %s in hits %+v", want, hits)
		}
	}
}

func TestIsJSURL(t *testing.T) {
	if !isJSURL(mustURL(t, "http://x/app.js"), "text/html") {
		t.Error(".js path should be JS")
	}
	if !isJSURL(mustURL(t, "http://x/app"), "application/javascript") {
		t.Error("javascript content-type should be JS")
	}
	if isJSURL(mustURL(t, "http://x/page"), "text/html") {
		t.Error("html page should not be JS")
	}
}
