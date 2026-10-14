package crawler

import (
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func minedPathsOf(t *testing.T, body string, isJS bool) []MinedPath {
	t.Helper()
	return minePaths(body, isJS)
}

func TestMinePathsJS(t *testing.T) {
	// 模板字面量段用双引号 Go 字符串拼接（raw string 不能含反引号）。
	body := `const routes = ["/app1/home", '/app1/list', "/portal/user"];
	axios.get("/api/order/list");
	fetch("/api/order/detail");` + "\nconst u = fetch(`/api/order/${id}`);\n" + `baseURL = "/external/v1";
	const abs = "https://other.example.com/x";`
	got := minedPathsOf(t, body, true)
	byPath := map[string]MinedPath{}
	var fromJS int
	for _, mp := range got {
		byPath[mp.Path] = mp
		if mp.FromJS {
			fromJS++
		}
	}
	// 引号字符串 js-str。
	for _, want := range []string{"/app1/home", "/app1/list", "/portal/user", "/api/order/list", "/api/order/detail", "/external/v1"} {
		if _, ok := byPath[want]; !ok {
			t.Errorf("missing mined js path %q in %v", want, got)
		}
	}
	// 模板字面量静态前缀 js-template → /api/order。
	if mp, ok := byPath["/api/order"]; !ok || mp.Origin != "js-template" {
		t.Errorf("/api/order should be js-template, got %+v", byPath["/api/order"])
	}
	// 绝对外链不产出站点内路径。
	for _, mp := range got {
		if strings.HasPrefix(mp.Path, "http") {
			t.Errorf("absolute url leaked into mined path: %v", got)
		}
	}
	if fromJS != len(got) {
		t.Errorf("all JS-mined paths should be FromJS, got %d/%d", fromJS, len(got))
	}
}

func TestMinePathsHTML(t *testing.T) {
	body := `<html><body>
		<div data-url="/api/export" data-href="/internal/stat"></div>
		<form action="/app1/submit"></form>
		<a href="/about">about</a>
		<script>fetch("/inline/endpoint"); fetch("/inline/endpoint2");</script>
		<script src="/static/out.js"></script>
	</body></html>`
	got := minedPathsOf(t, body, false)
	byPath := map[string]MinedPath{}
	for _, mp := range got {
		byPath[mp.Path] = mp
	}
	for _, want := range []string{"/api/export", "/internal/stat", "/app1/submit", "/about"} {
		if _, ok := byPath[want]; !ok {
			t.Errorf("missing mined html-attr path %q in %v", want, got)
		}
	}
	// 内联 script 走 JS miner → html-inline-js。
	if mp, ok := byPath["/inline/endpoint"]; !ok || mp.Origin != "html-inline-js" || !mp.FromJS {
		t.Errorf("/inline/endpoint should be html-inline-js FromJS, got %+v", byPath["/inline/endpoint"])
	}
	// /static/out.js 首段命中拒绝表，不应出现。
	if _, ok := byPath["/static/out.js"]; ok {
		t.Errorf("/static/out.js should be rejected by reject table: %v", got)
	}
}

func TestPathOK(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/api/order?x=1", "/api/order", true},
		{"/api/order#frag", "/api/order", true},
		{"/app1/", "/app1", true},
		{"//cdn.x/y", "", false},
		{"/", "", false},
		{"/static/app.js", "", false},
		{"/assets/css/a.css", "", false},
		{"/favicon.ico", "", false},
		{"", "", false},
		{"not/a/path", "", false},
	}
	for _, c := range cases {
		got, ok := pathOK(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("pathOK(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestEvaluatePathApps(t *testing.T) {
	seed := mustURL(t, "http://example.com:8080/")
	opts := Options{MaxPathApps: 3, CrawlAI: false}
	shared := &sharedState{
		seedRoots:        map[string]struct{}{},
		emittedSites:     map[string]struct{}{},
		emittedSensitive: map[string]struct{}{},
	}
	prof := newPathProfiler(opts)
	if prof == nil {
		t.Fatal("profiler should be enabled when MaxPathApps>0")
	}

	// 根页面：标题 Main Site，链接到 app1/app2/blog。
	prof.observe(fetchedResource{u: mustURL(t, "http://example.com:8080/"), body: `<html><head><title>Main Site</title></head><body>
		<a href="/app1">a1</a><a href="/app2">a2</a><a href="/blog/x">b</a>
		<script src="/static/app.js"></script></body></html>`}, seed)

	// /app1：着陆页 + 子页，独立标题、链接全自包含 → path_app。
	prof.observe(fetchedResource{u: mustURL(t, "http://example.com:8080/app1"), body: `<html><head><title>Admin Console</title></head><body>
		<a href="/app1/page2">p2</a><a href="/app1/">home</a></body></html>`}, seed)
	prof.observe(fetchedResource{u: mustURL(t, "http://example.com:8080/app1/page2"), body: `<html><head><title>Admin Console</title></head><body>
		<a href="/app1">home</a></body></html>`}, seed)

	// /blog：单页、无着陆、链向根 → 两个启发式都不满足，不应上报。
	prof.observe(fetchedResource{u: mustURL(t, "http://example.com:8080/blog/x"), body: `<html><head><title>Blog</title></head><body>
		<a href="/">home</a></body></html>`}, seed)

	// JS bundle：/internal、/api 仅 JS 出现多次 → hidden_path。
	prof.observe(fetchedResource{u: mustURL(t, "http://example.com:8080/static/app.js"), isJS: true, body: `
		fetch("/internal/report"); fetch('/internal/list'); fetch("/api/v1/audit");
		const r = ["/api/v2/x", "/api/v3/y", "/internal/z"];`}, seed)

	var emitted []structs.OutputMessage
	emit := func(m structs.OutputMessage) { emitted = append(emitted, m) }
	var stats Stats
	prof.evaluate(seed, shared, opts, emit, &stats)

	got := map[string]string{} // url → siteType
	for _, m := range emitted {
		got[m.CrawlSite.URL] = m.CrawlSite.SiteType
	}
	if got["http://example.com:8080/app1"] != "path_app" {
		t.Errorf("/app1 should be path_app, got %v", got)
	}
	if got["http://example.com:8080/internal"] != "hidden_path" {
		t.Errorf("/internal should be hidden_path, got %v", got)
	}
	if got["http://example.com:8080/api"] != "hidden_path" {
		t.Errorf("/api should be hidden_path, got %v", got)
	}
	if _, ok := got["http://example.com:8080/blog"]; ok {
		t.Errorf("/blog should not be reported, got %v", got)
	}
	// 证据写入 LinkContext。
	for _, m := range emitted {
		if m.CrawlSite.URL == "http://example.com:8080/app1" && !strings.Contains(m.CrawlSite.LinkContext, "path-app:") {
			t.Errorf("path_app evidence missing in LinkContext: %q", m.CrawlSite.LinkContext)
		}
	}
}

func TestEvaluatePathAppsLimit(t *testing.T) {
	seed := mustURL(t, "http://example.com/")
	opts := Options{MaxPathApps: 1, CrawlAI: false}
	shared := &sharedState{
		seedRoots:        map[string]struct{}{},
		emittedSites:     map[string]struct{}{},
		emittedSensitive: map[string]struct{}{},
	}
	prof := newPathProfiler(opts)
	// 两个 path_app，上限 1 → 只发分高的（/app 有 2 页 + 着陆，/portal 1 页不达标，这里都用 hidden 比 mined）。
	js := `fetch("/aa/1");fetch("/aa/2");fetch("/aa/3");fetch("/bb/1");fetch("/bb/2");fetch("/bb/3");`
	prof.observe(fetchedResource{u: mustURL(t, "http://example.com/x.js"), isJS: true, body: js}, seed)
	var emitted []structs.OutputMessage
	emit := func(m structs.OutputMessage) { emitted = append(emitted, m) }
	var stats Stats
	prof.evaluate(seed, shared, opts, emit, &stats)
	if len(emitted) != 1 {
		t.Fatalf("MaxPathApps=1 should emit exactly 1, got %d: %v", len(emitted), emitted)
	}
}

func TestNewPathProfilerDisabled(t *testing.T) {
	if newPathProfiler(Options{MaxPathApps: 0}) != nil {
		t.Error("MaxPathApps=0 should disable profiler (nil)")
	}
}
