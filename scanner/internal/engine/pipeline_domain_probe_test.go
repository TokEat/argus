package engine

import (
	"reflect"
	"testing"
)

func TestBuildHTTPProbeURLsPrefersBoundDomainForm(t *testing.T) {
	ctx := &ScanContext{IPDomainMap: map[string][]string{"203.0.113.10": {"abc.test"}}}
	cfg := Config{}

	got := buildHTTPProbeURLs(ctx, cfg, map[string]string{"203.0.113.10:8080": "http"})
	want := []string{"http://abc.test:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bound host probe urls = %#v, want %#v", got, want)
	}

	got = buildHTTPProbeURLs(ctx, cfg, map[string]string{"203.0.113.10:443": "https"})
	want = []string{"https://abc.test:443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bound TLS host probe urls = %#v, want %#v", got, want)
	}
}

func TestBuildHTTPProbeURLsKeepsLegacyFormWithoutBinding(t *testing.T) {
	ctx := &ScanContext{IPDomainMap: map[string][]string{"203.0.113.10": {"abc.test"}}}
	cfg := Config{}

	got := buildHTTPProbeURLs(ctx, cfg, map[string]string{"198.51.100.7:80": "http"})
	want := []string{"http://198.51.100.7:80"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unbound host probe urls = %#v, want %#v", got, want)
	}

	if buildHTTPProbeURLs(nil, cfg, map[string]string{"198.51.100.7:80": "http"}) == nil {
		t.Fatal("nil ScanContext must fall back to legacy IP-form probe URLs")
	}
}

func TestBuildHTTPProbeURLsFallsBackWhenDisabled(t *testing.T) {
	ctx := &ScanContext{IPDomainMap: map[string][]string{"203.0.113.10": {"abc.test"}}}
	cfg := Config{NoDomainProbe: true}

	got := buildHTTPProbeURLs(ctx, cfg, map[string]string{"203.0.113.10:8080": "http"})
	want := []string{"http://203.0.113.10:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NoDomainProbe must restore IP-form probing, got %#v want %#v", got, want)
	}
}

func TestBuildHTTPProbeURLsDeduplicatesDomainsPerHostPort(t *testing.T) {
	ctx := &ScanContext{IPDomainMap: map[string][]string{"203.0.113.10": {"a.test", "b.test", "a.test"}}}
	cfg := Config{}

	got := buildHTTPProbeURLs(ctx, cfg, map[string]string{"203.0.113.10:80": "http"})
	want := []string{"http://a.test:80", "http://b.test:80"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("multi-domain binding urls = %#v, want %#v", got, want)
	}
}

func TestBuildHTTPProbeURLsPassesDirectDomainPortThrough(t *testing.T) {
	cfg := Config{}

	got := buildHTTPProbeURLs(&ScanContext{}, cfg, map[string]string{"abc.test:8443": "ssl/http"})
	want := []string{"https://abc.test:8443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("direct domain:port endpoint urls = %#v, want %#v", got, want)
	}
}

func TestSuppressSafedogTargetsMatchesDomainFormRoots(t *testing.T) {
	safedogPaths := map[string]UrlPathEntity{
		"/": {Title: "请验证是否真人访问", StatusCode: 200},
	}
	cleanPaths := map[string]UrlPathEntity{
		"/": {Title: "Normal Page", StatusCode: 200},
	}
	ctx := &ScanContext{
		URLMap: map[string]URLEntity{
			"https://waf.test":   {IP: "203.0.113.10", Port: 443, WebPaths: safedogPaths},
			"http://waf.test":    {IP: "203.0.113.10", Port: 80, WebPaths: cleanPaths},
			"https://clean.test": {IP: "203.0.113.11", Port: 443, WebPaths: cleanPaths},
		},
	}
	resultMap := map[string][]string{
		"https://waf.test":    {"nginx"},
		"http://waf.test":     {"nginx"},
		"https://clean.test":  {"nginx"},
		"http://198.51.100.9": {"nginx"},
	}

	suppressSafedogTargets(ctx, resultMap)

	if _, ok := resultMap["https://waf.test"]; ok {
		t.Fatal("domain-form target on a Safedog host must be suppressed")
	}
	if _, ok := resultMap["http://waf.test"]; ok {
		t.Fatal("same-IP sibling rootURL must stay suppressed like the legacy substring match")
	}
	if _, ok := resultMap["https://clean.test"]; !ok {
		t.Fatal("unrelated domain-form target must survive the Safedog filter")
	}
	if _, ok := resultMap["http://198.51.100.9"]; !ok {
		t.Fatal("unrelated IP-form target must survive the Safedog filter")
	}
}

func TestSuppressSafedogTargetsKeepsLegacySubstringMatching(t *testing.T) {
	ctx := &ScanContext{
		URLMap: map[string]URLEntity{
			"http://203.0.113.20": {IP: "203.0.113.20", Port: 80, WebPaths: map[string]UrlPathEntity{
				"/": {Title: "当前网络访问异常", StatusCode: 200},
			}},
		},
	}
	resultMap := map[string][]string{
		"http://203.0.113.20": {"thinkphp"},
		"https://other.test":  {"nginx"},
	}

	suppressSafedogTargets(ctx, resultMap)

	if _, ok := resultMap["http://203.0.113.20"]; ok {
		t.Fatal("legacy IP-form target on a Safedog host must still be suppressed")
	}
	if _, ok := resultMap["https://other.test"]; !ok {
		t.Fatal("unrelated target must survive the Safedog filter")
	}
}
