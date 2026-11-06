package subdomainpassive

import (
	"context"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestParseAlienVaultHosts(t *testing.T) {
	body := []byte(`{"passive_dns":[{"hostname":"mail.example.test"},{"hostname":"example.test"},{"hostname":""}]}`)
	got, err := parseAlienVaultHosts(body)
	if err != nil {
		t.Fatalf("parseAlienVaultHosts: %v", err)
	}
	want := []string{"mail.example.test", "example.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("parseAlienVaultHosts = %v, want %v", got, want)
	}
	if _, err := parseAlienVaultHosts([]byte(`not json`)); err == nil {
		t.Fatal("expected decode error for malformed alienvault body")
	}
}

func TestParseHackerTargetHosts(t *testing.T) {
	body := []byte("api.example.test,192.0.2.1\nwww.example.test,192.0.2.2\nbare.example.test\n\n")
	got, err := parseHackerTargetHosts(body)
	if err != nil {
		t.Fatalf("parseHackerTargetHosts: %v", err)
	}
	want := []string{"api.example.test", "www.example.test", "bare.example.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("parseHackerTargetHosts = %v, want %v", got, want)
	}
}

func TestParseThreatMinerHosts(t *testing.T) {
	got, err := parseThreatMinerHosts([]byte(`{"results":["cdn.example.test","example.test",""]}`))
	if err != nil {
		t.Fatalf("parseThreatMinerHosts: %v", err)
	}
	want := []string{"cdn.example.test", "example.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("parseThreatMinerHosts = %v, want %v", got, want)
	}
}

func TestParseAnubisHosts(t *testing.T) {
	got, err := parseAnubisHosts([]byte(`["blog.example.test",""]`))
	if err != nil {
		t.Fatalf("parseAnubisHosts: %v", err)
	}
	want := []string{"blog.example.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("parseAnubisHosts = %v, want %v", got, want)
	}
}

func TestScrapeHosts(t *testing.T) {
	html := `<table><tr><td>WWW.Example.test</td></tr><tr><td>a.b.example.test</td></tr>` +
		`<tr><td>other.test</td></tr><tr><td>notadomain</td></tr></table>`
	got := scrapeHosts(html, "example.test")
	want := []string{"www.example.test", "a.b.example.test"}
	if !slices.Equal(got, want) {
		t.Fatalf("scrapeHosts = %v, want %v", got, want)
	}
}

func TestHostFromArchiveURL(t *testing.T) {
	cases := map[string]string{
		"http://Sub.Example.test/path?x=1": "sub.example.test",
		"https://B.example.test:8443/y":    "b.example.test",
		"example.test/path":                "example.test",
		"  https://a.example.test/x  ":     "a.example.test",
		"":                                 "",
	}
	for in, want := range cases {
		if got := hostFromArchiveURL(in); got != want {
			t.Fatalf("hostFromArchiveURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseWaybackHosts(t *testing.T) {
	body := []byte("http://staging.example.test/path\nhttps://example.test/x\nnotaurl\n")
	got, err := parseWaybackHosts(body)
	if err != nil {
		t.Fatalf("parseWaybackHosts: %v", err)
	}
	joined := "," + strings.Join(got, ",") + ","
	for _, want := range []string{"staging.example.test", "example.test"} {
		if !strings.Contains(joined, ","+want+",") {
			t.Fatalf("parseWaybackHosts = %v, missing %v", got, want)
		}
	}
}

// TestCollectUnionsKeylessSourceFormats pipes representative payloads from every
// keyless source format through the real parsers and the Collector, asserting
// the suffix invariant and per-source attribution hold end to end.
func TestCollectUnionsKeylessSourceFormats(t *testing.T) {
	sources := []SourceClient{
		{Name: "hackertarget", Fetch: func(_ context.Context, _ *http.Client, domain string) ([]string, error) {
			return parseHackerTargetHosts([]byte("api.example.test,192.0.2.1\nwww.example.test,192.0.2.2\n"))
		}},
		{Name: "alienvault", Fetch: func(_ context.Context, _ *http.Client, domain string) ([]string, error) {
			return parseAlienVaultHosts([]byte(`{"passive_dns":[{"hostname":"mail.example.test"},{"hostname":"example.test"}]}`))
		}},
		{Name: "rapiddns", Fetch: func(_ context.Context, _ *http.Client, domain string) ([]string, error) {
			return scrapeHosts(`<td>dev.example.test</td><td>other.test</td>`, domain), nil
		}},
		{Name: "waybackarchive", Fetch: func(_ context.Context, _ *http.Client, domain string) ([]string, error) {
			return parseWaybackHosts([]byte("http://staging.example.test/p\nhttps://example.test/x\n"))
		}},
		{Name: "threatminer", Fetch: func(_ context.Context, _ *http.Client, domain string) ([]string, error) {
			return parseThreatMinerHosts([]byte(`{"results":["cdn.example.test","example.test"]}`))
		}},
		{Name: "anubis", Fetch: func(_ context.Context, _ *http.Client, domain string) ([]string, error) {
			return parseAnubisHosts([]byte(`["blog.example.test"]`))
		}},
		{Name: "digitorus", Fetch: func(_ context.Context, _ *http.Client, domain string) ([]string, error) {
			return scrapeHosts(`<html>shop.example.test<br>other.test</html>`, domain), nil
		}},
	}
	// Everything under *.example.test resolves; apex / unrelated / wildcard
	// probes are NXDOMAIN so the domain reads as not wildcarded.
	lookup := func(_ context.Context, host string) ([]net.IP, error) {
		if strings.HasSuffix(host, ".example.test") {
			return []net.IP{net.ParseIP("192.0.2.10")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	result, err := testCollector(sources, lookup).Collect(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	wantSubs := []string{
		"api.example.test", "blog.example.test", "cdn.example.test", "dev.example.test",
		"mail.example.test", "shop.example.test", "staging.example.test", "www.example.test",
	}
	if !slices.Equal(result.Subdomains, wantSubs) {
		t.Fatalf("subdomains = %v, want %v", result.Subdomains, wantSubs)
	}
	wantSources := []string{
		"alienvault", "anubis", "digitorus", "hackertarget", "rapiddns", "threatminer", "waybackarchive",
	}
	if !slices.Equal(result.Sources, wantSources) {
		t.Fatalf("sources = %v, want %v", result.Sources, wantSources)
	}
}
