package subdomainpassive

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testCollector(sources []SourceClient, lookup func(ctx context.Context, host string) ([]net.IP, error)) *Collector {
	return &Collector{
		HTTP:          &http.Client{},
		Sources:       sources,
		LookupIP:      lookup,
		RandomLabel:   func() string { return "wildcardprobe" },
		SourceTimeout: 5 * time.Second,
		DomainBudget:  10 * time.Second,
		MaxSubdomains: DefaultMaxSubdomains,
	}
}

func fetchText(ctx context.Context, client *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("source returned %s", resp.Status)
	}
	var lines []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func TestCollectUnionsSourcesAndDropsWildcardHits(t *testing.T) {
	crtName := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("apex") != "example.test" {
			t.Errorf("unexpected crt.name apex: %s", r.URL.RawQuery)
		}
		fmt.Fprint(w, "example.test\napi.example.test\n*.example.test\nDev.example.test\nother.test\n")
	}))
	defer crtName.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer dead.Close()

	// wildcard baseline resolves; api+dev resolve normally; cdn would resolve
	// to the wildcard IP; anything else is NXDOMAIN.
	wildcardIP := net.ParseIP("203.0.113.1")
	lookup := func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "wildcardprobe.example.test":
			return []net.IP{wildcardIP}, nil
		case "api.example.test", "dev.example.test":
			return []net.IP{net.ParseIP("192.0.2.10")}, nil
		default:
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
	}
	collector := testCollector([]SourceClient{
		{
			Name: "crt.name",
			Fetch: func(ctx context.Context, client *http.Client, domain string) ([]string, error) {
				return fetchText(ctx, client, crtName.URL+"/v1/search?apex="+domain)
			},
		},
		{
			Name: "crtsh",
			Fetch: func(ctx context.Context, client *http.Client, domain string) ([]string, error) {
				return nil, fmt.Errorf("crt.sh is down")
			},
		},
	}, lookup)

	result, err := collector.Collect(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	want := []string{"api.example.test", "dev.example.test"}
	if strings.Join(result.Subdomains, ",") != strings.Join(want, ",") {
		t.Fatalf("subdomains = %v, want %v", result.Subdomains, want)
	}
	if strings.Join(result.Sources, ",") != "crt.name" {
		t.Fatalf("sources = %v, want [crt.name]", result.Sources)
	}
}

func TestCollectFailsWhenAllSourcesFail(t *testing.T) {
	collector := testCollector([]SourceClient{
		{Name: "dead", Fetch: func(ctx context.Context, client *http.Client, domain string) ([]string, error) {
			return nil, fmt.Errorf("502")
		}},
	}, func(_ context.Context, host string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})
	if _, err := collector.Collect(context.Background(), "example.test"); err == nil {
		t.Fatal("expected failure when every source fails")
	}
}

func TestCollectEmptyButValidWhenSourcesAnswerNothing(t *testing.T) {
	collector := testCollector([]SourceClient{
		{Name: "crt.name", Fetch: func(ctx context.Context, client *http.Client, domain string) ([]string, error) {
			return []string{"unrelated.test"}, nil
		}},
	}, func(_ context.Context, host string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})
	result, err := collector.Collect(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(result.Subdomains) != 0 {
		t.Fatalf("expected empty valid result, got %v", result.Subdomains)
	}
}

func TestCollectFailsOnResolverOutage(t *testing.T) {
	collector := testCollector([]SourceClient{
		{Name: "crt.name", Fetch: func(ctx context.Context, client *http.Client, domain string) ([]string, error) {
			return []string{"api.example.test"}, nil
		}},
	}, func(_ context.Context, host string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	})
	if _, err := collector.Collect(context.Background(), "example.test"); err == nil {
		t.Fatal("expected resolver outage to fail collection instead of caching an empty result")
	}
}

func TestNormalizeCandidates(t *testing.T) {
	raw := map[string][]string{
		"s1": {"API.Example.test", "*.example.test", "example.test", "deep.a.example.test", "other.test", " api.example.test "},
	}
	got := normalizeCandidates(raw, "example.test")
	want := []string{"api.example.test", "deep.a.example.test"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("normalizeCandidates = %v, want %v", got, want)
	}
}
