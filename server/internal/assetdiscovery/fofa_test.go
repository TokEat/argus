package assetdiscovery

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFOFAClientSearchNormalizesDeduplicatesAndBoundsRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/search/all" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		query := r.URL.Query()
		decoded, err := base64.StdEncoding.DecodeString(query.Get("qbase64"))
		if err != nil || string(decoded) != `domain="Example.com"` {
			t.Fatalf("qbase64 = %q decoded=%q err=%v", query.Get("qbase64"), decoded, err)
		}
		if query.Get("email") != "tenant@example.test" || query.Get("key") != "secret-key" ||
			query.Get("page") != "1" || query.Get("size") != "4" || query.Get("fields") != fofaFields || query.Get("full") != "false" {
			t.Fatalf("unexpected FOFA query parameters: %v", query)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"error":false,"size":5,"results":[
				["HTTPS://Demo.Example.com:443/path?q=secret","https","Demo","ICP-A","192.0.2.1","443","Demo.Example.com."],
				["demo.example.com:443","https","","","192.0.2.1","443","demo.example.com"],
				["192.0.2.10:22","ssh","SSH","","192.0.2.10","22",""],
				["bad","tcp","Bad","","not-an-ip","0",""],
				["ignored.example:80","http","Ignored","","192.0.2.8","80","ignored.example"]
			]
		}`))
	}))
	defer server.Close()

	client := NewFOFAClient(server.Client())
	client.endpoint = server.URL + "/api/v1/search/all"
	result, err := client.Search(context.Background(), FOFACredential{
		Email: "tenant@example.test", Key: "secret-key",
	}, FOFAQuery{Expression: `domain="Example.com"`, Limit: 4})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Provider != fofaProvider || result.ProviderTotal != 5 || !result.Truncated || result.SkippedRows != 1 {
		t.Fatalf("unexpected result metadata: %#v", result)
	}
	if len(result.Assets) != 2 {
		t.Fatalf("assets = %#v, want two normalized unique targets", result.Assets)
	}
	if got := result.Assets[0]; got.Target != "192.0.2.10:22" || got.IP != "192.0.2.10" || got.Protocol != "ssh" || got.Source != fofaProvider {
		t.Fatalf("service asset = %#v", got)
	}
	if got := result.Assets[1]; got.Target != "https://demo.example.com:443" || got.Domain != "demo.example.com" || got.Title != "Demo" || got.ICP != "ICP-A" {
		t.Fatalf("web asset = %#v", got)
	}
	if strings.Contains(result.Assets[1].Target, "secret") || strings.Contains(result.Assets[1].Target, "/path") {
		t.Fatalf("provider path or query leaked into target: %q", result.Assets[1].Target)
	}
}

func TestFOFAClientSearchFetchesOnePageAndReportsMoreResults(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		query := r.URL.Query()
		if query.Get("page") != "2" || query.Get("size") != "100" || query.Get("qbase64") == "" {
			t.Fatalf("unexpected paging parameters: %v", query)
		}
		makeRow := func(index int) string {
			return fmt.Sprintf(`["192.0.2.%d:80","http","","","192.0.2.%d","80",""]`, index, index)
		}
		rows := make([]string, 0, 100)
		for index := 101; index <= 200; index++ {
			rows = append(rows, makeRow(index))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":false,"size":250,"results":[` + strings.Join(rows, ",") + `]}`))
	}))
	defer server.Close()

	client := NewFOFAClient(server.Client())
	client.endpoint = server.URL + "/api/v1/search/all"
	result, err := client.Search(context.Background(), FOFACredential{
		Email: "tenant@example.test", Key: "secret-key",
	}, FOFAQuery{Expression: `domain="Example.com"`, Limit: 100, Page: 2})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if requests.Load() != 1 || result.Page != 2 || result.PageSize != 100 ||
		result.ProviderTotal != 250 || !result.Truncated || len(result.Assets) != 100 {
		t.Fatalf("unexpected paged result: requests=%d result=%#v", requests.Load(), result)
	}
	if got := result.Assets[0]; got.Target != "http://192.0.2.101:80" || got.Source != fofaProvider {
		t.Fatalf("first paged asset = %#v", got)
	}
}

func TestFOFAClientSearchRejectsInvalidInput(t *testing.T) {
	client := NewFOFAClient(nil)
	validCredential := FOFACredential{Email: "tenant@example.test", Key: "key"}
	for _, test := range []struct {
		name       string
		ctx        context.Context
		credential FOFACredential
		query      FOFAQuery
	}{
		{name: "nil context", credential: validCredential, query: FOFAQuery{Expression: "domain=x"}},
		{name: "missing email", ctx: context.Background(), credential: FOFACredential{Key: "key"}, query: FOFAQuery{Expression: "domain=x"}},
		{name: "credential control", ctx: context.Background(), credential: FOFACredential{Email: "tenant@example.test", Key: "key\nleak"}, query: FOFAQuery{Expression: "domain=x"}},
		{name: "empty query", ctx: context.Background(), credential: validCredential},
		{name: "query control", ctx: context.Background(), credential: validCredential, query: FOFAQuery{Expression: "domain=x\nnext"}},
		{name: "limit too large", ctx: context.Background(), credential: validCredential, query: FOFAQuery{Expression: "domain=x", Limit: MaxFOFAResultLimit + 1}},
		{name: "page too large", ctx: context.Background(), credential: validCredential, query: FOFAQuery{Expression: "domain=x", Page: fofaMaxPages + 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.Search(test.ctx, test.credential, test.query); !errors.Is(err, ErrInvalidFOFARequest) {
				t.Fatalf("expected typed validation error, got %v", err)
			}
		})
	}
}

func TestFOFAClientSearchSanitizesTransportAndProviderErrors(t *testing.T) {
	secret := "do-not-leak"
	email := "private@example.test"
	client := NewFOFAClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New(req.URL.String())
	})})
	_, err := client.Search(context.Background(), FOFACredential{Email: email, Key: secret}, FOFAQuery{Expression: "domain=private"})
	if !errors.Is(err, ErrFOFAUnavailable) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), email) || strings.Contains(err.Error(), "domain=private") {
		t.Fatalf("transport error was not sanitized: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(secret))
	}))
	defer server.Close()
	client = NewFOFAClient(server.Client())
	client.endpoint = server.URL
	_, err = client.Search(context.Background(), FOFACredential{Email: email, Key: secret}, FOFAQuery{Expression: "domain=private"})
	if !errors.Is(err, ErrFOFARejected) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), email) {
		t.Fatalf("provider error was not sanitized: %v", err)
	}
}

func TestFOFAClientSearchRejectsOversizedMalformedAndRedirectResponses(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		mutate  func(*FOFAClient)
	}{
		{
			name: "oversized",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"error":false,"size":0,"results":[]}` + strings.Repeat(" ", 128)))
			},
			mutate: func(client *FOFAClient) { client.responseLimit = 32 },
		},
		{
			name: "trailing json",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"error":false,"size":0,"results":[]} {}`))
			},
		},
		{
			name: "provider rejection",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"error":true,"errmsg":"do-not-return-provider-body"}`))
			},
		},
		{
			name: "redirect",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://example.invalid/credential-sink")
				w.WriteHeader(http.StatusFound)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			client := NewFOFAClient(server.Client())
			client.endpoint = server.URL
			if test.mutate != nil {
				test.mutate(client)
			}
			_, err := client.Search(context.Background(), FOFACredential{Email: "tenant@example.test", Key: "secret"}, FOFAQuery{Expression: "domain=x"})
			if err == nil {
				t.Fatal("expected response rejection")
			}
		})
	}
}

func TestFOFAClientDoesNotForwardCredentialsAcrossRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	credentialSink := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
	}))
	defer credentialSink.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, credentialSink.URL, http.StatusFound)
	}))
	defer origin.Close()

	client := NewFOFAClient(origin.Client())
	client.endpoint = origin.URL
	if _, err := client.Search(context.Background(), FOFACredential{
		Email: "tenant@example.test", Key: "redirect-secret",
	}, FOFAQuery{Expression: "domain=redirect"}); err == nil {
		t.Fatal("expected redirect response to be rejected")
	}
	if calls := redirectedRequests.Load(); calls != 0 {
		t.Fatalf("FOFA credentials were forwarded across %d redirect requests", calls)
	}
}

func TestNormalizeFOFARowCanonicalizesIPv6AndRejectsUnsafeHost(t *testing.T) {
	asset, ok := normalizeFOFARow([]string{"", "ssh", "", "", "2001:db8::1", "22", ""})
	if !ok || asset.Target != "[2001:db8::1]:22" {
		t.Fatalf("IPv6 asset = %#v ok=%v", asset, ok)
	}
	asset, ok = normalizeFOFARow([]string{"https://user:pass@example.test/path", "https", "", "", "192.0.2.2", "443", ""})
	if !ok || asset.Target != "https://192.0.2.2:443" {
		t.Fatalf("unsafe provider host should fall back to IP: %#v ok=%v", asset, ok)
	}
}

func TestCleanMetadataPreservesValidUTF8AtLimit(t *testing.T) {
	metadata := strings.Repeat("测", 400)
	cleaned := cleanMetadata(metadata)
	if len(cleaned) > 1024 || strings.ContainsRune(cleaned, '\uFFFD') {
		t.Fatalf("metadata was not safely truncated: bytes=%d", len(cleaned))
	}
}

func TestMergeAssetIsOrderIndependent(t *testing.T) {
	left := Asset{Target: "https://example.test:443", IP: "192.0.2.2", Port: 443, Domain: "example.test", Protocol: "https", Title: "Zulu", Source: fofaProvider}
	right := Asset{Target: left.Target, IP: left.IP, Port: 443, Domain: left.Domain, Protocol: left.Protocol, Title: "Alpha", ICP: "ICP-A", Source: fofaProvider}
	forward := mergeAsset(left, right)
	reverse := mergeAsset(right, left)
	if forward != reverse || forward.Title != "Alpha" || forward.ICP != "ICP-A" {
		t.Fatalf("duplicate merge is not deterministic: forward=%#v reverse=%#v", forward, reverse)
	}
}

func TestFOFAClientHonorsCallerDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"error":false,"size":0,"results":[]}`))
	}))
	defer server.Close()
	client := NewFOFAClient(server.Client())
	client.endpoint = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := client.Search(ctx, FOFACredential{Email: "tenant@example.test", Key: "secret"}, FOFAQuery{Expression: "domain=x"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
