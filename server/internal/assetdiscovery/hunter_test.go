package assetdiscovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHunterClientSearchPaginatesNormalizesAndDropsRawBanner(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/openApi/search" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		query := r.URL.Query()
		decoded, err := base64.URLEncoding.DecodeString(query.Get("search"))
		if err != nil || string(decoded) != `domain="Example.com"` {
			t.Fatalf("search = %q decoded=%q err=%v", query.Get("search"), decoded, err)
		}
		if query.Get("api-key") != "tenant-hunter-key" || query.Get("page_size") != "2" || query.Get("is_web") != hunterSearchWebAndServices {
			t.Fatalf("unexpected Hunter query parameters: %v", query)
		}
		w.Header().Set("Content-Type", "application/json")
		switch query.Get("page") {
		case "1":
			_, _ = w.Write([]byte(`{
				"code":200,"message":"ok","data":{"total":4,"rest_quota":"private-quota","arr":[
					{"url":"HTTPS://Demo.Example.com:443/path?q=private","ip":"192.0.2.1","port":443,"domain":"Demo.Example.com.","protocol":"https","city":"Shenzhen","company":"Zulu Co","status_code":200,"web_title":"Zulu","country":"CN","banner":"private-banner"},
					{"url":"","ip":"192.0.2.10","port":22,"domain":"","protocol":"ssh","banner":"SSH-2.0-private"}
				]}}`))
		case "2":
			_, _ = w.Write([]byte(`{
				"code":200,"data":{"total":4,"arr":[
					{"url":"demo.example.com:443","ip":"192.0.2.1","port":443,"domain":"demo.example.com","protocol":"https","city":"Shenzhen","company":"Alpha Co","status_code":200,"web_title":"Alpha","country":"CN","banner":"second-private-banner"},
					{"url":"bad","ip":"not-an-ip","port":0,"domain":"","protocol":"tcp","banner":"invalid-private-banner"}
				]}}`))
		default:
			t.Fatalf("unexpected page: %s", query.Get("page"))
		}
	}))
	defer server.Close()

	client := NewHunterClient(server.Client())
	client.endpoint = server.URL + "/openApi/search"
	result, err := client.Search(context.Background(), HunterCredential{APIKey: "tenant-hunter-key"}, HunterQuery{
		Expression: `domain="Example.com"`, Limit: 4, PageSize: 2,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if requests.Load() != 2 || result.Provider != hunterProvider || result.ProviderTotal != 4 || result.Truncated || result.SkippedRows != 1 {
		t.Fatalf("unexpected result metadata: requests=%d result=%#v", requests.Load(), result)
	}
	if len(result.Assets) != 2 {
		t.Fatalf("assets = %#v, want two normalized unique targets", result.Assets)
	}
	if got := result.Assets[0]; got.Target != "192.0.2.10:22" || got.IP != "192.0.2.10" || got.Protocol != "ssh" || got.Source != hunterProvider {
		t.Fatalf("service asset = %#v", got)
	}
	if got := result.Assets[1]; got.Target != "https://demo.example.com:443" || got.Domain != "demo.example.com" || got.Title != "Alpha" || got.Company != "Alpha Co" || got.City != "Shenzhen" || got.Country != "CN" || got.StatusCode != 200 {
		t.Fatalf("web asset = %#v", got)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, sensitive := range []string{"tenant-hunter-key", `domain="Example.com"`, "private-banner", "private-quota", "/path", "q=private"} {
		if strings.Contains(string(encoded), sensitive) {
			t.Fatalf("result exposed raw provider/request value %q: %s", sensitive, encoded)
		}
	}
}

func TestHunterClientSearchFetchesOneExplicitPage(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		query := r.URL.Query()
		if query.Get("page") != "2" || query.Get("page_size") != "2" {
			t.Fatalf("unexpected paging parameters: %v", query)
		}
		_, _ = w.Write([]byte(`{"code":200,"data":{"total":4,"arr":[
			{"url":"","ip":"192.0.2.3","port":22,"protocol":"ssh"},
			{"url":"","ip":"192.0.2.4","port":22,"protocol":"ssh"}
		]}}`))
	}))
	defer server.Close()

	client := NewHunterClient(server.Client())
	client.endpoint = server.URL
	result, err := client.Search(context.Background(), HunterCredential{APIKey: "key"}, HunterQuery{
		Expression: "domain=example", Limit: 4, PageSize: 2, Page: 2,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if requests.Load() != 1 || result.Page != 2 || result.PageSize != 2 ||
		result.ProviderTotal != 4 || result.Truncated || len(result.Assets) != 2 {
		t.Fatalf("unexpected single-page result: requests=%d result=%#v", requests.Load(), result)
	}
}

func TestHunterClientSearchEnforcesResultLimitAcrossPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		start := (page-1)*2 + 1
		_, _ = w.Write([]byte(`{"code":200,"data":{"total":5,"arr":[` +
			`{"url":"","ip":"192.0.2.` + strconv.Itoa(start) + `","port":22,"protocol":"ssh"},` +
			`{"url":"","ip":"192.0.2.` + strconv.Itoa(start+1) + `","port":22,"protocol":"ssh"}` +
			`]}}`))
	}))
	defer server.Close()

	client := NewHunterClient(server.Client())
	client.endpoint = server.URL
	result, err := client.Search(context.Background(), HunterCredential{APIKey: "key"}, HunterQuery{
		Expression: "domain=example", Limit: 3, PageSize: 2,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if !result.Truncated || result.ProviderTotal != 5 || len(result.Assets) != 3 {
		t.Fatalf("result limit was not enforced: %#v", result)
	}
}

func TestHunterClientSearchRejectsInvalidInput(t *testing.T) {
	client := NewHunterClient(nil)
	validCredential := HunterCredential{APIKey: "key"}
	for _, test := range []struct {
		name       string
		ctx        context.Context
		credential HunterCredential
		query      HunterQuery
	}{
		{name: "nil context", credential: validCredential, query: HunterQuery{Expression: "domain=x"}},
		{name: "missing key", ctx: context.Background(), query: HunterQuery{Expression: "domain=x"}},
		{name: "credential control", ctx: context.Background(), credential: HunterCredential{APIKey: "key\nleak"}, query: HunterQuery{Expression: "domain=x"}},
		{name: "empty query", ctx: context.Background(), credential: validCredential},
		{name: "query control", ctx: context.Background(), credential: validCredential, query: HunterQuery{Expression: "domain=x\nnext"}},
		{name: "limit too large", ctx: context.Background(), credential: validCredential, query: HunterQuery{Expression: "domain=x", Limit: MaxHunterResultLimit + 1}},
		{name: "page size too large", ctx: context.Background(), credential: validCredential, query: HunterQuery{Expression: "domain=x", PageSize: MaxHunterPageSize + 1}},
		{name: "page too large", ctx: context.Background(), credential: validCredential, query: HunterQuery{Expression: "domain=x", Page: hunterMaxPages + 1}},
		{name: "negative page", ctx: context.Background(), credential: validCredential, query: HunterQuery{Expression: "domain=x", Page: -1}},
		{name: "too many pages", ctx: context.Background(), credential: validCredential, query: HunterQuery{Expression: "domain=x", Limit: 11, PageSize: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.Search(test.ctx, test.credential, test.query); !errors.Is(err, ErrInvalidHunterRequest) {
				t.Fatalf("expected typed validation error, got %v", err)
			}
		})
	}
}

func TestHunterClientSearchSanitizesTransportHTTPAndProviderErrors(t *testing.T) {
	secret := "do-not-leak-hunter-key"
	expression := "domain=private-hunter-query"
	client := NewHunterClient(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, errors.New(request.URL.String())
	})})
	_, err := client.Search(context.Background(), HunterCredential{APIKey: secret}, HunterQuery{Expression: expression})
	if !errors.Is(err, ErrHunterUnavailable) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), expression) {
		t.Fatalf("transport error was not sanitized: %v", err)
	}

	for _, test := range []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{name: "http rejection", status: http.StatusUnauthorized, body: secret, wantErr: ErrHunterRejected},
		{name: "http unavailable", status: http.StatusBadGateway, body: secret, wantErr: ErrHunterUnavailable},
		{name: "provider rejection", status: http.StatusOK, body: `{"code":401,"message":"` + secret + `"}`, wantErr: ErrHunterRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client := NewHunterClient(server.Client())
			client.endpoint = server.URL
			_, err := client.Search(context.Background(), HunterCredential{APIKey: secret}, HunterQuery{Expression: expression})
			if !errors.Is(err, test.wantErr) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), expression) {
				t.Fatalf("provider error was not sanitized: %v", err)
			}
		})
	}
}

func TestHunterClientRejectsMalformedPaginationAndTotalResponseOverflow(t *testing.T) {
	validItem := `{"url":"","ip":"192.0.2.1","port":22,"protocol":"ssh"}`
	firstPage := `{"code":200,"data":{"total":3,"arr":[` + validItem + `,` + strings.Replace(validItem, "192.0.2.1", "192.0.2.2", 1) + `]},"padding":"` + strings.Repeat("a", 32) + `"}`
	secondPage := `{"code":200,"data":{"total":3,"arr":[` + strings.Replace(validItem, "192.0.2.1", "192.0.2.3", 1) + `]},"padding":"` + strings.Repeat("b", 32) + `"}`

	tests := []struct {
		name          string
		handler       http.HandlerFunc
		responseLimit int64
	}{
		{
			name: "oversized single response",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"code":200,"data":{"total":0,"arr":[]}}` + strings.Repeat(" ", 128)))
			},
			responseLimit: 32,
		},
		{
			name: "trailing json",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"code":200,"data":{"total":0,"arr":[]}} {}`))
			},
		},
		{
			name: "rows with zero total",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"code":200,"data":{"total":0,"arr":[` + validItem + `]}}`))
			},
		},
		{
			name: "rows exceed total",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"code":200,"data":{"total":1,"arr":[` + validItem + `,` + strings.Replace(validItem, "192.0.2.1", "192.0.2.2", 1) + `]}}`))
			},
		},
		{
			name: "short page",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"code":200,"data":{"total":5,"arr":[` + validItem + `]}}`))
			},
		},
		{
			name: "total response budget across pages",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("page") == "1" {
					_, _ = w.Write([]byte(firstPage))
					return
				}
				_, _ = w.Write([]byte(secondPage))
			},
			responseLimit: int64(len(firstPage) + len(secondPage) - 1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			client := NewHunterClient(server.Client())
			client.endpoint = server.URL
			if test.responseLimit != 0 {
				client.responseLimit = test.responseLimit
			}
			_, err := client.Search(context.Background(), HunterCredential{APIKey: "key"}, HunterQuery{
				Expression: "domain=x", Limit: 3, PageSize: 2,
			})
			if !errors.Is(err, ErrInvalidHunterResponse) {
				t.Fatalf("expected invalid Hunter response, got %v", err)
			}
		})
	}
}

func TestHunterClientDoesNotForwardAPIKeyAcrossRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	credentialSink := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
	}))
	defer credentialSink.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, credentialSink.URL, http.StatusFound)
	}))
	defer origin.Close()

	client := NewHunterClient(origin.Client())
	client.endpoint = origin.URL
	if _, err := client.Search(context.Background(), HunterCredential{APIKey: "redirect-secret"}, HunterQuery{Expression: "domain=redirect"}); !errors.Is(err, ErrHunterRejected) {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
	if calls := redirectedRequests.Load(); calls != 0 {
		t.Fatalf("Hunter API key was forwarded across %d redirect requests", calls)
	}
}

func TestNormalizeHunterRowCanonicalizesTargetsAndRejectsUnsafeData(t *testing.T) {
	asset, ok := normalizeHunterRow(hunterResponseItem{IP: "2001:db8::1", Port: 22, Protocol: "ssh"})
	if !ok || asset.Target != "[2001:db8::1]:22" {
		t.Fatalf("IPv6 asset = %#v ok=%v", asset, ok)
	}
	asset, ok = normalizeHunterRow(hunterResponseItem{URL: "https://user:pass@example.test/private", IP: "192.0.2.2", Port: 443, Protocol: "https"})
	if !ok || asset.Target != "https://192.0.2.2:443" {
		t.Fatalf("unsafe URL should fall back to IP: %#v ok=%v", asset, ok)
	}
	asset, ok = normalizeHunterRow(hunterResponseItem{URL: "https://Derived.Example.test/path?q=private", Port: 443})
	if !ok || asset.Target != "https://derived.example.test:443" || asset.Domain != "derived.example.test" || asset.Protocol != "https" {
		t.Fatalf("URL-derived asset = %#v ok=%v", asset, ok)
	}
	if _, ok := normalizeHunterRow(hunterResponseItem{IP: "192.0.2.3", Port: 70000, Protocol: "ssh"}); ok {
		t.Fatal("invalid port was accepted")
	}
}

func TestHunterClientHonorsCallerDeadlineAcrossPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"code":200,"data":{"total":0,"arr":[]}}`))
	}))
	defer server.Close()
	client := NewHunterClient(server.Client())
	client.endpoint = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := client.Search(ctx, HunterCredential{APIKey: "key"}, HunterQuery{Expression: "domain=x"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
}
