package assetdiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestQuakeClientSearchUsesSingleBoundedRequestAndNormalizesAssets(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/search/quake_service" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-QuakeToken") != "tenant-quake-token" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected Quake headers: %v", r.Header)
		}
		var request quakeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.Query != `domain: "Example.com"` || request.Start != 0 || request.Size != 4 || request.Latest || !request.IgnoreCache {
			t.Fatalf("unexpected Quake request: %+v", request)
		}
		for _, required := range []string{"ip", "port", "service.name", "service.http.host", "service.http.title", "service.http.http_load_url"} {
			found := false
			for _, field := range request.Include {
				if field == required {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("missing include field %q: %v", required, request.Include)
			}
		}
		_, _ = w.Write([]byte(`{
			"code":0,"message":"ok","meta":{"pagination":{"total":5}},"data":[
				{"ip":"192.0.2.1","port":443,"service":{"name":"http/ssl","http":{"host":"Demo.Example.com","title":"Demo","http_load_url":["HTTPS://Demo.Example.com:443/private?q=secret","https://demo.example.com:443/other"]}}},
				{"ip":"192.0.2.10","port":22,"service":{"name":"ssh","http":{}}},
				{"ip":"192.0.2.20","port":3389,"service":{"name":"暂无权限","http":{"host":"暂无权限","title":"暂无权限","http_load_url":[]}}},
				{"ip":"not-an-ip","port":0,"service":{"name":"tcp","http":{}}}
			]}`))
	}))
	defer server.Close()

	client := NewQuakeClient(server.Client())
	client.endpoint = server.URL + "/api/v3/search/quake_service"
	result, err := client.Search(context.Background(), QuakeCredential{Token: "tenant-quake-token"}, QuakeQuery{
		Expression: `domain: "Example.com"`, Limit: 4,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if requests.Load() != 1 || result.Provider != quakeProvider || result.ProviderTotal != 5 || !result.Truncated || result.SkippedRows != 1 {
		t.Fatalf("unexpected result metadata: requests=%d result=%#v", requests.Load(), result)
	}
	if len(result.Assets) != 3 {
		t.Fatalf("assets = %#v, want three normalized targets", result.Assets)
	}
	if got := result.Assets[0]; got.Target != "192.0.2.10:22" || got.Protocol != "ssh" || got.Source != quakeProvider {
		t.Fatalf("ssh asset = %#v", got)
	}
	if got := result.Assets[1]; got.Target != "192.0.2.20:3389" || got.Protocol != "" || got.Title != "" || got.Source != quakeProvider {
		t.Fatalf("restricted fallback asset = %#v", got)
	}
	if got := result.Assets[2]; got.Target != "https://demo.example.com:443" || got.Domain != "demo.example.com" || got.Protocol != "https" || got.Title != "Demo" {
		t.Fatalf("web asset = %#v", got)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, sensitive := range []string{"tenant-quake-token", `domain: "Example.com"`, "/private", "q=secret", "message"} {
		if strings.Contains(string(encoded), sensitive) {
			t.Fatalf("result exposed request/provider value %q: %s", sensitive, encoded)
		}
	}
}

func TestQuakeClientSearchBoundsExpandedURLs(t *testing.T) {
	urls := make([]string, 40)
	for index := range urls {
		urls[index] = fmt.Sprintf("https://host-%02d.example.test/private", index)
	}
	response := map[string]interface{}{
		"code": 0,
		"meta": map[string]interface{}{"pagination": map[string]interface{}{"total": 1}},
		"data": []interface{}{map[string]interface{}{
			"ip": "192.0.2.1", "port": 443,
			"service": map[string]interface{}{"name": "https", "http": map[string]interface{}{"host": "example.test", "http_load_url": urls}},
		}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	client := NewQuakeClient(server.Client())
	client.endpoint = server.URL
	result, err := client.Search(context.Background(), QuakeCredential{Token: "token"}, QuakeQuery{Expression: "service:https", Limit: 1})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if !result.Truncated || len(result.Assets) != 4 {
		t.Fatalf("expanded URLs were not bounded: %#v", result)
	}
}

func TestQuakeClientSearchFetchesPageByOffsetAndReportsMoreResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request quakeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.Start != 200 || request.Size != 100 {
			t.Fatalf("unexpected paging request: %+v", request)
		}
		_, _ = w.Write([]byte(`{"code":0,"meta":{"pagination":{"total":250}},"data":[
			{"ip":"192.0.2.10","port":80,"service":{"name":"http","http":{}}},
			{"ip":"192.0.2.11","port":80,"service":{"name":"http","http":{}}}
		]}`))
	}))
	defer server.Close()

	client := NewQuakeClient(server.Client())
	client.endpoint = server.URL
	result, err := client.Search(context.Background(), QuakeCredential{Token: "token"}, QuakeQuery{
		Expression: "service:http", Limit: 100, Page: 3,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Page != 3 || result.PageSize != 100 || result.ProviderTotal != 250 ||
		!result.Truncated || len(result.Assets) != 2 {
		t.Fatalf("unexpected paged result: %#v", result)
	}
	if got := result.Assets[0]; got.Target != "http://192.0.2.10:80" || got.Source != quakeProvider {
		t.Fatalf("first paged asset = %#v", got)
	}
}

func TestQuakeClientSearchRejectsInvalidInput(t *testing.T) {
	client := NewQuakeClient(nil)
	validCredential := QuakeCredential{Token: "token"}
	for _, test := range []struct {
		name       string
		ctx        context.Context
		credential QuakeCredential
		query      QuakeQuery
	}{
		{name: "nil context", credential: validCredential, query: QuakeQuery{Expression: "service:http"}},
		{name: "missing token", ctx: context.Background(), query: QuakeQuery{Expression: "service:http"}},
		{name: "credential control", ctx: context.Background(), credential: QuakeCredential{Token: "token\nleak"}, query: QuakeQuery{Expression: "service:http"}},
		{name: "empty query", ctx: context.Background(), credential: validCredential},
		{name: "query control", ctx: context.Background(), credential: validCredential, query: QuakeQuery{Expression: "service:http\nnext"}},
		{name: "limit too large", ctx: context.Background(), credential: validCredential, query: QuakeQuery{Expression: "service:http", Limit: MaxQuakeResultLimit + 1}},
		{name: "page too large", ctx: context.Background(), credential: validCredential, query: QuakeQuery{Expression: "service:http", Page: quakeMaxPages + 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.Search(test.ctx, test.credential, test.query); !errors.Is(err, ErrInvalidQuakeRequest) {
				t.Fatalf("expected typed validation error, got %v", err)
			}
		})
	}
}

func TestQuakeClientSearchSanitizesTransportHTTPAndProviderErrors(t *testing.T) {
	secret := "do-not-leak-quake-token"
	expression := "service:private-query"
	client := NewQuakeClient(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, errors.New(request.Header.Get("X-QuakeToken") + request.URL.String())
	})})
	_, err := client.Search(context.Background(), QuakeCredential{Token: secret}, QuakeQuery{Expression: expression})
	if !errors.Is(err, ErrQuakeUnavailable) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), expression) {
		t.Fatalf("transport error was not sanitized: %v", err)
	}

	for _, test := range []struct {
		name    string
		status  int
		body    string
		wantErr error
	}{
		{name: "http rejection", status: http.StatusUnauthorized, body: secret, wantErr: ErrQuakeRejected},
		{name: "http unavailable", status: http.StatusBadGateway, body: secret, wantErr: ErrQuakeUnavailable},
		{name: "provider rejection", status: http.StatusOK, body: `{"code":401,"message":"` + secret + `"}`, wantErr: ErrQuakeRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client := NewQuakeClient(server.Client())
			client.endpoint = server.URL
			_, err := client.Search(context.Background(), QuakeCredential{Token: secret}, QuakeQuery{Expression: expression})
			if !errors.Is(err, test.wantErr) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), expression) {
				t.Fatalf("provider error was not sanitized: %v", err)
			}
		})
	}
}

func TestQuakeClientRejectsMalformedAndOversizedResponses(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		mutate  func(*QuakeClient)
		wantErr error
	}{
		{name: "missing code", body: `{"data":[]}`, wantErr: ErrInvalidQuakeResponse},
		{name: "invalid code", body: `{"code":{},"data":[]}`, wantErr: ErrInvalidQuakeResponse},
		{name: "trailing json", body: `{"code":0,"data":[]} {}`, wantErr: ErrInvalidQuakeResponse},
		{name: "negative total", body: `{"code":"0","meta":{"pagination":{"total":-1}},"data":[]}`, wantErr: ErrInvalidQuakeResponse},
		{name: "empty before total", body: `{"code":0,"meta":{"pagination":{"total":1}},"data":[]}`, wantErr: ErrInvalidQuakeResponse},
		{
			name: "oversized", body: `{"code":0,"data":[]}` + strings.Repeat(" ", 128), wantErr: ErrInvalidQuakeResponse,
			mutate: func(client *QuakeClient) { client.responseLimit = 32 },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client := NewQuakeClient(server.Client())
			client.endpoint = server.URL
			if test.mutate != nil {
				test.mutate(client)
			}
			_, err := client.Search(context.Background(), QuakeCredential{Token: "token"}, QuakeQuery{Expression: "service:http"})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("expected %v, got %v", test.wantErr, err)
			}
		})
	}
}

func TestQuakeClientDoesNotForwardTokenAcrossRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	credentialSink := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
	}))
	defer credentialSink.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, credentialSink.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	client := NewQuakeClient(origin.Client())
	client.endpoint = origin.URL
	if _, err := client.Search(context.Background(), QuakeCredential{Token: "redirect-secret"}, QuakeQuery{Expression: "service:http"}); !errors.Is(err, ErrQuakeRejected) {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
	if calls := redirectedRequests.Load(); calls != 0 {
		t.Fatalf("Quake token was forwarded across %d redirect requests", calls)
	}
}

func TestQuakeClientHonorsCallerDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"code":0,"data":[]}`))
	}))
	defer server.Close()
	client := NewQuakeClient(server.Client())
	client.endpoint = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := client.Search(ctx, QuakeCredential{Token: "token"}, QuakeQuery{Expression: "service:http"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
}
