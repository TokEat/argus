package httpx

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestDo(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)

	t.Run("content-length in header", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://scanme.sh", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 2, resp.ContentLength)
	})

	t.Run("content-length with binary body", func(t *testing.T) {
		req, err := retryablehttp.NewRequest(http.MethodGet, "https://www.w3schools.com/images/favicon.ico", nil)
		require.Nil(t, err)
		resp, err := ht.Do(req, UnsafeOptions{})
		require.Nil(t, err)
		require.Equal(t, 318, resp.ContentLength)
	})
}

func TestSameRedirectOriginAllowsDefaultPortEquivalent(t *testing.T) {
	previous := &http.Request{URL: mustParseURL(t, "https://example.com/portal/cas/login")}
	redirected := &http.Request{URL: mustParseURL(t, "https://example.com:443/bic/ssoService/v1/casLogin")}

	require.True(t, sameRedirectOrigin(previous, redirected))
}

func TestSameRedirectOriginAllowsDefaultHTTPToHTTPSUpgrade(t *testing.T) {
	previous := &http.Request{URL: mustParseURL(t, "http://example.com/")}
	redirected := &http.Request{URL: mustParseURL(t, "https://example.com/portal/")}

	require.True(t, sameRedirectOrigin(previous, redirected))
}

func TestSameRedirectOriginSkipsHTTPToHTTPSFromNonDefaultPort(t *testing.T) {
	previous := &http.Request{URL: mustParseURL(t, "http://example.com:8080/")}
	redirected := &http.Request{URL: mustParseURL(t, "https://example.com/portal/")}

	require.False(t, sameRedirectOrigin(previous, redirected))
}

func TestSameRedirectOriginSkipsSchemeChangeOnSameNonDefaultPort(t *testing.T) {
	previous := &http.Request{URL: mustParseURL(t, "http://example.com:8443/")}
	redirected := &http.Request{URL: mustParseURL(t, "https://example.com:8443/portal/")}

	require.False(t, sameRedirectOrigin(previous, redirected))
}

func TestSameRedirectOriginKeepsNonDefaultPortDistinct(t *testing.T) {
	previous := &http.Request{URL: mustParseURL(t, "https://example.com:8443/")}
	redirected := &http.Request{URL: mustParseURL(t, "https://example.com/portal/")}

	require.False(t, sameRedirectOrigin(previous, redirected))
}

func TestSameRedirectOriginAllowsSameNonDefaultPort(t *testing.T) {
	previous := &http.Request{URL: mustParseURL(t, "https://example.com:8443/")}
	redirected := &http.Request{URL: mustParseURL(t, "https://example.com:8443/portal/")}

	require.True(t, sameRedirectOrigin(previous, redirected))
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}
