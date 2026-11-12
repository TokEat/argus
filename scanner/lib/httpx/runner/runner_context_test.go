package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

func newContextTestRunner(t *testing.T, options *Options) *Runner {
	t.Helper()
	runner, err := New(options)
	require.NoError(t, err)
	t.Cleanup(runner.Close)
	return runner
}

func TestRunnerAnalyzeSharesTargetDeadlineAcrossRetryAndFallback(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)

	var contexts atomic.Int32
	deadline := 120 * time.Millisecond
	runner := newContextTestRunner(t, &Options{
		Timeout:       5,
		Retries:       1,
		HostMaxErrors: -1,
		TargetContext: func(string) context.Context {
			contexts.Add(1)
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			t.Cleanup(cancel)
			return ctx
		},
	})

	started := time.Now()
	result := runner.analyze(runner.hp, httpx.HTTPorHTTPS, httpx.Target{Host: server.URL}, http.MethodGet, server.URL, &runner.scanopts)
	elapsed := time.Since(started)

	require.ErrorIs(t, result.Err, context.DeadlineExceeded)
	require.EqualValues(t, 1, contexts.Load(), "fallback must reuse the original input context")
	require.GreaterOrEqual(t, requests.Load(), int32(1), "the TLS attempt should reach the loopback fixture")
	require.Less(t, elapsed, 800*time.Millisecond, "retry and scheme fallback must not receive a fresh timeout budget")
}

func TestRunnerRecordsNextCheckSourceInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<script>window.location.href = "/next"</script>`))
	}))
	t.Cleanup(server.Close)

	options := &Options{
		Timeout:          1,
		HostMaxErrors:    -1,
		NoFallbackScheme: true,
	}
	options.InputTargetHost = append(options.InputTargetHost, server.URL)
	runner := newContextTestRunner(t, options)
	runner.CallBack = func(Result) {}

	runner.RunEnumeration()

	require.Equal(t, []string{server.URL + "/next"}, runner.NextCheckUrl)
	require.Equal(t, []NextCheckTarget{{
		URL:         server.URL + "/next",
		SourceInput: server.URL,
	}}, runner.NextCheckTargets)
}
