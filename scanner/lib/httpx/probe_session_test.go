package httpx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/httpx/runner"
	"github.com/stretchr/testify/require"
)

func TestProbeSessionInitialReservationStartsAtRequest(t *testing.T) {
	session := NewProbeSession(context.Background(), 1)
	defer session.Close()
	const first = "http://127.0.0.1:18080/"
	const second = "http://127.0.0.1:18081/"
	session.reserveInputs([]string{first, second})

	firstCtx := session.TargetContext(first)
	time.Sleep(1100 * time.Millisecond)
	require.Error(t, firstCtx.Err())
	secondCtx := session.TargetContext(second)
	require.NoError(t, secondCtx.Err(), "independent inputs must not share a deadline")
}

func TestProbeSessionParentCancelAndClose(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	session := NewProbeSession(parent, 5)
	ctx := session.TargetContext("http://127.0.0.1:18080/")
	cancel()
	require.Eventually(t, func() bool { return ctx.Err() != nil }, time.Second, 10*time.Millisecond)

	other := NewProbeSession(context.Background(), 5)
	otherCtx := other.TargetContext("http://127.0.0.1:18081/")
	other.Close()
	require.Eventually(t, func() bool { return otherCtx.Err() != nil }, time.Second, 10*time.Millisecond)
}

func TestProbeSessionNextCheckAndLocationUseSourceBudget(t *testing.T) {
	session := NewProbeSession(context.Background(), 5)
	defer session.Close()
	source := "http://127.0.0.1:18080/"
	session.reserveInputs([]string{source})
	session.TargetContext(source)

	next := "http://127.0.0.1:18080/next"
	urls := session.registerNextCheckTargets([]runner.NextCheckTarget{{URL: next, SourceInput: source}})
	require.Equal(t, []string{next}, urls)
	require.Same(t, session.lookup(source), session.lookup(next))

	location := safeLocation(source, "/location")
	require.NotEmpty(t, location)
	session.alias(location, source)
	require.Same(t, session.lookup(source), session.lookup(location))

	// An independently supplied URL keeps its own budget when discovered as a
	// location from another response.
	independent := "http://127.0.0.1:18080/independent"
	session.reserveInputs([]string{independent})
	session.alias(independent, source)
	require.NotSame(t, session.lookup(source), session.lookup(independent))
	require.Empty(t, safeLocation(source, "https://127.0.0.1:18080/not-an-upgrade"))
}

func TestPackageAndSessionCallsKeepNextCheckVisitsIsolated(t *testing.T) {
	var nextRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/root-a", "/root-b":
			_, _ = w.Write([]byte(`<script>window.location.href = "/next"</script>`))
		case "/next":
			nextRequests.Add(1)
			_, _ = w.Write([]byte("next"))
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	var packageCallbacks atomic.Int32
	CallHTTPx([]string{server.URL + "/root-a"}, func(result runner.Result) {
		if strings.HasSuffix(result.URL, "/next") {
			packageCallbacks.Add(1)
		}
	}, "", 1, 3)
	require.EqualValues(t, 1, packageCallbacks.Load(), "package-level call did not complete its next-check target")

	session := NewProbeSession(context.Background(), 3)
	defer session.Close()
	var sessionCallbacks atomic.Int32
	session.CallHTTPx([]string{server.URL + "/root-b"}, func(result runner.Result) {
		if strings.HasSuffix(result.URL, "/next") {
			sessionCallbacks.Add(1)
		}
	}, "", 1)
	require.EqualValues(t, 1, sessionCallbacks.Load(), "session did not complete its own next-check target")
	require.EqualValues(t, 2, nextRequests.Load(), "separate package/session calls must not suppress a shared next-check URL")
}

func TestURLVisitSetAtomicallyDeduplicatesSharedVisits(t *testing.T) {
	visits := newMemoryURLVisitSet()
	const workers = 32
	start := make(chan struct{})
	results := make(chan bool, workers)
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- visits.TryVisitHTTPURL("https://EXAMPLE.test:443/shared#fragment")
		}()
	}
	close(start)
	group.Wait()
	close(results)

	accepted := 0
	for result := range results {
		if result {
			accepted++
		}
	}
	require.Equal(t, 1, accepted)
}

func TestProbeSessionsWithIndependentVisitSetsDoNotShareURLs(t *testing.T) {
	first := NewProbeSessionWithURLVisits(context.Background(), 3, newMemoryURLVisitSet())
	second := NewProbeSessionWithURLVisits(context.Background(), 3, newMemoryURLVisitSet())
	defer first.Close()
	defer second.Close()

	url := "https://example.test/shared"
	require.Equal(t, []string{url}, first.reserveUnvisitedURLs([]string{url}))
	require.Equal(t, []string{url}, second.reserveUnvisitedURLs([]string{url}))
	require.Empty(t, first.reserveUnvisitedURLs([]string{url}))
}

func TestProbeSessionsWithSharedVisitSetDeduplicateURLs(t *testing.T) {
	visits := newMemoryURLVisitSet()
	first := NewProbeSessionWithURLVisits(context.Background(), 3, visits)
	second := NewProbeSessionWithURLVisits(context.Background(), 3, visits)
	defer first.Close()
	defer second.Close()

	url := "https://example.test/shared"
	require.Equal(t, []string{url}, first.reserveUnvisitedURLs([]string{url}))
	require.Empty(t, second.reserveUnvisitedURLs([]string{url}))
}

type typedNilURLVisitSet struct{}

func (*typedNilURLVisitSet) TryVisitHTTPURL(string) bool {
	panic("typed-nil URL visit set must be replaced before use")
}

func TestProbeSessionReplacesTypedNilVisitSet(t *testing.T) {
	var visits *typedNilURLVisitSet
	session := NewProbeSessionWithURLVisits(context.Background(), 3, visits)
	defer session.Close()

	url := "https://example.test/typed-nil"
	require.Equal(t, []string{url}, session.reserveUnvisitedURLs([]string{url}))
	require.Empty(t, session.reserveUnvisitedURLs([]string{url}))
}

func TestRunnerConstructionFailureDoesNotClaimVisit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	originalNewRunner := newProbeRunner
	defer func() { newProbeRunner = originalNewRunner }()
	var attempts atomic.Int32
	newProbeRunner = func(options *runner.Options) (*runner.Runner, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.New("injected runner construction failure")
		}
		return originalNewRunner(options)
	}

	session := NewProbeSession(context.Background(), 3)
	defer session.Close()
	var callbacks atomic.Int32
	session.CallHTTPx([]string{server.URL}, func(runner.Result) {
		callbacks.Add(1)
	}, "", 1)
	require.Zero(t, callbacks.Load())

	session.CallHTTPx([]string{server.URL}, func(runner.Result) {
		callbacks.Add(1)
	}, "", 1)
	require.EqualValues(t, 1, callbacks.Load(), "runner construction failure permanently claimed the URL")
}

func TestProbeSessionSuppressesLateCallback(t *testing.T) {
	session := NewProbeSession(context.Background(), 1)
	defer session.Close()
	const source = "http://127.0.0.1:18080/"
	session.reserveInputs([]string{source})
	ctx := session.TargetContext(source)
	require.Eventually(t, func() bool { return ctx.Err() != nil }, 2*time.Second, 20*time.Millisecond)

	var calls atomic.Int32
	session.wrapCallback(func(runner.Result) { calls.Add(1) })(runner.Result{
		Input: source,
		URL:   source,
	})
	require.Zero(t, calls.Load())
}

func TestProbeSessionHangingTargetUsesSingleBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	session := NewProbeSession(context.Background(), 1)
	defer session.Close()
	start := time.Now()
	session.CallHTTPx([]string{server.URL}, func(runner.Result) {}, "", 1)
	require.Less(t, time.Since(start), 2500*time.Millisecond)
}

func TestProbeSessionParentCancellationStopsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	var startedOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-r.Context().Done()
	}))
	defer server.Close()

	parent, cancel := context.WithCancel(context.Background())
	session := NewProbeSession(parent, 10)
	defer session.Close()
	done := make(chan struct{})
	var callbacks atomic.Int32
	go func() {
		defer close(done)
		session.CallHTTPx([]string{server.URL}, func(runner.Result) { callbacks.Add(1) }, "", 1)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP request did not reach the loopback fixture")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("HTTP probe did not converge after parent cancellation")
	}
	require.Zero(t, callbacks.Load(), "cancelled request must not emit a late callback")
}

func TestProbeSessionConcurrentTargetsKeepIndependentBudgets(t *testing.T) {
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hanging.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer fast.Close()

	session := NewProbeSession(context.Background(), 1)
	defer session.Close()
	var successful atomic.Int32
	session.CallHTTPx([]string{hanging.URL, fast.URL}, func(resp runner.Result) {
		if strings.HasPrefix(resp.URL, fast.URL) {
			successful.Add(1)
		}
	}, "", 2)
	require.EqualValues(t, 1, successful.Load(), "one exhausted target must not cancel another target")
	require.ErrorIs(t, session.Err(), context.DeadlineExceeded)
}

func TestProbeSessionCompletedTargetDoesNotBecomeFailureAfterDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	session := NewProbeSession(context.Background(), 1)
	defer session.Close()
	session.CallHTTPx([]string{server.URL}, func(runner.Result) {}, "", 1)
	time.Sleep(1100 * time.Millisecond)
	require.NoError(t, session.Err(), "a completed target must not become failed while the session remains open")
}

func TestProbeSessionExpiredDiscoveredFollowUpMakesCoverageIncomplete(t *testing.T) {
	session := NewProbeSession(context.Background(), 1)
	defer session.Close()
	const source = "http://127.0.0.1:18080/"
	const followUp = "http://127.0.0.1:18080/follow-up"
	session.reserveInputs([]string{source})
	session.TargetContext(source)
	require.True(t, session.completeIfActive(source))
	session.alias(followUp, source)
	time.Sleep(1100 * time.Millisecond)
	require.Empty(t, filterActiveTargets(session, []string{followUp}))
	require.ErrorIs(t, session.Err(), context.DeadlineExceeded)
}

func TestProbeSessionNextCheckConsumesRemainingBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			time.Sleep(1500 * time.Millisecond)
			_, _ = w.Write([]byte(`<script>window.location.href = "/hang"</script>`))
		case "/hang":
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	session := NewProbeSession(context.Background(), 2)
	defer session.Close()
	started := time.Now()
	session.CallHTTPx([]string{server.URL}, func(runner.Result) {}, "", 1)
	require.Less(t, time.Since(started), 3*time.Second, "NextCheckUrl must not receive a fresh target timeout")
	require.ErrorIs(t, session.Err(), context.DeadlineExceeded)
}

func TestProbeSessionLocationConsumesRemainingBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hang" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Location", "/hang")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	session := NewProbeSession(context.Background(), 2)
	defer session.Close()
	started := time.Now()
	session.CallHTTPx([]string{server.URL}, func(runner.Result) {}, "", 1)
	time.Sleep(1500 * time.Millisecond)
	session.CallHTTPxFollowHostRedirects([]string{server.URL + "/hang"}, func(runner.Result) {}, "", 1)
	require.Less(t, time.Since(started), 3*time.Second, "same-origin Location must not receive a fresh target timeout")
	require.ErrorIs(t, session.Err(), context.DeadlineExceeded)
}

type schemeFixture struct {
	listener net.Listener
	done     chan struct{}
	bytes    chan byte
	wg       sync.WaitGroup
	respond  bool
}

func newSchemeFixture(t *testing.T, respondHTTP bool) *schemeFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	fixture := &schemeFixture{
		listener: listener,
		done:     make(chan struct{}),
		bytes:    make(chan byte, 16),
		respond:  respondHTTP,
	}
	fixture.wg.Add(1)
	go func() {
		defer fixture.wg.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			fixture.wg.Add(1)
			go fixture.handle(connection)
		}
	}()
	return fixture
}

func (f *schemeFixture) handle(connection net.Conn) {
	defer f.wg.Done()
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	first := []byte{0}
	if _, err := connection.Read(first); err != nil {
		return
	}
	select {
	case f.bytes <- first[0]:
	case <-f.done:
		return
	}
	if f.respond && first[0] == 'G' {
		_, _ = connection.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}
}

func (f *schemeFixture) close() []byte {
	close(f.done)
	_ = f.listener.Close()
	f.wg.Wait()
	close(f.bytes)
	var observed []byte
	for value := range f.bytes {
		observed = append(observed, value)
	}
	return observed
}

func TestProbeSessionExplicitSchemesNeverProbeAlternateProtocol(t *testing.T) {
	for _, test := range []struct {
		name       string
		scheme     string
		unexpected byte
	}{
		{name: "http", scheme: "http://", unexpected: 0x16},
		{name: "https", scheme: "https://", unexpected: 'G'},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSchemeFixture(t, false)
			session := NewProbeSession(context.Background(), 3)
			session.CallHTTPx([]string{test.scheme + fixture.listener.Addr().String()}, func(runner.Result) {}, "", 1)
			session.Close()
			observed := fixture.close()
			require.NotEmpty(t, observed)
			require.NotContains(t, observed, test.unexpected)
		})
	}
}

func TestProbeSessionExplicitHTTPLoopbackReturnsResult(t *testing.T) {
	fixture := newSchemeFixture(t, true)
	session := NewProbeSession(context.Background(), 3)
	var callbacks atomic.Int32
	session.CallHTTPx([]string{"http://" + fixture.listener.Addr().String()}, func(result runner.Result) {
		if result.StatusCode == http.StatusOK {
			callbacks.Add(1)
		}
	}, "", 1)
	session.Close()
	observed := fixture.close()

	require.Contains(t, observed, byte('G'), "explicit HTTP loopback target should be requested")
	require.EqualValues(t, 1, callbacks.Load())
	require.NoError(t, session.Err())
}

func TestProbeSessionUnschemedTargetRetainsBudgetedFallback(t *testing.T) {
	fixture := newSchemeFixture(t, true)
	session := NewProbeSession(context.Background(), 3)
	var callbacks atomic.Int32
	session.CallHTTPx([]string{fixture.listener.Addr().String()}, func(runner.Result) { callbacks.Add(1) }, "", 1)
	session.Close()
	observed := fixture.close()

	require.Contains(t, observed, byte(0x16), "unschemed target should try HTTPS first")
	require.Contains(t, observed, byte('G'), "unschemed target should retain HTTP fallback")
	require.EqualValues(t, 1, callbacks.Load())
}
