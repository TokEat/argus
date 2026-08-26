package engine

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/P0lar1ght/argus/scanner/internal/scanner/web"
	"github.com/P0lar1ght/argus/scanner/structs"

	"github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/httpx/runner"
)

type fakeHTTPProbeSession struct {
	initialCalls  [][]string
	redirectCalls [][]string
	closed        int
	err           error
}

func (s *fakeHTTPProbeSession) CallHTTPx(urls []string, callback func(runner.Result), _ string, _ int) {
	s.initialCalls = append(s.initialCalls, append([]string(nil), urls...))
	callback(testRedirectResult("https://example.test", "/one"))
}

func (s *fakeHTTPProbeSession) CallHTTPxFollowHostRedirects(urls []string, callback func(runner.Result), _ string, _ int) {
	s.redirectCalls = append(s.redirectCalls, append([]string(nil), urls...))
	if len(s.redirectCalls) == 1 {
		callback(testRedirectResult("https://example.test/one", "/two"))
	}
}

func (s *fakeHTTPProbeSession) Close() { s.closed++ }

func (s *fakeHTTPProbeSession) Err() error { return s.err }

func testRedirectResult(rawURL, location string) runner.Result {
	return runner.Result{
		URL:        rawURL,
		Scheme:     "https",
		Host:       "example.test",
		Port:       "443",
		Path:       "/",
		Location:   location,
		StatusCode: 302,
		Hashes: map[string]interface{}{
			"body_md5":   "body",
			"header_md5": "header",
		},
	}
}

func TestRunHTTPProbeReusesSessionForRedirectsAndPropagatesParentContext(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()

	var factoryParent context.Context
	var factoryVisits httpx.URLVisitSet
	session := &fakeHTTPProbeSession{}
	previousFactory := newHTTPProbeSession
	newHTTPProbeSession = func(gotParent context.Context, _ int, visits httpx.URLVisitSet) httpProbeSession {
		factoryParent = gotParent
		factoryVisits = visits
		return session
	}
	defer func() { newHTTPProbeSession = previousFactory }()

	urlMap := make(map[string]structs.URLEntity)
	webRuntime := web.NewRuntime(
		urlMap, &sync.Mutex{}, nil, nil, nil, nil, nil, nil,
		map[string][]string{}, &sync.Mutex{}, nil,
	)
	ctx := &ScanContext{Ctx: parent}
	cfg := Config{HTTPProxy: "", WebThreads: 3, WebTimeout: 2}

	if err := (&Pipeline{}).runHTTPProbe(ctx, &cfg, []string{"https://example.test"}, webRuntime); err != nil {
		t.Fatalf("runHTTPProbe returned error: %v", err)
	}
	if factoryParent != parent {
		t.Fatal("HTTP probe session did not receive ScanContext parent context")
	}
	if factoryVisits != ctx {
		t.Fatal("HTTP probe session did not receive the task ScanContext URL visit set")
	}
	if len(session.initialCalls) != 1 || len(session.initialCalls[0]) != 1 || session.initialCalls[0][0] != "https://example.test" {
		t.Fatalf("unexpected initial calls: %#v", session.initialCalls)
	}
	if len(session.redirectCalls) != 2 {
		t.Fatalf("expected two redirect passes through the same session, got %#v", session.redirectCalls)
	}
	if got := session.redirectCalls[0]; len(got) != 1 || got[0] != "https://example.test/one" {
		t.Fatalf("unexpected first redirect pass: %#v", got)
	}
	if got := session.redirectCalls[1]; len(got) != 1 || got[0] != "https://example.test/two" {
		t.Fatalf("unexpected second redirect pass: %#v", got)
	}
	if session.closed != 1 {
		t.Fatalf("expected one session close, got %d", session.closed)
	}
}

func TestPipelineHTTPProbeContextFallsBackToBackground(t *testing.T) {
	if pipelineHTTPProbeContext(nil) == nil {
		t.Fatal("nil ScanContext must use a background HTTP probe context")
	}
	if pipelineHTTPProbeContext(&ScanContext{}) == nil {
		t.Fatal("ScanContext without Ctx must use a background HTTP probe context")
	}
	if pipelineHTTPURLVisits(nil) != nil {
		t.Fatal("nil ScanContext must not expose a shared URL visit set")
	}
	ctx := &ScanContext{}
	if pipelineHTTPURLVisits(ctx) != ctx {
		t.Fatal("Pipeline must expose the current ScanContext as the URL visit set")
	}
}

func TestRunHTTPProbeStillDrainsSuccessfulRedirectsWhenAnotherTargetExpires(t *testing.T) {
	session := &fakeHTTPProbeSession{err: context.DeadlineExceeded}
	previousFactory := newHTTPProbeSession
	newHTTPProbeSession = func(context.Context, int, httpx.URLVisitSet) httpProbeSession { return session }
	defer func() { newHTTPProbeSession = previousFactory }()

	webRuntime := web.NewRuntime(
		map[string]structs.URLEntity{}, &sync.Mutex{}, nil, nil, nil, nil, nil, nil,
		map[string][]string{}, &sync.Mutex{}, nil,
	)
	err := (&Pipeline{}).runHTTPProbe(&ScanContext{Ctx: context.Background()}, &Config{WebTimeout: 1}, []string{"https://fast.example", "https://timeout.example"}, webRuntime)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runHTTPProbe error=%v, want target deadline", err)
	}
	if len(session.redirectCalls) != 2 {
		t.Fatalf("successful target redirects must be drained before reporting another target's timeout: %#v", session.redirectCalls)
	}
}

func TestCompleteHTTPProbePhaseMarksTargetDeadlineFailedWithoutCancellingPipeline(t *testing.T) {
	var phases []PhaseEvent
	ctx := &ScanContext{
		Ctx: context.Background(),
		PhaseObserver: func(event PhaseEvent) {
			phases = append(phases, event)
		},
	}

	complete, err := completeHTTPProbePhase(ctx, context.DeadlineExceeded)
	if err != nil {
		t.Fatalf("target deadline should fail the stage without cancelling the remaining pipeline: %v", err)
	}
	if complete {
		t.Fatal("target deadline must keep HTTP coverage incomplete")
	}
	if len(phases) != 1 || phases[0].Phase != PhaseHTTPProbe || phases[0].Status != "failed" {
		t.Fatalf("unexpected phase events: %#v", phases)
	}
	completeHTTPDependentPhase(ctx, PhaseFingerprint, complete)
	if len(phases) != 2 || phases[1].Phase != PhaseFingerprint || phases[1].Status != "skipped" || phases[1].Message != "upstream HTTP probe incomplete" {
		t.Fatalf("empty URL map must skip fingerprint instead of failing it: %#v", phases)
	}

	ctx.URLMap = map[string]URLEntity{"https://alive.example": {}}
	completeHTTPDependentPhase(ctx, PhaseDirBrute, complete)
	if len(phases) != 3 || phases[2].Phase != PhaseDirBrute || phases[2].Status != "end" {
		t.Fatalf("partial HTTP evidence must still finish directory/fingerprint work: %#v", phases)
	}

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ctx.Ctx = parent
	if _, err := completeHTTPProbePhase(ctx, context.Canceled); err == nil {
		t.Fatal("parent cancellation must still stop the pipeline")
	}
	if _, err := completeHTTPProbePhase(ctx, nil); err == nil {
		t.Fatal("parent cancellation racing with a completed probe must still stop the pipeline")
	}
}

func TestCompleteHTTPProbePhaseKeepsSuccessfulTargetsWhenAnotherBudgetExpires(t *testing.T) {
	var phases []PhaseEvent
	ctx := &ScanContext{
		Ctx:    context.Background(),
		URLMap: map[string]URLEntity{"https://alive.example": {}},
		PhaseObserver: func(event PhaseEvent) {
			phases = append(phases, event)
		},
	}

	complete, err := completeHTTPProbePhase(ctx, context.DeadlineExceeded)
	if err != nil {
		t.Fatalf("independent target deadline should not cancel HTTP coverage: %v", err)
	}
	if !complete {
		t.Fatal("usable HTTP responses must keep the HTTP stage complete")
	}
	if len(phases) != 1 || phases[0].Phase != PhaseHTTPProbe || phases[0].Status != "failed" || phases[0].Message != "target HTTP budget exhausted" {
		t.Fatalf("partial budget expiry must fail unprobed targets, not emit end: %#v", phases)
	}
}
