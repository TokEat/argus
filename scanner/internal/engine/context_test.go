package engine

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestNewScanContextUsesTaskResponseStoresAndResetKeepsThem(t *testing.T) {
	ctx, err := NewScanContext(Config{Targets: []string{"https://example.com"}, NoDirSearch: true, NoHostBind: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()
	if ctx.BodyHMap == nil || ctx.HeaderHMap == nil || ctx.BannerHMap == nil {
		t.Fatal("response stores were not initialized")
	}
	if err := ctx.BodyHMap.Set("body", []byte("response")); err != nil {
		t.Fatal(err)
	}
	if body, ok := ctx.BodyHMap.Get("body"); !ok || string(body) != "response" {
		t.Fatalf("response store Get = %q, %v", body, ok)
	}
	body := ctx.BodyHMap
	ctx.Reset()
	if ctx.BodyHMap != body {
		t.Fatal("Reset replaced the response stores")
	}

	risk, err := NewScanContext(Config{ExecutionMode: "risk_validation", Targets: []string{"192.0.2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	risk.Close()
}

func TestScanContextResponseStoresAreTaskPrivate(t *testing.T) {
	first, err := NewScanContext(Config{Targets: []string{"https://example.com"}, NoDirSearch: true, NoHostBind: true})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewScanContext(Config{Targets: []string{"https://example.com"}, NoDirSearch: true, NoHostBind: true})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	if err := first.BodyHMap.Set("body", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, ok := second.BodyHMap.Get("body"); ok {
		t.Fatal("response body leaked across ScanContext instances")
	}
}

func TestScanContextTryVisitHTTPURLConcurrent(t *testing.T) {
	ctx := &ScanContext{}
	const callers = 64

	var firstVisits atomic.Int32
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if ctx.TryVisitHTTPURL("https://example.test/") {
				firstVisits.Add(1)
			}
		}()
	}
	wait.Wait()

	if got := firstVisits.Load(); got != 1 {
		t.Fatalf("first visits = %d, want 1", got)
	}
}

func TestScanContextTryVisitHTTPURLIsolatedAndReset(t *testing.T) {
	first := &ScanContext{}
	second := &ScanContext{}

	start := make(chan struct{})
	results := make(chan bool, 2)
	var wait sync.WaitGroup
	for _, ctx := range []*ScanContext{first, second} {
		wait.Add(1)
		go func(ctx *ScanContext) {
			defer wait.Done()
			<-start
			results <- ctx.TryVisitHTTPURL("https://example.test/")
		}(ctx)
	}
	close(start)
	wait.Wait()
	close(results)
	for accepted := range results {
		if !accepted {
			t.Fatal("independent contexts did not each accept the same URL")
		}
	}
	if first.TryVisitHTTPURL("https://example.test/") {
		t.Fatal("first context accepted a duplicate URL")
	}
	if first.TryVisitHTTPURL("") {
		t.Fatal("context accepted an empty URL")
	}

	first.Reset()
	if !first.TryVisitHTTPURL("https://example.test/") {
		t.Fatal("Reset did not clear HTTP URL visits")
	}
}
