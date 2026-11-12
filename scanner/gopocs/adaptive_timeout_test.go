package gopocs

import (
	"net"
	"testing"
	"time"
)

func TestAdaptiveAuthTimeoutClampsToHardBounds(t *testing.T) {
	cases := []struct {
		rtt  time.Duration
		want time.Duration
	}{
		{rtt: -time.Millisecond, want: adaptiveAuthTimeoutFloor},
		{rtt: 0, want: adaptiveAuthTimeoutFloor},
		{rtt: time.Millisecond, want: adaptiveAuthTimeoutFloor},
		{rtt: 200 * time.Millisecond, want: 600 * time.Millisecond},
		{rtt: adaptiveAuthTimeoutCeiling / 3, want: adaptiveAuthTimeoutCeiling},
		{rtt: 10 * time.Second, want: adaptiveAuthTimeoutCeiling},
	}
	for _, tc := range cases {
		if got := adaptiveAuthTimeout(tc.rtt); got != tc.want {
			t.Fatalf("adaptiveAuthTimeout(%v) = %v, want %v", tc.rtt, got, tc.want)
		}
	}
}

func TestAuthTimeoutForProbesTargetOnceAndCaches(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	first := authTimeoutFor(host, port)
	if first != adaptiveAuthTimeoutFloor {
		t.Fatalf("loopback timeout = %v, want floor %v", first, adaptiveAuthTimeoutFloor)
	}
	cached, ok := adaptiveAuthTimeoutCache.Load(host + ":" + port)
	if !ok || cached.(time.Duration) != first {
		t.Fatalf("cache = %#v, want %v", cached, first)
	}

	// Any second probe would now be refused and fall back to the ceiling, so
	// an unchanged result proves the second lookup reused the cache.
	listener.Close()
	if second := authTimeoutFor(host, port); second != first {
		t.Fatalf("second lookup = %v, want cached %v", second, first)
	}
}

func TestAuthTimeoutForFallsBackToCeilingWhenProbeFails(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()

	if got := authTimeoutFor(host, port); got != adaptiveAuthTimeoutCeiling {
		t.Fatalf("refused target timeout = %v, want ceiling %v", got, adaptiveAuthTimeoutCeiling)
	}
}
