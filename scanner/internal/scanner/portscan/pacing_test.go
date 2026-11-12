package portscan

import (
	"testing"
	"time"
)

func TestPacerBook(t *testing.T) {
	p := newScanPacer(100 * time.Millisecond)

	if wait := p.book("192.0.2.1"); wait > 5*time.Millisecond {
		t.Fatalf("first booking should not wait, got %s", wait)
	}
	second := p.book("192.0.2.1")
	if second < 95*time.Millisecond || second > 100*time.Millisecond {
		t.Fatalf("second booking wait = %s, want ~100ms", second)
	}
	third := p.book("192.0.2.1")
	if third < 195*time.Millisecond {
		t.Fatalf("third booking wait = %s, want ~200ms", third)
	}
	if wait := p.book("192.0.2.2"); wait > 5*time.Millisecond {
		t.Fatalf("different target must not wait, got %s", wait)
	}

	fresh := newScanPacer(100 * time.Millisecond)
	fresh.book("192.0.2.1")
	time.Sleep(120 * time.Millisecond)
	if wait := fresh.book("192.0.2.1"); wait > 5*time.Millisecond {
		t.Fatalf("expired slot should not wait, got %s", wait)
	}
}

func TestPacedSYNRate(t *testing.T) {
	tests := []struct {
		name          string
		targetCount   int
		intervalMillis int
		capRate       int
		want          int
	}{
		{"aggregate rate", 100, 500, 10000, 200},
		{"cap applied", 10000, 50, 100, 100},
		{"single target", 1, 5000, 10000, 1},
		{"no cap", 5, 500, 0, 10},
		{"no targets", 0, 500, 10000, 10000},
		{"no interval", 10, 0, 10000, 10000},
	}
	for _, test := range tests {
		if got := pacedSYNRate(test.targetCount, test.intervalMillis, test.capRate); got != test.want {
			t.Fatalf("%s: pacedSYNRate(%d, %d, %d) = %d, want %d",
				test.name, test.targetCount, test.intervalMillis, test.capRate, got, test.want)
		}
	}
}

func TestScanTCPScatterPacesSameTarget(t *testing.T) {
	// Closed localhost ports fail fast; the pacer must still space the dials.
	ports := "39681,39682,39683"
	const interval = 100 * time.Millisecond

	start := time.Now()
	ScanTCP([]string{"127.0.0.1"}, ports, 1, 3, 300, true, true, interval, nil, nil)
	scattered := time.Since(start)
	if scattered < 2*interval-20*time.Millisecond {
		t.Fatalf("scattered scan took %s, want at least ~%s for 3 paced probes", scattered, 2*interval)
	}

	start = time.Now()
	ScanTCP([]string{"127.0.0.1"}, ports, 1, 3, 300, true, false, interval, nil, nil)
	plain := time.Since(start)
	if plain >= interval {
		t.Fatalf("unscattered scan took %s, want well under %s", plain, interval)
	}
}
