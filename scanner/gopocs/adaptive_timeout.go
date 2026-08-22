package gopocs

import (
	"net"
	"sync"
	"time"
)

const (
	// adaptiveAuthTimeoutFloor keeps barely-reachable devices usable: below
	// this window a slow link would be misread as an authentication failure.
	adaptiveAuthTimeoutFloor = 500 * time.Millisecond
	// adaptiveAuthTimeoutCeiling preserves the historical fixed dial budget so
	// one hung target cannot stall a credential attempt indefinitely.
	adaptiveAuthTimeoutCeiling = 6 * time.Second
)

// adaptiveAuthTimeout maps one measured TCP RTT onto an authentication dial
// timeout, clamped into [500ms, 6s]. Both bounds are hard limits: faster
// measurements keep a floor that tolerates jittery links and slower ones must
// never exceed the legacy fixed budget.
func adaptiveAuthTimeout(rtt time.Duration) time.Duration {
	timeout := 3 * rtt
	if timeout < adaptiveAuthTimeoutFloor {
		return adaptiveAuthTimeoutFloor
	}
	if timeout > adaptiveAuthTimeoutCeiling {
		return adaptiveAuthTimeoutCeiling
	}
	return timeout
}

// adaptiveAuthTimeoutCache memoizes one resolved timeout per "host:port".
// GoPoc dispatches plugins concurrently against shared targets, so lookups
// must be race-free; sync.Map fits this write-once-per-target pattern.
var adaptiveAuthTimeoutCache sync.Map

// authTimeoutFor measures the TCP RTT to host:port exactly once per process
// and returns the clamped authentication timeout reused by every later
// credential attempt against that target. The probe socket is closed
// immediately after the handshake; a failed probe falls back to the ceiling
// instead of disabling the timeout.
func authTimeoutFor(host, port string) time.Duration {
	key := host + ":" + port
	if cached, ok := adaptiveAuthTimeoutCache.Load(key); ok {
		if timeout, ok := cached.(time.Duration); ok && timeout > 0 {
			return timeout
		}
	}
	timeout := adaptiveAuthTimeoutCeiling
	if rtt, ok := probeTargetRTT(key); ok {
		timeout = adaptiveAuthTimeout(rtt)
	}
	adaptiveAuthTimeoutCache.Store(key, timeout)
	return timeout
}

// probeTargetRTT times a single TCP connect to addr and closes it at once so
// brute-force targets only ever see one extra probe connection.
func probeTargetRTT(addr string) (time.Duration, bool) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, adaptiveAuthTimeoutCeiling)
	if err != nil {
		return 0, false
	}
	rtt := time.Since(start)
	_ = conn.Close()
	return rtt, true
}
