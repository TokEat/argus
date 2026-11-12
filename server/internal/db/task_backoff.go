package db

import (
	"math/rand"
	"time"
)

const (
	backoffBase        = 5 * time.Second
	backoffMultiplier  = 4
	backoffCap         = 5 * time.Minute
	backoffJitterDenom = 5 // ±20%
)

// BackoffForRetry returns the deterministic exponential backoff delay before a
// retry with the given 1-based retry count becomes eligible again:
// min(cap, base * multiplier^(count-1)). count<=1 yields the base delay
// (5s, 20s, 80s, ... capped at 5m).
func BackoffForRetry(retryCount int) time.Duration {
	if retryCount < 1 {
		retryCount = 1
	}
	delay := backoffBase
	for i := 1; i < retryCount; i++ {
		delay *= backoffMultiplier
		if delay >= backoffCap {
			return backoffCap
		}
	}
	return delay
}

// backoffRNG jitters backoff delays so that many simultaneously-failed tasks
// do not all become eligible again in lockstep (thundering herd).
var backoffRNG = rand.New(rand.NewSource(time.Now().UnixNano()))

// jitterBackoff applies ±20% jitter to a backoff delay.
func jitterBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	spread := int64(d) / backoffJitterDenom
	if spread <= 0 {
		return d
	}
	return d + time.Duration(backoffRNG.Int63n(2*spread+1)-spread)
}

// RetryEligibleAt returns the absolute time at which a retry with the given
// count becomes eligible: now plus the jittered backoff.
func RetryEligibleAt(retryCount int, now time.Time) time.Time {
	return now.Add(jitterBackoff(BackoffForRetry(retryCount)))
}
