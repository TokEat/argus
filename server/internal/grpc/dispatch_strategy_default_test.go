package grpc

import (
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

// init pins the legacy agent-claim pull model for the grpc test suite. The
// production default is controller_push, but these tests exercise the
// retry/split/replan/dump enqueue paths against the shared-queue pull model
// and set no dispatch_strategy on their fixtures. Tests covering the
// controller-push behavior override this locally and restore it in cleanup.
// Tests in this package run sequentially (no t.Parallel), so pinning the
// package-global default here is safe.
func init() {
	scanpolicy.SetDefaultDispatchStrategy(scanpolicy.DispatchStrategyAgentClaim)
}
