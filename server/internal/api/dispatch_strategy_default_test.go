package api

import (
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

// init pins the legacy agent-claim pull model for the api test suite. The
// production default is controller_push, but the existing api tests exercise
// the pull model (shared-queue dispatch, pending recovery) and set no
// dispatch_strategy on their fixtures. Tests that cover controller-push
// behavior override this locally and restore it in cleanup. Tests in this
// package run sequentially (no t.Parallel), so the package-global default is
// safe to pin here.
func init() {
	scanpolicy.SetDefaultDispatchStrategy(scanpolicy.DispatchStrategyAgentClaim)
}
