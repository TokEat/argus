package engine

import "runtime"

// MaxConcurrentTasks returns the number of scan tasks that can safely execute
// in parallel within a single agent process.
//
// Phase 1.0: Engine refactored to context-isolated execution.
// All pipeline state flows through ScanContext; globals are only used
// in CLI (legacy) mode via bindLegacyContext with its own mutex.
// Agent mode uses bindAgentContext which is fully lock-free.
func MaxConcurrentTasks() int {
	n := runtime.NumCPU()
	if n < 2 {
		return 2
	}
	if n > 16 {
		return 16
	}
	return n
}
