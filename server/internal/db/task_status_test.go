package db

import "testing"

func TestCanonicalTaskStateLegacyAliases(t *testing.T) {
	tests := map[string]TaskState{
		"Pending":       TaskStateQueued,
		"Queued":        TaskStateQueued,
		"PartialDone":   TaskStatePartial,
		"FINISHED":      TaskStateCompleted,
		"DONE":          TaskStateCompleted,
		"CancelPending": TaskStateStopping,
		"Cancelled":     TaskStateStopped,
		"canceled":      TaskStateStopped,
		"unknown-value": TaskStateUnknown,
	}
	for input, want := range tests {
		if got := CanonicalTaskState(input); got != want {
			t.Fatalf("CanonicalTaskState(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTaskStatusBehaviorMatrix(t *testing.T) {
	if !CanPauseTaskStatus("PartialDone") || !CanStopTaskStatus("Running") {
		t.Fatal("active legacy task states must remain manageable")
	}
	if !CanResumeTaskStatus("Paused") {
		t.Fatal("paused task must be resumable")
	}
	if !CanStopTaskStatus("Paused") {
		t.Fatal("paused task must remain stoppable")
	}
	for _, status := range []string{"Failed", "Timeout", "Cancelled", "PartialDone"} {
		if !CanExplicitRetryTaskStatus(status) {
			t.Fatalf("%s must expose explicit retry", status)
		}
	}
	if CanExplicitRetryTaskStatus("FINISHED") || CanExplicitRetryTaskStatus("Running") {
		t.Fatal("completed and active tasks must not expose task-level retry")
	}
	for _, status := range []string{"FINISHED", "Failed", "Timeout", "Cancelled"} {
		if !IsTerminalTaskStatus(status) {
			t.Fatalf("%s must be terminal", status)
		}
		if CanPauseTaskStatus(status) || CanStopTaskStatus(status) {
			t.Fatalf("%s must not expose active task actions", status)
		}
	}
}

func TestCanonicalAttemptStateLegacyAliases(t *testing.T) {
	tests := map[string]AttemptState{
		"Pending":       AttemptStateQueued,
		"Dispatching":   AttemptStateDispatching,
		"Recovered":     AttemptStateRecovered,
		"DONE":          AttemptStateCompleted,
		"CancelPending": AttemptStateStopping,
		"Cancelled":     AttemptStateStopped,
	}
	for input, want := range tests {
		if got := CanonicalAttemptState(input); got != want {
			t.Fatalf("CanonicalAttemptState(%q) = %q, want %q", input, got, want)
		}
	}
}
