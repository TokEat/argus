package db

import "strings"

// TaskState is the canonical product-level state for a RootTask. Persisted
// records may still contain legacy spellings; CanonicalTaskState is the only
// supported way to interpret them.
type TaskState string

const (
	TaskStateUnknown   TaskState = "UNKNOWN"
	TaskStateCreated   TaskState = "CREATED"
	TaskStateQueued    TaskState = "QUEUED"
	TaskStateRunning   TaskState = "RUNNING"
	TaskStatePartial   TaskState = "PARTIAL"
	TaskStatePausing   TaskState = "PAUSING"
	TaskStatePaused    TaskState = "PAUSED"
	TaskStateStopping  TaskState = "STOPPING"
	TaskStateStopped   TaskState = "STOPPED"
	TaskStateCompleted TaskState = "COMPLETED"
	TaskStateFailed    TaskState = "FAILED"
	TaskStateTimeout   TaskState = "TIMEOUT"
)

// AttemptState is the canonical execution state for a SubTask/Attempt.
type AttemptState string

type BatchControlState string

const (
	AttemptStateUnknown     AttemptState = "UNKNOWN"
	AttemptStateQueued      AttemptState = "QUEUED"
	AttemptStateDispatching AttemptState = "DISPATCHING"
	AttemptStateRunning     AttemptState = "RUNNING"
	AttemptStateRecovered   AttemptState = "RECOVERED"
	AttemptStatePaused      AttemptState = "PAUSED"
	AttemptStateStopping    AttemptState = "STOPPING"
	AttemptStateStopped     AttemptState = "STOPPED"
	AttemptStateCompleted   AttemptState = "COMPLETED"
	AttemptStateFailed      AttemptState = "FAILED"
	AttemptStateTimeout     AttemptState = "TIMEOUT"
)

const (
	BatchControlActive   BatchControlState = "active"
	BatchControlPaused   BatchControlState = "paused"
	BatchControlStopping BatchControlState = "stopping"
	BatchControlStopped  BatchControlState = "stopped"
)

func CanonicalBatchControlState(state string) BatchControlState {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "", string(BatchControlActive):
		return BatchControlActive
	case string(BatchControlPaused):
		return BatchControlPaused
	case string(BatchControlStopping):
		return BatchControlStopping
	case string(BatchControlStopped):
		return BatchControlStopped
	default:
		return BatchControlState(strings.ToLower(strings.TrimSpace(state)))
	}
}

func IsTerminalAttemptStatus(status string) bool {
	switch CanonicalAttemptState(status) {
	case AttemptStateStopped, AttemptStateCompleted, AttemptStateFailed, AttemptStateTimeout:
		return true
	default:
		return false
	}
}

func normalizedStatus(status string) string {
	return strings.ToUpper(strings.TrimSpace(status))
}

// NormalizeSubTaskStatus remains for compatibility with existing call sites
// that compare persisted spellings. New lifecycle decisions should use
// CanonicalTaskState or CanonicalAttemptState instead.
func NormalizeSubTaskStatus(status string) string {
	return normalizedStatus(status)
}

func CanonicalTaskState(status string) TaskState {
	switch normalizedStatus(status) {
	case "CREATED":
		return TaskStateCreated
	case "QUEUED", "PENDING":
		return TaskStateQueued
	case "RUNNING":
		return TaskStateRunning
	case "PARTIAL", "PARTIALDONE":
		return TaskStatePartial
	case "PAUSING":
		return TaskStatePausing
	case "PAUSED":
		return TaskStatePaused
	case "STOPPING", "CANCELPENDING":
		return TaskStateStopping
	case "STOPPED", "CANCELLED", "CANCELED":
		return TaskStateStopped
	case "COMPLETED", "FINISHED", "DONE", "SUCCESS", "SUCCEEDED":
		return TaskStateCompleted
	case "FAILED":
		return TaskStateFailed
	case "TIMEOUT":
		return TaskStateTimeout
	default:
		return TaskStateUnknown
	}
}

func CanonicalAttemptState(status string) AttemptState {
	switch normalizedStatus(status) {
	case "QUEUED", "PENDING":
		return AttemptStateQueued
	case "DISPATCHING":
		return AttemptStateDispatching
	case "RUNNING":
		return AttemptStateRunning
	case "RECOVERED":
		return AttemptStateRecovered
	case "PAUSED":
		return AttemptStatePaused
	case "STOPPING", "CANCELPENDING":
		return AttemptStateStopping
	case "STOPPED", "CANCELLED", "CANCELED":
		return AttemptStateStopped
	case "COMPLETED", "FINISHED", "DONE", "SUCCESS", "SUCCEEDED":
		return AttemptStateCompleted
	case "FAILED":
		return AttemptStateFailed
	case "TIMEOUT":
		return AttemptStateTimeout
	default:
		return AttemptStateUnknown
	}
}

func CanPauseTaskStatus(status string) bool {
	switch CanonicalTaskState(status) {
	case TaskStateQueued, TaskStateRunning, TaskStatePartial:
		return true
	default:
		return false
	}
}

func CanResumeTaskStatus(status string) bool {
	return CanonicalTaskState(status) == TaskStatePaused
}

func CanStopTaskStatus(status string) bool {
	switch CanonicalTaskState(status) {
	case TaskStateQueued, TaskStateRunning, TaskStatePartial, TaskStatePaused:
		return true
	default:
		return false
	}
}

// CanExplicitRetryTaskStatus is intentionally separate from
// CanRetryTaskStatus. Automatic recovery is only allowed while a task is
// active; an operator retry starts new Attempts after an unsuccessful terminal
// task state and deliberately bypasses historical coverage reuse.
func CanExplicitRetryTaskStatus(status string) bool {
	switch CanonicalTaskState(status) {
	case TaskStatePartial, TaskStateStopped, TaskStateFailed, TaskStateTimeout:
		return true
	default:
		return false
	}
}

func CanRetryTaskStatus(status string) bool {
	switch CanonicalTaskState(status) {
	case TaskStateQueued, TaskStateRunning, TaskStatePartial:
		return true
	default:
		return false
	}
}

func IsTerminalTaskStatus(status string) bool {
	switch CanonicalTaskState(status) {
	case TaskStateStopped, TaskStateCompleted, TaskStateFailed, TaskStateTimeout:
		return true
	default:
		return false
	}
}

func IsStoppingAttemptStatus(status string) bool {
	return CanonicalAttemptState(status) == AttemptStateStopping
}
