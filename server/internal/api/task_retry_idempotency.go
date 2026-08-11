package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

const taskRetryIdempotencyOperation = "retry_task_v1"

var errInvalidTaskRetryIdempotencyKey = errors.New("Idempotency-Key must contain 1-128 visible ASCII characters")
var errTaskRetryQueueUnavailable = errors.New("task queue not initialized")

// canonicalTaskRetryRequest binds a retry to its operator and task. Retries
// are force-retest operations by definition; recording that explicitly keeps
// the hash future-proof if this endpoint later accepts optional controls.
type canonicalTaskRetryRequest struct {
	SchemaVersion string `json:"schema_version"`
	TenantID      string `json:"tenant_id"`
	ProjectID     string `json:"project_id"`
	RootTaskID    string `json:"root_task_id"`
	OperatorID    string `json:"operator_id"`
	Operation     string `json:"operation"`
	ForceRetest   bool   `json:"force_retest"`
}

func parseTaskRetryIdempotencyKey(header http.Header) (string, bool, error) {
	values := header.Values("Idempotency-Key")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || !validTaskCreateIdempotencyKey(values[0]) {
		return "", true, errInvalidTaskRetryIdempotencyKey
	}
	return values[0], true, nil
}

func buildTaskRetryRequestHash(input canonicalTaskRetryRequest) (string, error) {
	input.SchemaVersion = db.TaskRetryIdempotencySchemaVersion
	input.Operation = taskRetryIdempotencyOperation
	input.ForceRetest = true
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func decodeTaskRetryAttemptIDs(record db.TaskRetryIdempotency) ([]string, error) {
	var attemptIDs []string
	if err := json.Unmarshal([]byte(record.AttemptIDs), &attemptIDs); err != nil {
		return nil, err
	}
	return attemptIDs, nil
}

// taskRetryReplayDispatchPending projects the current delivery state of the
// immutable Attempts from the first retry. It never queues work during a
// replay, so this value may evolve while the business outcome remains fixed.
func taskRetryReplayDispatchPending(tx *gorm.DB, record db.TaskRetryIdempotency) (int, error) {
	attemptIDs, err := decodeTaskRetryAttemptIDs(record)
	if err != nil {
		return 0, err
	}
	if len(attemptIDs) == 0 {
		return 0, nil
	}
	var attempts []db.SubTask
	if err := tx.Select("id", "status").
		Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND id IN ?", record.TenantID, record.ProjectID, record.RootTaskID, attemptIDs).
		Find(&attempts).Error; err != nil {
		return 0, err
	}
	if len(attempts) != len(attemptIDs) {
		return 0, errors.New("task retry idempotency attempts are incomplete")
	}
	pending := 0
	for _, attempt := range attempts {
		if strings.EqualFold(strings.TrimSpace(attempt.Status), subTaskStatusDispatching) {
			pending++
		}
	}
	return pending, nil
}

type taskRetryResponseInput struct {
	Status, BeforeStatus, AfterStatus                                string
	RetriedBatches, CompletedSkipped, PausedSkipped, DispatchPending int
	Replayed                                                         bool
}

func buildTaskRetryResponse(input taskRetryResponseInput) map[string]interface{} {
	return map[string]interface{}{
		"status": input.Status, "retried_batches": input.RetriedBatches,
		"completed_skipped": input.CompletedSkipped, "paused_skipped": input.PausedSkipped,
		"dispatch_pending": input.DispatchPending, "replayed": input.Replayed,
	}
}
