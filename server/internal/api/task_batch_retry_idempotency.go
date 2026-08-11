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

const taskBatchRetryIdempotencyOperation = "retry_task_batch_v1"

var errInvalidTaskBatchRetryIdempotencyKey = errors.New("Idempotency-Key must contain 1-128 visible ASCII characters")
var errTaskBatchRetryIdempotencyRace = errors.New("task batch retry idempotency record was committed concurrently")

type canonicalTaskBatchRetryRequest struct {
	SchemaVersion string `json:"schema_version"`
	TenantID      string `json:"tenant_id"`
	ProjectID     string `json:"project_id"`
	RootTaskID    string `json:"root_task_id"`
	BatchID       string `json:"batch_id"`
	OperatorID    string `json:"operator_id"`
	Operation     string `json:"operation"`
	ForceRetest   bool   `json:"force_retest"`
}

func parseTaskBatchRetryIdempotencyKey(header http.Header) (string, bool, error) {
	values := header.Values("Idempotency-Key")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || !validTaskCreateIdempotencyKey(values[0]) {
		return "", true, errInvalidTaskBatchRetryIdempotencyKey
	}
	return values[0], true, nil
}

func buildTaskBatchRetryRequestHash(input canonicalTaskBatchRetryRequest) (string, error) {
	input.SchemaVersion = db.TaskBatchRetryIdempotencySchemaVersion
	input.Operation = taskBatchRetryIdempotencyOperation
	input.ForceRetest = true
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func taskBatchRetryConfigHash(config string) string {
	sum := sha256.Sum256([]byte(config))
	return hex.EncodeToString(sum[:])
}

// taskBatchRetryReplayDispatchPending only projects current delivery state of
// the frozen Attempt. Replays never make a queue call.
func taskBatchRetryReplayDispatchPending(tx *gorm.DB, record db.TaskBatchRetryIdempotency) (int, error) {
	var attempt db.SubTask
	if err := tx.Select("id", "status").Where("id = ? AND tenant_id = ? AND project_id = ? AND root_task_id = ? AND batch_id = ?", record.AttemptID, record.TenantID, record.ProjectID, record.RootTaskID, record.BatchID).First(&attempt).Error; err != nil {
		return 0, err
	}
	if strings.EqualFold(strings.TrimSpace(attempt.Status), subTaskStatusDispatching) {
		return 1, nil
	}
	return 0, nil
}

type taskBatchRetryResponseInput struct {
	AttemptID       string `json:"attempt_id"`
	Status          string `json:"status"`
	BeforeStatus    string `json:"-"`
	AfterStatus     string `json:"-"`
	RuleVersion     string `json:"rule_version"`
	AttemptNo       int    `json:"attempt_no"`
	ConfigVersion   int    `json:"config_version"`
	DispatchPending int    `json:"dispatch_pending"`
	Replayed        bool   `json:"replayed"`
}

func buildTaskBatchRetryResponse(input taskBatchRetryResponseInput) map[string]interface{} {
	return map[string]interface{}{
		"status": input.Status, "attempt_id": input.AttemptID, "attempt_no": input.AttemptNo,
		"config_version": input.ConfigVersion, "rule_version": input.RuleVersion,
		"dispatch_pending": input.DispatchPending, "replayed": input.Replayed,
	}
}

func requireFreshTaskBatchRetryIdempotency(result db.TaskBatchRetryIdempotencyRecordResult) error {
	if result.Replayed {
		return errTaskBatchRetryIdempotencyRace
	}
	return nil
}
