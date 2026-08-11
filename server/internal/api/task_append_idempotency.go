package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const taskAppendIdempotencyOperation = "append_targets_v1"

var errInvalidTaskAppendIdempotencyKey = errors.New("Idempotency-Key must contain 1-128 visible ASCII characters")
var errTaskAppendQueueUnavailable = errors.New("task queue not initialized")

// canonicalTaskAppendRequest deliberately binds the HTTP target projection,
// rather than a mutable task configuration. A retry must still find its first
// committed append after a later configuration revision.
type canonicalTaskAppendRequest struct {
	SchemaVersion string   `json:"schema_version"`
	TenantID      string   `json:"tenant_id"`
	ProjectID     string   `json:"project_id"`
	RootTaskID    string   `json:"root_task_id"`
	OperatorID    string   `json:"operator_id"`
	Operation     string   `json:"operation"`
	Targets       []string `json:"targets"`
}

func parseTaskAppendIdempotencyKey(header http.Header) (string, bool, error) {
	values := header.Values("Idempotency-Key")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || !validTaskCreateIdempotencyKey(values[0]) {
		return "", true, errInvalidTaskAppendIdempotencyKey
	}
	return values[0], true, nil
}

func buildTaskAppendRequestHash(input canonicalTaskAppendRequest) (string, error) {
	input.SchemaVersion = db.TaskAppendIdempotencySchemaVersion
	input.Operation = taskAppendIdempotencyOperation
	seen := make(map[string]struct{}, len(input.Targets))
	targets := make([]string, 0, len(input.Targets))
	for _, target := range input.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	input.Targets = targets
	sort.Strings(input.Targets)
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func taskAppendReplayDispatchCounts(tx *gorm.DB, record db.TaskAppendIdempotency) (int, int, error) {
	var attemptIDs []string
	if err := json.Unmarshal([]byte(record.AttemptIDs), &attemptIDs); err != nil {
		return 0, 0, err
	}
	if len(attemptIDs) == 0 {
		return 0, 0, nil
	}
	var attempts []db.SubTask
	if err := tx.Select("id", "status").Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND id IN ?", record.TenantID, record.ProjectID, record.RootTaskID, attemptIDs).Find(&attempts).Error; err != nil {
		return 0, 0, err
	}
	if len(attempts) != len(attemptIDs) {
		return 0, 0, errors.New("task append idempotency attempts are incomplete")
	}
	dispatched, pending := 0, 0
	for _, attempt := range attempts {
		status := strings.TrimSpace(attempt.Status)
		if strings.EqualFold(status, subTaskStatusDispatching) {
			pending++
			continue
		}
		if strings.EqualFold(status, "paused") {
			continue
		}
		dispatched++
	}
	return dispatched, pending, nil
}

func taskAppendReplayScanSummary(tx *gorm.DB, record db.TaskAppendIdempotency) (taskTargetSummary, batchProfile, error) {
	empty := batchProfile{BatchesByType: map[string]int{}, BatchSize: map[string]int{}}
	var batchIDs []string
	if err := json.Unmarshal([]byte(record.BatchIDs), &batchIDs); err != nil {
		return taskTargetSummary{}, empty, err
	}
	if len(batchIDs) == 0 {
		return taskTargetSummary{}, empty, nil
	}
	var batches []db.TaskBatch
	if err := tx.Select("id", "sequence", "target_type", "targets", "target_count").Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND id IN ?", record.TenantID, record.ProjectID, record.RootTaskID, batchIDs).Order("sequence ASC").Find(&batches).Error; err != nil {
		return taskTargetSummary{}, empty, err
	}
	if len(batches) != len(batchIDs) {
		return taskTargetSummary{}, empty, errors.New("task append idempotency batches are incomplete")
	}
	var revision db.TaskConfigRevision
	if err := tx.Select("config").Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND version = ?", record.TenantID, record.ProjectID, record.RootTaskID, record.ConfigVersion).First(&revision).Error; err != nil {
		return taskTargetSummary{}, empty, err
	}
	profile := batchProfile{TotalBatches: len(batches), BatchesByType: map[string]int{}, BatchSize: map[string]int{}}
	targets := make([]string, 0, record.NewTargets)
	for _, batch := range batches {
		var batchTargets []string
		if err := json.Unmarshal([]byte(batch.Targets), &batchTargets); err != nil || len(batchTargets) != batch.TargetCount {
			return taskTargetSummary{}, empty, errors.New("task append idempotency batch targets are inconsistent")
		}
		targets = append(targets, batchTargets...)
		profile.BatchesByType[batch.TargetType]++
		if _, ok := profile.BatchSize[batch.TargetType]; !ok {
			profile.BatchSize[batch.TargetType] = batchSizeForTargetType(batch.TargetType)
		}
	}
	if len(targets) != record.NewTargets {
		return taskTargetSummary{}, empty, errors.New("task append idempotency target count is inconsistent")
	}
	profile.TotalTargets = len(targets)
	_, invalid, summary := classifyTargets(targets, detectTargetModeFromStoredConfig(revision.Config))
	if len(invalid) != 0 || summary.Total != len(targets) {
		return taskTargetSummary{}, empty, errors.New("task append idempotency target summary is inconsistent")
	}
	return summary, profile, nil
}

func buildTaskAppendResponse(result taskAppendResponseInput) map[string]interface{} {
	response := map[string]interface{}{
		"status": result.Outcome, "new_subtasks": result.NewBatches, "new_batches": result.NewBatches,
		"new_targets": result.NewTargets, "duplicate_targets": result.DuplicateTargets,
		"config_version": result.ConfigVersion, "total_chunks": result.TotalChunks, "total_targets": result.TotalTargets,
		"project_scope_added": result.ProjectScopeAdded, "project_seeds_added": result.ProjectSeedsAdded,
		"dispatched": result.Dispatched, "dispatch_pending": result.DispatchPending, "replayed": result.Replayed,
	}
	if result.Outcome == "appended" {
		response["target_summary"] = result.TargetSummary
		response["batch_profile"] = result.Profile
		response["batch_summary"] = gin.H{"total_targets": result.NewTargets, "total_batches": result.NewBatches}
	}
	return response
}

type taskAppendResponseInput struct {
	Outcome                                                                            string
	NewBatches, NewTargets, DuplicateTargets, ConfigVersion, TotalChunks, TotalTargets int
	ProjectScopeAdded, ProjectSeedsAdded, Dispatched, DispatchPending                  int
	TargetSummary                                                                      taskTargetSummary
	Profile                                                                            batchProfile
	Replayed                                                                           bool
}
