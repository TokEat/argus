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
	"gorm.io/gorm"
)

const taskCreateIdempotencyOperation = "create_task_v1"

var errInvalidTaskCreateIdempotencyKey = errors.New("Idempotency-Key must contain 1-128 visible ASCII characters")
var errTaskCreateQueueUnavailable = errors.New("task queue is unavailable")

type canonicalTaskCreateRequest struct {
	SchemaVersion      string          `json:"schema_version"`
	TenantID           string          `json:"tenant_id"`
	ProjectID          string          `json:"project_id"`
	OperatorID         string          `json:"operator_id"`
	Operation          string          `json:"operation"`
	Name               string          `json:"name"`
	Targets            []string        `json:"targets"`
	SkippedTargets     []invalidTarget `json:"skipped_targets"`
	Config             string          `json:"config"`
	TargetMode         string          `json:"target_mode"`
	Priority           int             `json:"priority"`
	TimeoutSec         int             `json:"timeout_sec"`
	AgentSelector      string          `json:"agent_selector"`
	AgentSelectorRules string          `json:"agent_selector_rules"`
	SkipUnsupported    bool            `json:"skip_unsupported"`
	TargetSource       string          `json:"target_source"`
}

type taskCreateResponseInput struct {
	TaskID            string
	ConfigVersion     int
	TargetSummary     taskTargetSummary
	Dispatched        int
	DispatchPending   int
	Profile           batchProfile
	TargetSource      string
	ProjectScopeAdded int
	ProjectSeedsAdded int
	SkippedTargets    []invalidTarget
	Replayed          bool
}

func parseTaskCreateIdempotencyKey(header http.Header) (string, bool, error) {
	values := header.Values("Idempotency-Key")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || !validTaskCreateIdempotencyKey(values[0]) {
		return "", true, errInvalidTaskCreateIdempotencyKey
	}
	return values[0], true, nil
}

func validTaskCreateIdempotencyKey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func buildTaskCreateRequestHash(input canonicalTaskCreateRequest) (string, error) {
	input.SchemaVersion = db.TaskCreationIdempotencySchemaVersion
	input.Operation = taskCreateIdempotencyOperation
	input.Targets = append([]string(nil), input.Targets...)
	sort.Strings(input.Targets)
	input.SkippedTargets = canonicalTaskCreateSkippedTargets(input.SkippedTargets)
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalTaskCreateSkippedTargets(items []invalidTarget) []invalidTarget {
	canonical := append([]invalidTarget(nil), items...)
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Target == canonical[j].Target {
			return canonical[i].Reason < canonical[j].Reason
		}
		return canonical[i].Target < canonical[j].Target
	})
	return canonical
}

func canonicalTaskCreateSelectorRules(rules db.AgentSelectorRules) string {
	canonicalize := func(values db.SelectorValues) db.SelectorValues {
		if len(values) == 0 {
			return nil
		}
		result := make(db.SelectorValues, len(values))
		for key, entries := range values {
			items := append([]string(nil), entries...)
			sort.Strings(items)
			deduped := items[:0]
			for _, item := range items {
				if len(deduped) == 0 || deduped[len(deduped)-1] != item {
					deduped = append(deduped, item)
				}
			}
			result[key] = deduped
		}
		return result
	}
	return db.SelectorRulesToJSON(db.AgentSelectorRules{
		Match:    canonicalize(rules.Match),
		NotMatch: canonicalize(rules.NotMatch),
	})
}

func decodeTaskCreationAttemptIDs(record db.TaskCreationIdempotency) ([]string, error) {
	var attemptIDs []string
	if err := json.Unmarshal([]byte(record.AttemptIDs), &attemptIDs); err != nil {
		return nil, err
	}
	return attemptIDs, nil
}

func taskCreationReplayDispatchCounts(tx *gorm.DB, record db.TaskCreationIdempotency) (int, int, error) {
	attemptIDs, err := decodeTaskCreationAttemptIDs(record)
	if err != nil {
		return 0, 0, err
	}
	if len(attemptIDs) == 0 {
		return 0, 0, nil
	}
	var attempts []db.SubTask
	if err := tx.Select("id", "status").
		Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND id IN ?", record.TenantID, record.ProjectID, record.RootTaskID, attemptIDs).
		Find(&attempts).Error; err != nil {
		return 0, 0, err
	}
	if len(attempts) != len(attemptIDs) {
		return 0, 0, errors.New("task creation idempotency attempts are incomplete")
	}
	pending := 0
	for _, attempt := range attempts {
		if strings.EqualFold(strings.TrimSpace(attempt.Status), subTaskStatusDispatching) {
			pending++
		}
	}
	return len(attempts) - pending, pending, nil
}

// taskCreationReplayScanSummary rebuilds the immutable creation summary from
// the initial attempts recorded by the idempotency ledger. Task append and
// config revision operations may update RootTask aggregates later, so they are
// intentionally not used to answer a creation replay.
func taskCreationReplayScanSummary(tx *gorm.DB, record db.TaskCreationIdempotency) (taskTargetSummary, batchProfile, error) {
	emptyProfile := batchProfile{BatchesByType: map[string]int{}, BatchSize: map[string]int{}}
	attemptIDs, err := decodeTaskCreationAttemptIDs(record)
	if err != nil {
		return taskTargetSummary{}, emptyProfile, err
	}
	if len(attemptIDs) == 0 {
		return taskTargetSummary{}, emptyProfile, errors.New("task creation idempotency attempts are empty")
	}

	var attempts []db.SubTask
	if err := tx.Select("id", "batch_id").
		Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND id IN ?", record.TenantID, record.ProjectID, record.RootTaskID, attemptIDs).
		Find(&attempts).Error; err != nil {
		return taskTargetSummary{}, emptyProfile, err
	}
	if len(attempts) != len(attemptIDs) {
		return taskTargetSummary{}, emptyProfile, errors.New("task creation idempotency attempts are incomplete")
	}

	batchIDs := make([]string, 0, len(attempts))
	seenBatchIDs := make(map[string]struct{}, len(attempts))
	for _, attempt := range attempts {
		if strings.TrimSpace(attempt.BatchID) == "" {
			return taskTargetSummary{}, emptyProfile, errors.New("task creation idempotency attempt batch is missing")
		}
		if _, exists := seenBatchIDs[attempt.BatchID]; exists {
			continue
		}
		seenBatchIDs[attempt.BatchID] = struct{}{}
		batchIDs = append(batchIDs, attempt.BatchID)
	}

	var batches []db.TaskBatch
	if err := tx.Select("id", "sequence", "target_type", "targets", "target_count").
		Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND id IN ?", record.TenantID, record.ProjectID, record.RootTaskID, batchIDs).
		Order("sequence ASC").
		Find(&batches).Error; err != nil {
		return taskTargetSummary{}, emptyProfile, err
	}
	if len(batches) != len(batchIDs) {
		return taskTargetSummary{}, emptyProfile, errors.New("task creation idempotency batches are incomplete")
	}

	var revision db.TaskConfigRevision
	if err := tx.Select("config").
		Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND version = ?", record.TenantID, record.ProjectID, record.RootTaskID, 1).
		First(&revision).Error; err != nil {
		return taskTargetSummary{}, emptyProfile, err
	}

	profile := batchProfile{
		TotalBatches:  len(batches),
		BatchesByType: make(map[string]int),
		BatchSize:     make(map[string]int),
	}
	targets := make([]string, 0)
	for _, batch := range batches {
		var batchTargets []string
		if err := json.Unmarshal([]byte(batch.Targets), &batchTargets); err != nil {
			return taskTargetSummary{}, emptyProfile, err
		}
		if len(batchTargets) != batch.TargetCount {
			return taskTargetSummary{}, emptyProfile, errors.New("task creation idempotency batch target count is inconsistent")
		}
		targets = append(targets, batchTargets...)
		profile.BatchesByType[batch.TargetType]++
		if _, exists := profile.BatchSize[batch.TargetType]; !exists {
			profile.BatchSize[batch.TargetType] = batchSizeForTargetType(batch.TargetType)
		}
	}
	profile.TotalTargets = len(targets)

	mode := detectTargetModeFromStoredConfig(revision.Config)
	_, invalid, summary := classifyTargets(targets, mode)
	if len(invalid) > 0 || summary.Total != len(targets) {
		return taskTargetSummary{}, emptyProfile, errors.New("task creation idempotency targets are inconsistent")
	}
	return summary, profile, nil
}

func buildTaskCreateResponse(input taskCreateResponseInput) map[string]interface{} {
	response := map[string]interface{}{
		"status":           "task_created",
		"task_id":          input.TaskID,
		"config_version":   input.ConfigVersion,
		"target_summary":   input.TargetSummary,
		"dispatched":       input.Dispatched,
		"dispatch_pending": input.DispatchPending,
		"batch_profile":    input.Profile,
		"batch_summary": map[string]interface{}{
			"total_targets": input.Profile.TotalTargets,
			"total_batches": input.Profile.TotalBatches,
		},
		"profile":             "external-map",
		"target_source":       input.TargetSource,
		"project_scope_added": input.ProjectScopeAdded,
		"project_seeds_added": input.ProjectSeedsAdded,
		"replayed":            input.Replayed,
	}
	if len(input.SkippedTargets) > 0 {
		response["skipped_targets"] = input.SkippedTargets
	}
	return response
}
