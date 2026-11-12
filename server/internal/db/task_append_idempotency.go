package db

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const TaskAppendIdempotencySchemaVersion = "argus.task-append-idempotency/v1"

// TaskAppendIdempotency is an immutable, task-scoped record of a completed
// append operation. It stores only request/key hashes and safe outcome
// metadata; it is not an authorization grant or a dispatch token.
type TaskAppendIdempotency struct {
	ID                 uint      `gorm:"primaryKey;autoIncrement;uniqueIndex:idx_tai_scope_id,priority:4"`
	SchemaVersion      string    `gorm:"not null;size:64"`
	TenantID           string    `gorm:"not null;default:'default';uniqueIndex:idx_tai_scope_id,priority:1;uniqueIndex:idx_tai_idempotency,priority:1;index:idx_tai_task_created,priority:1;index:idx_tai_operator_created,priority:1"`
	ProjectID          string    `gorm:"not null;uniqueIndex:idx_tai_scope_id,priority:2;uniqueIndex:idx_tai_idempotency,priority:2;index:idx_tai_task_created,priority:2;index:idx_tai_operator_created,priority:2"`
	RootTaskID         string    `gorm:"not null;uniqueIndex:idx_tai_scope_id,priority:3;uniqueIndex:idx_tai_idempotency,priority:3;index:idx_tai_task_created,priority:3"`
	OperatorID         string    `gorm:"not null;uniqueIndex:idx_tai_idempotency,priority:4;index:idx_tai_operator_created,priority:3"`
	Operation          string    `gorm:"not null;size:64;uniqueIndex:idx_tai_idempotency,priority:5"`
	IdempotencyKeyHash string    `gorm:"not null;size:64;uniqueIndex:idx_tai_idempotency,priority:6"`
	RequestHash        string    `gorm:"not null;size:64"`
	Outcome            string    `gorm:"not null;size:16"`
	ConfigVersion      int       `gorm:"not null"`
	ConfigHash         string    `gorm:"not null;size:64"`
	RuleVersion        string    `gorm:"not null;size:1024"`
	BeforeStatus       string    `gorm:"not null;size:64"`
	AfterStatus        string    `gorm:"not null;size:64"`
	BatchIDs           string    `gorm:"not null;type:jsonb"`
	AttemptIDs         string    `gorm:"not null;type:jsonb"`
	RequestedTargets   int       `gorm:"not null"`
	NewTargets         int       `gorm:"not null"`
	DuplicateTargets   int       `gorm:"not null"`
	ProjectScopeAdded  int       `gorm:"not null"`
	ProjectSeedsAdded  int       `gorm:"not null"`
	TotalChunks        int       `gorm:"not null"`
	TotalTargets       int       `gorm:"not null"`
	CreatedAt          time.Time `gorm:"not null;index:idx_tai_task_created,priority:4;index:idx_tai_operator_created,priority:4"`
}

func (TaskAppendIdempotency) TableName() string { return "task_append_idempotencies" }

type TaskAppendIdempotencyDraft struct {
	TenantID, ProjectID, RootTaskID, OperatorID, Operation string
	IdempotencyKey                                         string // never persisted raw
	RequestHash, ConfigHash, RuleVersion                   string
	Outcome, BeforeStatus, AfterStatus                     string
	ConfigVersion                                          int
	BatchIDs, AttemptIDs                                   []string
	RequestedTargets, NewTargets, DuplicateTargets         int
	ProjectScopeAdded, ProjectSeedsAdded                   int
	TotalChunks, TotalTargets                              int
}

type TaskAppendIdempotencyRecordResult struct {
	Record   TaskAppendIdempotency
	Replayed bool
}

var ErrTaskAppendIdempotencyConflict = errors.New("task append idempotency conflict")

// FindTaskAppendIdempotencyTx looks up a scoped key without comparing a
// request hash. API callers use the returned immutable ConfigVersion to
// normalize a retry exactly as the first committed request was normalized.
// This helper does not authorize the operation; callers must lock and verify
// the task and project before using it.
func FindTaskAppendIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey string) (TaskAppendIdempotency, bool, error) {
	var record TaskAppendIdempotency
	if tx == nil {
		return record, false, errors.New("task append idempotency transaction is unavailable")
	}
	for _, value := range []string{tenantID, projectID, rootTaskID, operatorID, operation} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 1024 {
			return record, false, errors.New("task append idempotency scope fields are required")
		}
	}
	if len(operation) > 64 || !validTaskAppendIdempotencyKey(idempotencyKey) {
		return record, false, errors.New("invalid task append idempotency key or operation")
	}
	err := tx.Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND operator_id = ? AND operation = ? AND idempotency_key_hash = ?", tenantID, projectID, rootTaskID, operatorID, operation, taskAppendIdempotencyHash(idempotencyKey)).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return TaskAppendIdempotency{}, false, nil
	}
	if err != nil {
		return TaskAppendIdempotency{}, false, fmt.Errorf("find task append idempotency: %w", err)
	}
	return record, true, nil
}

// LookupTaskAppendIdempotencyTx finds a prior record in the caller's
// transaction. A matching key bound to a different request returns conflict.
func LookupTaskAppendIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey, requestHash string) (TaskAppendIdempotencyRecordResult, error) {
	var result TaskAppendIdempotencyRecordResult
	if tx == nil {
		return result, errors.New("task append idempotency transaction is unavailable")
	}
	if err := validateTaskAppendIdempotencyLookup(tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey, requestHash); err != nil {
		return result, err
	}
	var record TaskAppendIdempotency
	err := tx.Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND operator_id = ? AND operation = ? AND idempotency_key_hash = ?", tenantID, projectID, rootTaskID, operatorID, operation, taskAppendIdempotencyHash(idempotencyKey)).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("lookup task append idempotency: %w", err)
	}
	if !constantTimeEqualTaskAppend(record.RequestHash, requestHash) {
		return result, ErrTaskAppendIdempotencyConflict
	}
	return TaskAppendIdempotencyRecordResult{Record: record, Replayed: true}, nil
}

// RecordTaskAppendIdempotencyTx atomically creates an immutable append
// outcome, or returns the previous outcome for an equivalent retry.
func RecordTaskAppendIdempotencyTx(tx *gorm.DB, draft TaskAppendIdempotencyDraft) (TaskAppendIdempotencyRecordResult, error) {
	var result TaskAppendIdempotencyRecordResult
	if tx == nil {
		return result, errors.New("task append idempotency transaction is unavailable")
	}
	if err := validateTaskAppendIdempotencyDraft(draft); err != nil {
		return result, err
	}
	batchIDs, _ := json.Marshal(draft.BatchIDs)
	attemptIDs, _ := json.Marshal(draft.AttemptIDs)
	candidate := TaskAppendIdempotency{
		SchemaVersion: TaskAppendIdempotencySchemaVersion, TenantID: draft.TenantID, ProjectID: draft.ProjectID, RootTaskID: draft.RootTaskID,
		OperatorID: draft.OperatorID, Operation: draft.Operation, IdempotencyKeyHash: taskAppendIdempotencyHash(draft.IdempotencyKey), RequestHash: draft.RequestHash,
		Outcome: draft.Outcome, ConfigVersion: draft.ConfigVersion, ConfigHash: draft.ConfigHash, RuleVersion: draft.RuleVersion,
		BeforeStatus: draft.BeforeStatus, AfterStatus: draft.AfterStatus, BatchIDs: string(batchIDs), AttemptIDs: string(attemptIDs),
		RequestedTargets: draft.RequestedTargets, NewTargets: draft.NewTargets, DuplicateTargets: draft.DuplicateTargets,
		ProjectScopeAdded: draft.ProjectScopeAdded, ProjectSeedsAdded: draft.ProjectSeedsAdded, TotalChunks: draft.TotalChunks, TotalTargets: draft.TotalTargets,
		CreatedAt: time.Now().UTC(),
	}
	created := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "root_task_id"}, {Name: "operator_id"}, {Name: "operation"}, {Name: "idempotency_key_hash"}}, DoNothing: true}).Create(&candidate)
	if created.Error != nil {
		return result, fmt.Errorf("record task append idempotency: %w", created.Error)
	}
	if created.RowsAffected == 1 {
		return TaskAppendIdempotencyRecordResult{Record: candidate}, nil
	}
	return LookupTaskAppendIdempotencyTx(tx, draft.TenantID, draft.ProjectID, draft.RootTaskID, draft.OperatorID, draft.Operation, draft.IdempotencyKey, draft.RequestHash)
}

func RecordTaskAppendIdempotency(store *gorm.DB, draft TaskAppendIdempotencyDraft) (TaskAppendIdempotencyRecordResult, error) {
	var result TaskAppendIdempotencyRecordResult
	if store == nil {
		return result, errors.New("task append idempotency store is unavailable")
	}
	err := store.Transaction(func(tx *gorm.DB) error {
		var err error
		result, err = RecordTaskAppendIdempotencyTx(tx, draft)
		return err
	})
	return result, err
}

func validateTaskAppendIdempotencyLookup(tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey, requestHash string) error {
	return validateTaskAppendIdempotencyDraft(TaskAppendIdempotencyDraft{TenantID: tenantID, ProjectID: projectID, RootTaskID: rootTaskID, OperatorID: operatorID, Operation: operation, IdempotencyKey: idempotencyKey, RequestHash: requestHash, Outcome: "unchanged", ConfigVersion: 1, ConfigHash: strings.Repeat("0", 64), RuleVersion: "unknown", BeforeStatus: "unknown", AfterStatus: "unknown"})
}

func validateTaskAppendIdempotencyDraft(d TaskAppendIdempotencyDraft) error {
	for _, value := range []string{d.TenantID, d.ProjectID, d.RootTaskID, d.OperatorID, d.Operation, d.Outcome, d.RuleVersion, d.BeforeStatus, d.AfterStatus} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 1024 {
			return errors.New("task append idempotency scope and outcome fields are required")
		}
	}
	if len(d.Operation) > 64 || len(d.Outcome) > 16 || len(d.BeforeStatus) > 64 || len(d.AfterStatus) > 64 || !validTaskAppendIdempotencyKey(d.IdempotencyKey) || !validTaskAppendIdempotencyHash(d.RequestHash) || !validTaskAppendIdempotencyHash(d.ConfigHash) {
		return errors.New("invalid task append idempotency hashes or operation")
	}
	if d.Outcome != "appended" && d.Outcome != "unchanged" {
		return errors.New("invalid task append idempotency outcome")
	}
	if d.ConfigVersion < 1 {
		return errors.New("invalid task append idempotency configuration version")
	}
	for _, value := range []int{d.RequestedTargets, d.NewTargets, d.DuplicateTargets, d.ProjectScopeAdded, d.ProjectSeedsAdded, d.TotalChunks, d.TotalTargets} {
		if value < 0 {
			return errors.New("invalid task append idempotency counts")
		}
	}
	if d.RequestedTargets != d.NewTargets+d.DuplicateTargets || (d.Outcome == "unchanged" && (d.NewTargets != 0 || len(d.BatchIDs) != 0 || len(d.AttemptIDs) != 0)) || (d.Outcome == "appended" && (d.NewTargets == 0 || len(d.BatchIDs) == 0 || len(d.BatchIDs) != len(d.AttemptIDs))) {
		return errors.New("inconsistent task append idempotency outcome")
	}
	for _, ids := range [][]string{d.BatchIDs, d.AttemptIDs} {
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if strings.TrimSpace(id) == "" || strings.TrimSpace(id) != id || len(id) > 1024 {
				return errors.New("invalid task append object id")
			}
			if _, ok := seen[id]; ok {
				return errors.New("duplicate task append object id")
			}
			seen[id] = struct{}{}
		}
	}
	return nil
}

func validTaskAppendIdempotencyKey(key string) bool {
	if len(key) < 1 || len(key) > 128 {
		return false
	}
	for _, r := range key {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func validTaskAppendIdempotencyHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func taskAppendIdempotencyHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqualTaskAppend(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
