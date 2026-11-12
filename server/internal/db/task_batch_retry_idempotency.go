package db

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const TaskBatchRetryIdempotencySchemaVersion = "argus.task-batch-retry-idempotency/v1"

// TaskBatchRetryIdempotency is an immutable, batch-scoped record of a completed
// retry operation. It stores only hashes and safe frozen outcome metadata; it
// is not an authorization grant or a dispatch token.
type TaskBatchRetryIdempotency struct {
	ID                 uint      `gorm:"primaryKey;autoIncrement;uniqueIndex:idx_tbri_scope_id,priority:5"`
	SchemaVersion      string    `gorm:"not null;size:64"`
	TenantID           string    `gorm:"not null;default:'default';uniqueIndex:idx_tbri_scope_id,priority:1;uniqueIndex:idx_tbri_idempotency,priority:1;index:idx_tbri_batch_created,priority:1;index:idx_tbri_operator_created,priority:1"`
	ProjectID          string    `gorm:"not null;uniqueIndex:idx_tbri_scope_id,priority:2;uniqueIndex:idx_tbri_idempotency,priority:2;index:idx_tbri_batch_created,priority:2;index:idx_tbri_operator_created,priority:2"`
	RootTaskID         string    `gorm:"not null;uniqueIndex:idx_tbri_scope_id,priority:3;uniqueIndex:idx_tbri_idempotency,priority:3;index:idx_tbri_batch_created,priority:3"`
	BatchID            string    `gorm:"not null;uniqueIndex:idx_tbri_scope_id,priority:4;uniqueIndex:idx_tbri_idempotency,priority:4;index:idx_tbri_batch_created,priority:4"`
	OperatorID         string    `gorm:"not null;uniqueIndex:idx_tbri_idempotency,priority:5;index:idx_tbri_operator_created,priority:3"`
	Operation          string    `gorm:"not null;size:64;uniqueIndex:idx_tbri_idempotency,priority:6"`
	IdempotencyKeyHash string    `gorm:"not null;size:64;uniqueIndex:idx_tbri_idempotency,priority:7"`
	RequestHash        string    `gorm:"not null;size:64"`
	AttemptID          string    `gorm:"not null"`
	AttemptNo          int       `gorm:"not null"`
	ConfigVersion      int       `gorm:"not null"`
	ConfigHash         string    `gorm:"not null;size:64"`
	RuleVersion        string    `gorm:"not null;size:1024"`
	BeforeStatus       string    `gorm:"not null;size:64"`
	AfterStatus        string    `gorm:"not null;size:64"`
	CreatedAt          time.Time `gorm:"not null;index:idx_tbri_batch_created,priority:5;index:idx_tbri_operator_created,priority:4"`
}

func (TaskBatchRetryIdempotency) TableName() string { return "task_batch_retry_idempotencies" }

type TaskBatchRetryIdempotencyDraft struct {
	TenantID, ProjectID, RootTaskID, BatchID, OperatorID, Operation string
	IdempotencyKey                                                 string // never persisted raw
	RequestHash, AttemptID, ConfigHash, RuleVersion                string
	AttemptNo, ConfigVersion                                       int
	BeforeStatus, AfterStatus                                      string
}

type TaskBatchRetryIdempotencyRecordResult struct {
	Record   TaskBatchRetryIdempotency
	Replayed bool
}

var ErrTaskBatchRetryIdempotencyConflict = errors.New("task batch retry idempotency conflict")

// FindTaskBatchRetryIdempotencyTx looks up a scoped key in the caller's
// transaction. Callers must authorize and lock the tenant/project/task/batch
// scope before using a result.
func FindTaskBatchRetryIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, batchID, operatorID, operation, idempotencyKey string) (TaskBatchRetryIdempotency, bool, error) {
	var record TaskBatchRetryIdempotency
	if tx == nil {
		return record, false, errors.New("task batch retry idempotency transaction is unavailable")
	}
	if err := validateTaskBatchRetryIdempotencyScope(tenantID, projectID, rootTaskID, batchID, operatorID, operation, idempotencyKey); err != nil {
		return record, false, err
	}
	err := tx.Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND batch_id = ? AND operator_id = ? AND operation = ? AND idempotency_key_hash = ?", tenantID, projectID, rootTaskID, batchID, operatorID, operation, taskBatchRetryIdempotencyHash(idempotencyKey)).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return TaskBatchRetryIdempotency{}, false, nil
	}
	if err != nil {
		return TaskBatchRetryIdempotency{}, false, fmt.Errorf("find task batch retry idempotency: %w", err)
	}
	return record, true, nil
}

func LookupTaskBatchRetryIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, batchID, operatorID, operation, idempotencyKey, requestHash string) (TaskBatchRetryIdempotencyRecordResult, error) {
	var result TaskBatchRetryIdempotencyRecordResult
	if tx == nil {
		return result, errors.New("task batch retry idempotency transaction is unavailable")
	}
	if err := validateTaskBatchRetryIdempotencyLookup(tenantID, projectID, rootTaskID, batchID, operatorID, operation, idempotencyKey, requestHash); err != nil {
		return result, err
	}
	record, found, err := FindTaskBatchRetryIdempotencyTx(tx, tenantID, projectID, rootTaskID, batchID, operatorID, operation, idempotencyKey)
	if err != nil || !found {
		return result, err
	}
	if !constantTimeEqualTaskBatchRetry(record.IdempotencyKeyHash, taskBatchRetryIdempotencyHash(idempotencyKey)) || !constantTimeEqualTaskBatchRetry(record.RequestHash, requestHash) {
		return result, ErrTaskBatchRetryIdempotencyConflict
	}
	return TaskBatchRetryIdempotencyRecordResult{Record: record, Replayed: true}, nil
}

// RecordTaskBatchRetryIdempotencyTx creates a frozen batch retry outcome in
// the caller's transaction, or returns the previous outcome for an equivalent
// retry. A matching key with a different request hash returns the conflict
// sentinel.
func RecordTaskBatchRetryIdempotencyTx(tx *gorm.DB, draft TaskBatchRetryIdempotencyDraft) (TaskBatchRetryIdempotencyRecordResult, error) {
	var result TaskBatchRetryIdempotencyRecordResult
	if tx == nil {
		return result, errors.New("task batch retry idempotency transaction is unavailable")
	}
	if err := validateTaskBatchRetryIdempotencyDraft(draft); err != nil {
		return result, err
	}
	candidate := TaskBatchRetryIdempotency{
		SchemaVersion: TaskBatchRetryIdempotencySchemaVersion, TenantID: draft.TenantID, ProjectID: draft.ProjectID, RootTaskID: draft.RootTaskID, BatchID: draft.BatchID,
		OperatorID: draft.OperatorID, Operation: draft.Operation, IdempotencyKeyHash: taskBatchRetryIdempotencyHash(draft.IdempotencyKey), RequestHash: draft.RequestHash,
		AttemptID: draft.AttemptID, AttemptNo: draft.AttemptNo, ConfigVersion: draft.ConfigVersion, ConfigHash: draft.ConfigHash, RuleVersion: draft.RuleVersion,
		BeforeStatus: draft.BeforeStatus, AfterStatus: draft.AfterStatus, CreatedAt: time.Now().UTC(),
	}
	created := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "root_task_id"}, {Name: "batch_id"}, {Name: "operator_id"}, {Name: "operation"}, {Name: "idempotency_key_hash"}}, DoNothing: true}).Create(&candidate)
	if created.Error != nil {
		return result, fmt.Errorf("record task batch retry idempotency: %w", created.Error)
	}
	if created.RowsAffected == 1 {
		return TaskBatchRetryIdempotencyRecordResult{Record: candidate}, nil
	}
	return LookupTaskBatchRetryIdempotencyTx(tx, draft.TenantID, draft.ProjectID, draft.RootTaskID, draft.BatchID, draft.OperatorID, draft.Operation, draft.IdempotencyKey, draft.RequestHash)
}

func validateTaskBatchRetryIdempotencyLookup(tenantID, projectID, rootTaskID, batchID, operatorID, operation, idempotencyKey, requestHash string) error {
	if err := validateTaskBatchRetryIdempotencyScope(tenantID, projectID, rootTaskID, batchID, operatorID, operation, idempotencyKey); err != nil {
		return err
	}
	if !validTaskBatchRetryIdempotencyHash(requestHash) {
		return errors.New("invalid task batch retry idempotency request hash")
	}
	return nil
}

func validateTaskBatchRetryIdempotencyScope(tenantID, projectID, rootTaskID, batchID, operatorID, operation, idempotencyKey string) error {
	for _, value := range []string{tenantID, projectID, rootTaskID, batchID, operatorID, operation} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 1024 {
			return errors.New("task batch retry idempotency scope fields are required")
		}
	}
	if len(operation) > 64 || !validTaskBatchRetryIdempotencyKey(idempotencyKey) {
		return errors.New("invalid task batch retry idempotency key or operation")
	}
	return nil
}

func validateTaskBatchRetryIdempotencyDraft(d TaskBatchRetryIdempotencyDraft) error {
	if err := validateTaskBatchRetryIdempotencyLookup(d.TenantID, d.ProjectID, d.RootTaskID, d.BatchID, d.OperatorID, d.Operation, d.IdempotencyKey, d.RequestHash); err != nil {
		return err
	}
	for _, value := range []string{d.AttemptID, d.RuleVersion, d.BeforeStatus, d.AfterStatus} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 1024 {
			return errors.New("task batch retry idempotency outcome fields are required")
		}
	}
	if len(d.BeforeStatus) > 64 || len(d.AfterStatus) > 64 || len(d.RuleVersion) > 1024 || d.AttemptNo < 1 || d.ConfigVersion < 1 || !validTaskBatchRetryIdempotencyHash(d.ConfigHash) {
		return errors.New("invalid task batch retry idempotency outcome")
	}
	return nil
}

func validTaskBatchRetryIdempotencyKey(key string) bool {
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

func validTaskBatchRetryIdempotencyHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func taskBatchRetryIdempotencyHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqualTaskBatchRetry(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
