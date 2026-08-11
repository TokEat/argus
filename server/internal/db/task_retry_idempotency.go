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

const TaskRetryIdempotencySchemaVersion = "argus.task-retry-idempotency/v1"

// TaskRetryIdempotency is an immutable, task-scoped record of a completed
// retry operation. It stores only hashes and safe outcome metadata; it is not
// an authorization grant or a dispatch token.
type TaskRetryIdempotency struct {
	ID                 uint      `gorm:"primaryKey;autoIncrement;uniqueIndex:idx_tri_scope_id,priority:4"`
	SchemaVersion      string    `gorm:"not null;size:64"`
	TenantID           string    `gorm:"not null;default:'default';uniqueIndex:idx_tri_scope_id,priority:1;uniqueIndex:idx_tri_idempotency,priority:1;index:idx_tri_task_created,priority:1;index:idx_tri_operator_created,priority:1"`
	ProjectID          string    `gorm:"not null;uniqueIndex:idx_tri_scope_id,priority:2;uniqueIndex:idx_tri_idempotency,priority:2;index:idx_tri_task_created,priority:2;index:idx_tri_operator_created,priority:2"`
	RootTaskID         string    `gorm:"not null;uniqueIndex:idx_tri_scope_id,priority:3;uniqueIndex:idx_tri_idempotency,priority:3;index:idx_tri_task_created,priority:3"`
	OperatorID         string    `gorm:"not null;uniqueIndex:idx_tri_idempotency,priority:4;index:idx_tri_operator_created,priority:3"`
	Operation          string    `gorm:"not null;size:64;uniqueIndex:idx_tri_idempotency,priority:5"`
	IdempotencyKeyHash string    `gorm:"not null;size:64;uniqueIndex:idx_tri_idempotency,priority:6"`
	RequestHash        string    `gorm:"not null;size:64"`
	BeforeStatus       string    `gorm:"not null;size:64"`
	AfterStatus        string    `gorm:"not null;size:64"`
	AttemptIDs         string    `gorm:"not null;type:jsonb"`
	CompletedSkipped   int       `gorm:"not null"`
	PausedSkipped      int       `gorm:"not null"`
	CreatedAt          time.Time `gorm:"not null;index:idx_tri_task_created,priority:4;index:idx_tri_operator_created,priority:4"`
}

func (TaskRetryIdempotency) TableName() string { return "task_retry_idempotencies" }

type TaskRetryIdempotencyDraft struct {
	TenantID, ProjectID, RootTaskID, OperatorID, Operation string
	IdempotencyKey                                         string // never persisted raw
	RequestHash                                            string
	BeforeStatus, AfterStatus                              string
	AttemptIDs                                             []string
	CompletedSkipped, PausedSkipped                        int
}

type TaskRetryIdempotencyRecordResult struct {
	Record   TaskRetryIdempotency
	Replayed bool
}

var ErrTaskRetryIdempotencyConflict = errors.New("task retry idempotency conflict")

func FindTaskRetryIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey string) (TaskRetryIdempotency, bool, error) {
	var record TaskRetryIdempotency
	if tx == nil {
		return record, false, errors.New("task retry idempotency transaction is unavailable")
	}
	if err := validateTaskRetryIdempotencyScope(tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey); err != nil {
		return record, false, err
	}
	err := tx.Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND operator_id = ? AND operation = ? AND idempotency_key_hash = ?", tenantID, projectID, rootTaskID, operatorID, operation, taskRetryIdempotencyHash(idempotencyKey)).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return TaskRetryIdempotency{}, false, nil
	}
	if err != nil {
		return TaskRetryIdempotency{}, false, fmt.Errorf("find task retry idempotency: %w", err)
	}
	return record, true, nil
}

func LookupTaskRetryIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey, requestHash string) (TaskRetryIdempotencyRecordResult, error) {
	var result TaskRetryIdempotencyRecordResult
	if tx == nil {
		return result, errors.New("task retry idempotency transaction is unavailable")
	}
	if err := validateTaskRetryIdempotencyLookup(tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey, requestHash); err != nil {
		return result, err
	}
	record, found, err := FindTaskRetryIdempotencyTx(tx, tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey)
	if err != nil || !found {
		return result, err
	}
	if !constantTimeEqualTaskRetry(record.IdempotencyKeyHash, taskRetryIdempotencyHash(idempotencyKey)) || !constantTimeEqualTaskRetry(record.RequestHash, requestHash) {
		return result, ErrTaskRetryIdempotencyConflict
	}
	return TaskRetryIdempotencyRecordResult{Record: record, Replayed: true}, nil
}

func RecordTaskRetryIdempotencyTx(tx *gorm.DB, draft TaskRetryIdempotencyDraft) (TaskRetryIdempotencyRecordResult, error) {
	var result TaskRetryIdempotencyRecordResult
	if tx == nil {
		return result, errors.New("task retry idempotency transaction is unavailable")
	}
	if err := validateTaskRetryIdempotencyDraft(draft); err != nil {
		return result, err
	}
	attemptIDs, _ := json.Marshal(draft.AttemptIDs)
	candidate := TaskRetryIdempotency{
		SchemaVersion: TaskRetryIdempotencySchemaVersion, TenantID: draft.TenantID, ProjectID: draft.ProjectID, RootTaskID: draft.RootTaskID,
		OperatorID: draft.OperatorID, Operation: draft.Operation, IdempotencyKeyHash: taskRetryIdempotencyHash(draft.IdempotencyKey), RequestHash: draft.RequestHash,
		BeforeStatus: draft.BeforeStatus, AfterStatus: draft.AfterStatus, AttemptIDs: string(attemptIDs), CompletedSkipped: draft.CompletedSkipped,
		PausedSkipped: draft.PausedSkipped, CreatedAt: time.Now().UTC(),
	}
	created := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "root_task_id"}, {Name: "operator_id"}, {Name: "operation"}, {Name: "idempotency_key_hash"}}, DoNothing: true}).Create(&candidate)
	if created.Error != nil {
		return result, fmt.Errorf("record task retry idempotency: %w", created.Error)
	}
	if created.RowsAffected == 1 {
		return TaskRetryIdempotencyRecordResult{Record: candidate}, nil
	}
	return LookupTaskRetryIdempotencyTx(tx, draft.TenantID, draft.ProjectID, draft.RootTaskID, draft.OperatorID, draft.Operation, draft.IdempotencyKey, draft.RequestHash)
}

func RecordTaskRetryIdempotency(store *gorm.DB, draft TaskRetryIdempotencyDraft) (TaskRetryIdempotencyRecordResult, error) {
	var result TaskRetryIdempotencyRecordResult
	if store == nil {
		return result, errors.New("task retry idempotency store is unavailable")
	}
	err := store.Transaction(func(tx *gorm.DB) error {
		var err error
		result, err = RecordTaskRetryIdempotencyTx(tx, draft)
		return err
	})
	return result, err
}

func validateTaskRetryIdempotencyLookup(tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey, requestHash string) error {
	if err := validateTaskRetryIdempotencyScope(tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey); err != nil {
		return err
	}
	if !validTaskRetryIdempotencyHash(requestHash) {
		return errors.New("invalid task retry idempotency request hash")
	}
	return nil
}

func validateTaskRetryIdempotencyScope(tenantID, projectID, rootTaskID, operatorID, operation, idempotencyKey string) error {
	for _, value := range []string{tenantID, projectID, rootTaskID, operatorID, operation} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 1024 {
			return errors.New("task retry idempotency scope fields are required")
		}
	}
	if len(operation) > 64 || !validTaskRetryIdempotencyKey(idempotencyKey) {
		return errors.New("invalid task retry idempotency key or operation")
	}
	return nil
}

func validateTaskRetryIdempotencyDraft(d TaskRetryIdempotencyDraft) error {
	if err := validateTaskRetryIdempotencyLookup(d.TenantID, d.ProjectID, d.RootTaskID, d.OperatorID, d.Operation, d.IdempotencyKey, d.RequestHash); err != nil {
		return err
	}
	for _, value := range []string{d.BeforeStatus, d.AfterStatus} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 64 {
			return errors.New("task retry idempotency statuses are required")
		}
	}
	if d.CompletedSkipped < 0 || d.PausedSkipped < 0 {
		return errors.New("invalid task retry idempotency counts")
	}
	if len(d.AttemptIDs) == 0 {
		return errors.New("task retry idempotency requires at least one attempt")
	}
	seen := make(map[string]struct{}, len(d.AttemptIDs))
	for _, id := range d.AttemptIDs {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(id) != id || len(id) > 1024 {
			return errors.New("invalid task retry attempt id")
		}
		if _, ok := seen[id]; ok {
			return errors.New("duplicate task retry attempt id")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validTaskRetryIdempotencyKey(key string) bool {
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

func validTaskRetryIdempotencyHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func taskRetryIdempotencyHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqualTaskRetry(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
