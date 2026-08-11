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

const TaskCreationIdempotencySchemaVersion = "argus.task-creation-idempotency/v1"

// TaskCreationIdempotency is an immutable, internal record of one completed
// task-creation operation. It intentionally stores only hashes, created IDs,
// and counts; it is neither an authorization grant nor an execution token.
type TaskCreationIdempotency struct {
	ID                 uint      `gorm:"primaryKey;autoIncrement;uniqueIndex:idx_tci_scope_id,priority:3"`
	SchemaVersion      string    `gorm:"not null;size:64"`
	TenantID           string    `gorm:"not null;default:'default';uniqueIndex:idx_tci_scope_id,priority:1;uniqueIndex:idx_tci_idempotency,priority:1;index:idx_tci_task_created,priority:1;index:idx_tci_operator_created,priority:1"`
	ProjectID          string    `gorm:"not null;uniqueIndex:idx_tci_scope_id,priority:2;uniqueIndex:idx_tci_idempotency,priority:2;index:idx_tci_task_created,priority:2;index:idx_tci_operator_created,priority:2"`
	OperatorID         string    `gorm:"not null;uniqueIndex:idx_tci_idempotency,priority:3;index:idx_tci_operator_created,priority:3"`
	Operation          string    `gorm:"not null;size:64;uniqueIndex:idx_tci_idempotency,priority:4"`
	IdempotencyKeyHash string    `gorm:"not null;size:64;uniqueIndex:idx_tci_idempotency,priority:5"`
	RequestHash        string    `gorm:"not null;size:64"`
	RootTaskID         string    `gorm:"not null;index:idx_tci_task_created,priority:3"`
	AttemptIDs         string    `gorm:"not null;type:jsonb"`
	ProjectScopeAdded  int       `gorm:"not null"`
	ProjectSeedsAdded  int       `gorm:"not null"`
	CreatedAt          time.Time `gorm:"not null;index:idx_tci_task_created,priority:4;index:idx_tci_operator_created,priority:4"`
}

func (TaskCreationIdempotency) TableName() string { return "task_creation_idempotencies" }

type TaskCreationIdempotencyDraft struct {
	TenantID, ProjectID, OperatorID, Operation string
	IdempotencyKey                             string // never persisted raw
	RequestHash, RootTaskID                    string
	AttemptIDs                                 []string
	ProjectScopeAdded, ProjectSeedsAdded       int
}

type TaskCreationIdempotencyRecordResult struct {
	Record   TaskCreationIdempotency
	Replayed bool
}

var ErrTaskCreationIdempotencyConflict = errors.New("task creation idempotency conflict")

// RecordTaskCreationIdempotencyTx creates the record in its caller's
// transaction. The caller must create the referenced RootTask in the same
// transaction before commit; PostgreSQL enforces that relationship deferred.
func RecordTaskCreationIdempotencyTx(tx *gorm.DB, draft TaskCreationIdempotencyDraft) (TaskCreationIdempotencyRecordResult, error) {
	var result TaskCreationIdempotencyRecordResult
	if tx == nil {
		return result, errors.New("task creation idempotency transaction is unavailable")
	}
	if err := validateTaskCreationIdempotencyDraft(draft); err != nil {
		return result, err
	}
	attemptIDs, _ := json.Marshal(draft.AttemptIDs)
	candidate := TaskCreationIdempotency{
		SchemaVersion: TaskCreationIdempotencySchemaVersion, TenantID: draft.TenantID, ProjectID: draft.ProjectID,
		OperatorID: draft.OperatorID, Operation: draft.Operation, IdempotencyKeyHash: taskCreationIdempotencyHash(draft.IdempotencyKey),
		RequestHash: draft.RequestHash, RootTaskID: draft.RootTaskID, AttemptIDs: string(attemptIDs),
		ProjectScopeAdded: draft.ProjectScopeAdded, ProjectSeedsAdded: draft.ProjectSeedsAdded, CreatedAt: time.Now().UTC(),
	}
	created := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "operator_id"}, {Name: "operation"}, {Name: "idempotency_key_hash"}}, DoNothing: true}).Create(&candidate)
	if created.Error != nil {
		return result, fmt.Errorf("record task creation idempotency: %w", created.Error)
	}
	if created.RowsAffected == 1 {
		return TaskCreationIdempotencyRecordResult{Record: candidate}, nil
	}
	var existing TaskCreationIdempotency
	if err := tx.Where("tenant_id = ? AND project_id = ? AND operator_id = ? AND operation = ? AND idempotency_key_hash = ?", draft.TenantID, draft.ProjectID, draft.OperatorID, draft.Operation, candidate.IdempotencyKeyHash).First(&existing).Error; err != nil {
		return result, fmt.Errorf("load task creation idempotency replay: %w", err)
	}
	// RootTaskID, AttemptIDs, and counters are generated during a creation
	// attempt. Retried HTTP requests may regenerate them before reaching this
	// helper, so the immutable result must be selected by the request binding,
	// not compared to a new candidate result.
	if !constantTimeEqual(existing.RequestHash, candidate.RequestHash) {
		return result, ErrTaskCreationIdempotencyConflict
	}
	return TaskCreationIdempotencyRecordResult{Record: existing, Replayed: true}, nil
}

func RecordTaskCreationIdempotency(store *gorm.DB, draft TaskCreationIdempotencyDraft) (TaskCreationIdempotencyRecordResult, error) {
	var result TaskCreationIdempotencyRecordResult
	if store == nil {
		return result, errors.New("task creation idempotency store is unavailable")
	}
	err := store.Transaction(func(tx *gorm.DB) error {
		var err error
		result, err = RecordTaskCreationIdempotencyTx(tx, draft)
		return err
	})
	return result, err
}

func validateTaskCreationIdempotencyDraft(d TaskCreationIdempotencyDraft) error {
	for _, value := range []string{d.TenantID, d.ProjectID, d.OperatorID, d.Operation, d.RootTaskID} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || len(value) > 1024 {
			return errors.New("task creation idempotency scope and binding fields are required")
		}
	}
	if len(d.Operation) > 64 || !validTaskCreationIdempotencyKey(d.IdempotencyKey) || !validTaskCreationIdempotencyHash(d.RequestHash) {
		return errors.New("invalid task creation idempotency hashes or operation")
	}
	if d.ProjectScopeAdded < 0 || d.ProjectSeedsAdded < 0 {
		return errors.New("invalid task creation idempotency result counts")
	}
	seen := make(map[string]struct{}, len(d.AttemptIDs))
	for _, id := range d.AttemptIDs {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(id) != id || len(id) > 1024 {
			return errors.New("invalid task creation attempt id")
		}
		if _, ok := seen[id]; ok {
			return errors.New("duplicate task creation attempt id")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validTaskCreationIdempotencyKey(key string) bool {
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

func validTaskCreationIdempotencyHash(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func taskCreationIdempotencyHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
