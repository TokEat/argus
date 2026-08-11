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

const RiskValidationExecutionIdempotencySchemaVersion = "argus.risk-validation-execution-idempotency/v1"

// RiskValidationExecutionIdempotency is an immutable execution ledger. It
// deliberately contains hashes and bounded counts only: never targets, POC
// contents, provider queries, or credentials.
type RiskValidationExecutionIdempotency struct {
	ID                         uint      `gorm:"primaryKey;autoIncrement;uniqueIndex:idx_rvei_scope_id,priority:4"`
	SchemaVersion              string    `gorm:"not null;size:64"`
	TenantID                   string    `gorm:"not null;default:'default';uniqueIndex:idx_rvei_scope_id,priority:1;uniqueIndex:idx_rvei_idempotency,priority:1;index:idx_rvei_task_created,priority:1;index:idx_rvei_operator_created,priority:1"`
	ProjectID                  string    `gorm:"not null;uniqueIndex:idx_rvei_scope_id,priority:2;uniqueIndex:idx_rvei_idempotency,priority:2;index:idx_rvei_task_created,priority:2;index:idx_rvei_operator_created,priority:2"`
	RootTaskID                 string    `gorm:"not null;uniqueIndex:idx_rvei_scope_id,priority:3;uniqueIndex:idx_rvei_idempotency,priority:3;index:idx_rvei_task_created,priority:3"`
	OperatorID                 string    `gorm:"not null;uniqueIndex:idx_rvei_idempotency,priority:4;index:idx_rvei_operator_created,priority:3"`
	Operation                  string    `gorm:"not null;size:64;uniqueIndex:idx_rvei_idempotency,priority:5"`
	IdempotencyKeyHash         string    `gorm:"not null;size:64;uniqueIndex:idx_rvei_idempotency,priority:6"`
	RequestHash                string    `gorm:"not null;size:64"`
	PlanHash                   string    `gorm:"not null;size:64"`
	POCSetHash                 string    `gorm:"not null;size:64"`
	ConfigVersion              int       `gorm:"not null"`
	ConfigHash                 string    `gorm:"not null;size:64"`
	RuleVersion                string    `gorm:"not null;size:1024"`
	BatchID                    string    `gorm:"not null"`
	BatchSequence              int       `gorm:"not null"`
	AttemptID                  string    `gorm:"not null"`
	AttemptNo                  int       `gorm:"not null"`
	CandidateCount             int       `gorm:"not null"`
	TargetCount                int       `gorm:"not null"`
	POCCount                   int       `gorm:"not null"`
	EstimatedRequests          int64     `gorm:"not null"`
	SecondConfirmationRequired bool      `gorm:"not null"`
	BeforeStatus               string    `gorm:"not null;size:64"`
	AfterStatus                string    `gorm:"not null;size:64"`
	CreatedAt                  time.Time `gorm:"not null;index:idx_rvei_task_created,priority:4;index:idx_rvei_operator_created,priority:4"`
}

func (RiskValidationExecutionIdempotency) TableName() string {
	return "risk_validation_execution_idempotencies"
}

type RiskValidationExecutionIdempotencyDraft struct {
	TenantID, ProjectID, RootTaskID, OperatorID, Operation, IdempotencyKey         string
	RequestHash, PlanHash, POCSetHash, ConfigHash, RuleVersion, BatchID, AttemptID string
	ConfigVersion, BatchSequence, AttemptNo, CandidateCount, TargetCount, POCCount int
	EstimatedRequests                                                              int64
	SecondConfirmationRequired                                                     bool
	BeforeStatus, AfterStatus                                                      string
}
type RiskValidationExecutionIdempotencyRecordResult struct {
	Record   RiskValidationExecutionIdempotency
	Replayed bool
}

var ErrRiskValidationExecutionIdempotencyConflict = errors.New("risk validation execution idempotency conflict")

func FindRiskValidationExecutionIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, operatorID, operation, key string) (RiskValidationExecutionIdempotency, bool, error) {
	var r RiskValidationExecutionIdempotency
	if tx == nil {
		return r, false, errors.New("risk validation execution idempotency transaction is unavailable")
	}
	if err := validateRiskValidationExecutionIdempotencyScope(tenantID, projectID, rootTaskID, operatorID, operation, key); err != nil {
		return r, false, err
	}
	err := tx.Where("tenant_id = ? AND project_id = ? AND root_task_id = ? AND operator_id = ? AND operation = ? AND idempotency_key_hash = ?", tenantID, projectID, rootTaskID, operatorID, operation, riskValidationExecutionIdempotencyHash(key)).First(&r).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return RiskValidationExecutionIdempotency{}, false, nil
	}
	if err != nil {
		return r, false, fmt.Errorf("find risk validation execution idempotency: %w", err)
	}
	return r, true, nil
}
func LookupRiskValidationExecutionIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, operatorID, operation, key, requestHash string) (RiskValidationExecutionIdempotencyRecordResult, error) {
	if !validRiskValidationExecutionIdempotencyHash(requestHash) {
		return RiskValidationExecutionIdempotencyRecordResult{}, errors.New("invalid risk validation execution idempotency request hash")
	}
	r, found, err := FindRiskValidationExecutionIdempotencyTx(tx, tenantID, projectID, rootTaskID, operatorID, operation, key)
	if err != nil || !found {
		return RiskValidationExecutionIdempotencyRecordResult{}, err
	}
	if !constantTimeEqualRiskValidationExecution(r.RequestHash, requestHash) {
		return RiskValidationExecutionIdempotencyRecordResult{}, ErrRiskValidationExecutionIdempotencyConflict
	}
	return RiskValidationExecutionIdempotencyRecordResult{Record: r, Replayed: true}, nil
}
func RecordRiskValidationExecutionIdempotencyTx(tx *gorm.DB, d RiskValidationExecutionIdempotencyDraft) (RiskValidationExecutionIdempotencyRecordResult, error) {
	if tx == nil {
		return RiskValidationExecutionIdempotencyRecordResult{}, errors.New("risk validation execution idempotency transaction is unavailable")
	}
	if err := validateRiskValidationExecutionIdempotencyDraft(d); err != nil {
		return RiskValidationExecutionIdempotencyRecordResult{}, err
	}
	r := RiskValidationExecutionIdempotency{SchemaVersion: RiskValidationExecutionIdempotencySchemaVersion, TenantID: d.TenantID, ProjectID: d.ProjectID, RootTaskID: d.RootTaskID, OperatorID: d.OperatorID, Operation: d.Operation, IdempotencyKeyHash: riskValidationExecutionIdempotencyHash(d.IdempotencyKey), RequestHash: d.RequestHash, PlanHash: d.PlanHash, POCSetHash: d.POCSetHash, ConfigVersion: d.ConfigVersion, ConfigHash: d.ConfigHash, RuleVersion: d.RuleVersion, BatchID: d.BatchID, BatchSequence: d.BatchSequence, AttemptID: d.AttemptID, AttemptNo: d.AttemptNo, CandidateCount: d.CandidateCount, TargetCount: d.TargetCount, POCCount: d.POCCount, EstimatedRequests: d.EstimatedRequests, SecondConfirmationRequired: d.SecondConfirmationRequired, BeforeStatus: d.BeforeStatus, AfterStatus: d.AfterStatus, CreatedAt: time.Now().UTC()}
	created := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "root_task_id"}, {Name: "operator_id"}, {Name: "operation"}, {Name: "idempotency_key_hash"}}, DoNothing: true}).Create(&r)
	if created.Error != nil {
		return RiskValidationExecutionIdempotencyRecordResult{}, fmt.Errorf("record risk validation execution idempotency: %w", created.Error)
	}
	if created.RowsAffected == 1 {
		return RiskValidationExecutionIdempotencyRecordResult{Record: r}, nil
	}
	return LookupRiskValidationExecutionIdempotencyTx(tx, d.TenantID, d.ProjectID, d.RootTaskID, d.OperatorID, d.Operation, d.IdempotencyKey, d.RequestHash)
}
func validateRiskValidationExecutionIdempotencyScope(values ...string) error {
	if len(values) != 6 {
		return errors.New("invalid risk validation execution idempotency scope")
	}
	for _, v := range values[:5] {
		if strings.TrimSpace(v) == "" || strings.TrimSpace(v) != v || len(v) > 1024 {
			return errors.New("risk validation execution idempotency scope fields are required")
		}
	}
	if len(values[4]) > 64 || !validRiskValidationExecutionIdempotencyKey(values[5]) {
		return errors.New("invalid risk validation execution idempotency key or operation")
	}
	return nil
}
func validateRiskValidationExecutionIdempotencyDraft(d RiskValidationExecutionIdempotencyDraft) error {
	if err := validateRiskValidationExecutionIdempotencyScope(d.TenantID, d.ProjectID, d.RootTaskID, d.OperatorID, d.Operation, d.IdempotencyKey); err != nil {
		return err
	}
	for _, v := range []string{d.RequestHash, d.PlanHash, d.POCSetHash, d.ConfigHash} {
		if !validRiskValidationExecutionIdempotencyHash(v) {
			return errors.New("invalid risk validation execution idempotency hash")
		}
	}
	for _, v := range []string{d.RuleVersion, d.BatchID, d.AttemptID, d.BeforeStatus, d.AfterStatus} {
		if strings.TrimSpace(v) == "" || strings.TrimSpace(v) != v || len(v) > 1024 {
			return errors.New("risk validation execution idempotency outcome fields are required")
		}
	}
	if len(d.RuleVersion) > 1024 || len(d.BeforeStatus) > 64 || len(d.AfterStatus) > 64 || d.ConfigVersion < 1 || d.BatchSequence < 0 || d.AttemptNo < 1 || d.CandidateCount < 1 || d.TargetCount < 1 || d.POCCount < 1 || d.EstimatedRequests < 0 {
		return errors.New("invalid risk validation execution idempotency outcome")
	}
	return nil
}
func validRiskValidationExecutionIdempotencyKey(key string) bool {
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
func validRiskValidationExecutionIdempotencyHash(v string) bool {
	if len(v) != 64 || strings.ToLower(v) != v {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
func riskValidationExecutionIdempotencyHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
func constantTimeEqualRiskValidationExecution(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type RiskValidationIdempotency = RiskValidationExecutionIdempotency
type RiskValidationIdempotencyDraft = RiskValidationExecutionIdempotencyDraft
type RiskValidationIdempotencyRecordResult = RiskValidationExecutionIdempotencyRecordResult

var ErrRiskValidationIdempotencyConflict = ErrRiskValidationExecutionIdempotencyConflict

func FindRiskValidationIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, operatorID, operation, key string) (RiskValidationIdempotency, bool, error) {
	return FindRiskValidationExecutionIdempotencyTx(tx, tenantID, projectID, rootTaskID, operatorID, operation, key)
}
func LookupRiskValidationIdempotencyTx(tx *gorm.DB, tenantID, projectID, rootTaskID, operatorID, operation, key, requestHash string) (RiskValidationIdempotencyRecordResult, error) {
	return LookupRiskValidationExecutionIdempotencyTx(tx, tenantID, projectID, rootTaskID, operatorID, operation, key, requestHash)
}
func RecordRiskValidationIdempotencyTx(tx *gorm.DB, draft RiskValidationIdempotencyDraft) (RiskValidationIdempotencyRecordResult, error) {
	return RecordRiskValidationExecutionIdempotencyTx(tx, draft)
}
