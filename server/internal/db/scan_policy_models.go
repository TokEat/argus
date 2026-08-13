package db

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	ScanStageIntentPending  = "pending"
	ScanStageIntentDerived  = "derived"
	ScanStageIntentSkipped  = "skipped"
	ScanStageIntentFailed   = "failed"
	ScanStageIntentComplete = "complete"
)

// ScanPolicyIntent is the immutable, Server-authoritative policy snapshot for
// one root task. PolicyJSON never contains dictionary contents or host paths.
type ScanPolicyIntent struct {
	ID                   uint   `gorm:"primaryKey;autoIncrement"`
	TenantID             string `gorm:"default:'default';index;uniqueIndex:idx_scan_policy_intent_root,priority:1"`
	ProjectID            string `gorm:"index"`
	RootTaskID           string `gorm:"index;uniqueIndex:idx_scan_policy_intent_root,priority:2"`
	SchemaVersion        string `gorm:"size:64"`
	PolicyJSON           string `gorm:"type:jsonb"`
	PolicyHash           string `gorm:"size:64;index"`
	PlanHash             string `gorm:"size:64;index"`
	RiskStatus           string `gorm:"size:24;index"`
	CredentialStatus     string `gorm:"size:24;index"`
	AuthorizationActorID string `gorm:"index"`
	AuthorizedAt         *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// ScanStageDerivation makes automatic validation batch creation idempotent.
// Exactly one row exists for each root/stage pair, including skipped stages.
type ScanStageDerivation struct {
	ID              uint   `gorm:"primaryKey;autoIncrement"`
	TenantID        string `gorm:"default:'default';index;uniqueIndex:idx_scan_stage_derivation,priority:1"`
	ProjectID       string `gorm:"index"`
	RootTaskID      string `gorm:"index;uniqueIndex:idx_scan_stage_derivation,priority:2"`
	Stage           string `gorm:"size:32;index;uniqueIndex:idx_scan_stage_derivation,priority:3"`
	Status          string `gorm:"size:24;index"`
	PlanHash        string `gorm:"size:64;index"`
	ObservationHash string `gorm:"size:64;index"`
	BatchID         string `gorm:"index"`
	AttemptID       string `gorm:"index"`
	ItemCount       int
	Summary         string `gorm:"type:jsonb;default:'{}'"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type CredentialDictionary struct {
	ID        string `gorm:"primaryKey"`
	TenantID  string `gorm:"default:'default';index;uniqueIndex:idx_credential_dictionary_name,priority:1"`
	ProjectID string `gorm:"index;uniqueIndex:idx_credential_dictionary_name,priority:2"`
	Kind      string `gorm:"size:16;index;uniqueIndex:idx_credential_dictionary_name,priority:3"`
	Name      string `gorm:"size:160;uniqueIndex:idx_credential_dictionary_name,priority:4"`
	CreatedBy string `gorm:"index"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

// CredentialDictionaryRevision is immutable. Ciphertext is encrypted with a
// purpose-specific Server key; only metadata leaves the Server.
type CredentialDictionaryRevision struct {
	ID           uint   `gorm:"primaryKey;autoIncrement"`
	TenantID     string `gorm:"default:'default';index"`
	ProjectID    string `gorm:"index"`
	DictionaryID string `gorm:"index;uniqueIndex:idx_credential_dictionary_revision,priority:1"`
	Revision     int    `gorm:"uniqueIndex:idx_credential_dictionary_revision,priority:2"`
	SHA256       string `gorm:"size:64;index"`
	ItemCount    int
	Ciphertext   []byte `gorm:"type:bytea"`
	Nonce        []byte `gorm:"type:bytea"`
	CreatedBy    string `gorm:"index"`
	CreatedAt    time.Time
}

// CredentialBundle is a short-lived one-time capability. Task configuration
// stores only Ref, SHA256 and PairCount.
type CredentialBundle struct {
	Ref        string `gorm:"primaryKey"`
	TenantID   string `gorm:"default:'default';index"`
	ProjectID  string `gorm:"index"`
	RootTaskID string `gorm:"index"`
	BatchID    string `gorm:"index"`
	AttemptID  string `gorm:"index"`
	AgentID    string `gorm:"index"`
	SHA256     string `gorm:"size:64;index"`
	PairCount  int
	Ciphertext []byte    `gorm:"type:bytea"`
	Nonce      []byte    `gorm:"type:bytea"`
	ExpiresAt  time.Time `gorm:"index"`
	ClaimedAt  *time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

// CredentialFindingSecret keeps successful credentials out of Vulnerability
// payloads. Viewer-facing result APIs can expose only MaskedUsername.
type CredentialFindingSecret struct {
	ID             string `gorm:"primaryKey"`
	TenantID       string `gorm:"default:'default';index"`
	ProjectID      string `gorm:"index"`
	RootTaskID     string `gorm:"index"`
	AttemptID      string `gorm:"index"`
	Endpoint       string `gorm:"index"`
	Service        string `gorm:"size:64;index"`
	Plugin         string `gorm:"size:128;index"`
	MaskedUsername string `gorm:"size:256"`
	Ciphertext     []byte `gorm:"type:bytea"`
	Nonce          []byte `gorm:"type:bytea"`
	CreatedAt      time.Time
}

type CredentialRevealAudit struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	TenantID  string    `gorm:"default:'default';index"`
	ProjectID string    `gorm:"index"`
	FindingID string    `gorm:"index"`
	ActorID   string    `gorm:"index"`
	Action    string    `gorm:"size:32;index"`
	CreatedAt time.Time `gorm:"index"`
}

// MarkAutomaticValidationStageDerived projects a newly appended validation
// Attempt back into the durable stage Intent. Legacy/manual batches without a
// semantic derivation are left unchanged.
func MarkAutomaticValidationStageDerived(tx *gorm.DB, root RootTask, batch TaskBatch, attemptID string) error {
	if tx == nil {
		return nil
	}
	stage := strings.ToLower(strings.TrimSpace(batch.Kind))
	column := ""
	switch stage {
	case "risk_validation":
		column = "risk_status"
	case "credential_validation":
		column = "credential_status"
	default:
		return nil
	}
	result := tx.Model(&ScanStageDerivation{}).
		Where("tenant_id = ? AND root_task_id = ? AND batch_id = ? AND stage = ?", root.TenantID, root.ID, batch.ID, stage).
		Updates(map[string]interface{}{"status": ScanStageIntentDerived, "attempt_id": attemptID})
	if result.Error != nil || result.RowsAffected == 0 {
		return result.Error
	}
	return tx.Model(&ScanPolicyIntent{}).
		Where("tenant_id = ? AND root_task_id = ?", root.TenantID, root.ID).
		Update(column, ScanStageIntentDerived).Error
}
