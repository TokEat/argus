package db

import "time"

const (
	ExpStatusDraft      = "draft"
	ExpStatusPublished  = "published"
	ExpStatusDeprecated = "deprecated"
)

// Exp is the tenant-scoped governance root. Source is stored only on immutable
// revisions; ActiveRevision is a pointer that can be rolled back safely.
type Exp struct {
	ID             string     `gorm:"size:36;primaryKey" json:"id"`
	TenantID       string     `gorm:"size:128;not null;uniqueIndex:idx_exps_tenant_name;index" json:"tenant_id"`
	Name           string     `gorm:"size:160;not null;uniqueIndex:idx_exps_tenant_name" json:"name"`
	Description    string     `gorm:"type:text" json:"description"`
	RiskLevel      string     `gorm:"size:24;not null" json:"risk_level"`
	Status         string     `gorm:"size:24;not null;index" json:"status"`
	ActiveRevision *int       `json:"active_revision,omitempty"`
	CreatedBy      string     `gorm:"size:128;not null;index" json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeprecatedAt   *time.Time `json:"deprecated_at,omitempty"`
}

// ExpRevision is immutable after creation. ObjectKey is never serialized by
// API handlers; callers receive the identity and verified source hash only.
type ExpRevision struct {
	ID              uint       `gorm:"primaryKey;autoIncrement" json:"-"`
	ExpID           string     `gorm:"size:36;not null;uniqueIndex:idx_exp_revision;index" json:"exp_id"`
	TenantID        string     `gorm:"size:128;not null;index" json:"tenant_id"`
	Revision        int        `gorm:"not null;uniqueIndex:idx_exp_revision" json:"revision"`
	Status          string     `gorm:"size:24;not null;index" json:"status"`
	SourceObjectKey string     `gorm:"size:768;not null" json:"-"`
	SourceSHA256    string     `gorm:"size:64;not null;index" json:"source_sha256"`
	SourceSize      int64      `gorm:"not null" json:"source_size"`
	CLISchema       string     `gorm:"type:jsonb;not null;default:'{}'" json:"cli_schema"`
	InspectSummary  string     `gorm:"type:jsonb;not null;default:'{}'" json:"inspect_summary"`
	ValidateSummary string     `gorm:"type:jsonb;not null;default:'{}'" json:"validate_summary"`
	TestsPassedAt   *time.Time `json:"tests_passed_at,omitempty"`
	TestCasesSHA256 string     `gorm:"size:64" json:"test_cases_sha256,omitempty"`
	CreatedBy       string     `gorm:"size:128;not null;index" json:"created_by"`
	PublishedBy     string     `gorm:"size:128" json:"published_by,omitempty"`
	PublishedAt     *time.Time `json:"published_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type ExpDependency struct {
	ID                 uint   `gorm:"primaryKey;autoIncrement" json:"-"`
	TenantID           string `gorm:"size:128;not null;index" json:"tenant_id"`
	ParentExpID        string `gorm:"size:36;not null;uniqueIndex:idx_exp_dependency" json:"parent_exp_id"`
	ParentRevision     int    `gorm:"not null;uniqueIndex:idx_exp_dependency" json:"parent_revision"`
	DependencyExpID    string `gorm:"size:36;not null;uniqueIndex:idx_exp_dependency" json:"dependency_exp_id"`
	DependencyRevision int    `gorm:"not null;uniqueIndex:idx_exp_dependency" json:"dependency_revision"`
	SourceSHA256       string `gorm:"size:64;not null" json:"source_sha256"`
}

type ExpAsset struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"-"`
	TenantID  string    `gorm:"size:128;not null;uniqueIndex:idx_exp_asset_identity;index" json:"tenant_id"`
	AssetID   string    `gorm:"size:128;not null;uniqueIndex:idx_exp_asset_identity" json:"asset_id"`
	Version   int       `gorm:"not null;uniqueIndex:idx_exp_asset_identity" json:"version"`
	ObjectKey string    `gorm:"size:768;not null" json:"-"`
	SHA256    string    `gorm:"size:64;not null;index" json:"sha256"`
	Size      int64     `gorm:"not null" json:"size"`
	MediaType string    `gorm:"size:160;not null" json:"media_type"`
	CreatedBy string    `gorm:"size:128;not null;index" json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type ExpAssetRef struct {
	ID           uint   `gorm:"primaryKey;autoIncrement" json:"-"`
	TenantID     string `gorm:"size:128;not null;index" json:"tenant_id"`
	ExpID        string `gorm:"size:36;not null;uniqueIndex:idx_exp_asset_ref" json:"exp_id"`
	Revision     int    `gorm:"not null;uniqueIndex:idx_exp_asset_ref" json:"revision"`
	AssetID      string `gorm:"size:128;not null;uniqueIndex:idx_exp_asset_ref" json:"asset_id"`
	AssetVersion int    `gorm:"not null" json:"asset_version"`
	SHA256       string `gorm:"size:64;not null" json:"sha256"`
}

type ExpTestCase struct {
	ID         string    `gorm:"size:36;primaryKey" json:"id"`
	TenantID   string    `gorm:"size:128;not null;index" json:"tenant_id"`
	ExpID      string    `gorm:"size:36;not null;index:idx_exp_test_case_revision" json:"exp_id"`
	Revision   int       `gorm:"not null;index:idx_exp_test_case_revision" json:"revision"`
	Name       string    `gorm:"size:160;not null" json:"name"`
	Params     string    `gorm:"type:jsonb;not null;default:'{}'" json:"params"`
	Fixtures   string    `gorm:"type:jsonb;not null;default:'[]'" json:"fixtures"`
	Assertions string    `gorm:"type:jsonb;not null;default:'[]'" json:"assertions"`
	Enabled    bool      `gorm:"not null;default:true" json:"enabled"`
	CreatedBy  string    `gorm:"size:128;not null" json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type ExpRun struct {
	ID                string     `gorm:"size:36;primaryKey" json:"id"`
	TenantID          string     `gorm:"size:128;not null;index" json:"tenant_id"`
	ExpID             string     `gorm:"size:36;not null;index" json:"exp_id"`
	Revision          int        `gorm:"not null" json:"revision"`
	SourceSHA256      string     `gorm:"size:64;not null" json:"source_sha256"`
	Action            string     `gorm:"size:16;not null;index" json:"action"`
	OperatorID        string     `gorm:"size:128;not null;index" json:"operator_id"`
	EgressMode        string     `gorm:"size:16;not null" json:"egress_mode"`
	AgentID           string     `gorm:"size:255;index" json:"agent_id,omitempty"`
	Status            string     `gorm:"size:32;not null;index" json:"status"`
	Provenance        string     `gorm:"size:32;not null" json:"provenance"`
	Attested          bool       `gorm:"not null;default:false" json:"attested"`
	ResultSummary     string     `gorm:"type:jsonb;not null;default:'{}'" json:"result_summary"`
	ArtifactObjectKey string     `gorm:"size:768" json:"-"`
	ArtifactSHA256    string     `gorm:"size:64" json:"artifact_sha256,omitempty"`
	ArtifactExpiresAt *time.Time `gorm:"index" json:"artifact_expires_at,omitempty"`
	ErrorCode         string     `gorm:"size:64" json:"error_code,omitempty"`
	StartedAt         time.Time  `gorm:"index" json:"started_at"`
	FinishedAt        *time.Time `gorm:"index" json:"finished_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

type ExpAudit struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID  string    `gorm:"size:128;not null;index" json:"tenant_id"`
	ExpID     string    `gorm:"size:36;not null;index" json:"exp_id"`
	Revision  int       `json:"revision,omitempty"`
	ActorID   string    `gorm:"size:128;not null;index" json:"actor_id"`
	Action    string    `gorm:"size:32;not null;index" json:"action"`
	Details   string    `gorm:"type:jsonb;not null;default:'{}'" json:"details"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}

type ExpRiskWaiver struct {
	ID        uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID  string     `gorm:"size:128;not null;uniqueIndex:idx_exp_risk_waiver" json:"tenant_id"`
	ExpID     string     `gorm:"size:36;not null;uniqueIndex:idx_exp_risk_waiver" json:"exp_id"`
	Reason    string     `gorm:"type:text;not null" json:"reason"`
	GrantedBy string     `gorm:"size:128;not null" json:"granted_by"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}
