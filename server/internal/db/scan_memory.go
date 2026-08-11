package db

import "time"

// ScanObservation is append-only execution evidence emitted by an Agent or
// the offline planner. Existing Asset/FingerprintHit/Vulnerability rows remain
// the materialized current-result views.
type ScanObservation struct {
	ID                  uint64    `gorm:"primaryKey;autoIncrement"`
	SchemaVersion       string    `gorm:"size:32"`
	TenantID            string    `gorm:"default:'default';index;index:idx_scan_observations_scope,priority:1;uniqueIndex:idx_scan_observations_tenant_event,priority:1,where:source_event_id IS NOT NULL"`
	ProjectID           string    `gorm:"index;index:idx_scan_observations_scope,priority:2"`
	NetworkZone         string    `gorm:"size:255;index:idx_scan_observations_scope,priority:3"`
	NormalizedTarget    string    `gorm:"type:text"`
	TargetHash          string    `gorm:"size:64;index"`
	Stage               string    `gorm:"size:64;index;index:idx_scan_observations_scope,priority:4"`
	WorkKeyHash         string    `gorm:"size:64;index"`
	ScopeHash           string    `gorm:"size:64"`
	ConfigHash          string    `gorm:"size:64"`
	RuleVersion         string    `gorm:"index"`
	POCSetHash          string    `gorm:"size:64"`
	EndpointContentHash string    `gorm:"size:64"`
	SourceEventID       *string   `gorm:"size:128;uniqueIndex:idx_scan_observations_tenant_event,priority:2,where:source_event_id IS NOT NULL"`
	RootTaskID          string    `gorm:"index"`
	BatchID             string    `gorm:"index"`
	AttemptID           string    `gorm:"index"`
	AgentID             string    `gorm:"index"`
	Outcome             string    `gorm:"size:32;index"`
	ContentHash         string    `gorm:"size:64"`
	Checkpoint          string    `gorm:"type:jsonb;default:'{}'"`
	CheckpointHash      string    `gorm:"size:64"`
	EvidenceHash        string    `gorm:"size:64"`
	ErrorCode           string    `gorm:"size:128"`
	ErrorMessage        string    `gorm:"type:text"`
	ObservedAt          time.Time `gorm:"index;index:idx_scan_observations_scope,priority:5,sort:desc"`
	CreatedAt           time.Time
}

// ScanCoverage is the latest reusable/non-reusable state for one canonical
// WorkKey. Its source observation remains immutable in ScanObservation.
type ScanCoverage struct {
	ID                  uint64 `gorm:"primaryKey;autoIncrement"`
	SchemaVersion       string `gorm:"size:32"`
	TenantID            string `gorm:"default:'default';index;uniqueIndex:idx_scan_coverages_tenant_project_work,priority:1;index:idx_scan_coverages_lookup,priority:1"`
	ProjectID           string `gorm:"index;uniqueIndex:idx_scan_coverages_tenant_project_work,priority:2;index:idx_scan_coverages_lookup,priority:2"`
	NetworkZone         string `gorm:"size:255;index:idx_scan_coverages_lookup,priority:3"`
	NormalizedTarget    string `gorm:"type:text"`
	TargetHash          string `gorm:"size:64;index:idx_scan_coverages_lookup,priority:4"`
	Stage               string `gorm:"size:64;index;index:idx_scan_coverages_lookup,priority:5"`
	WorkKeyHash         string `gorm:"size:64;uniqueIndex:idx_scan_coverages_tenant_project_work,priority:3"`
	ScopeHash           string `gorm:"size:64"`
	ConfigHash          string `gorm:"size:64"`
	RuleVersion         string `gorm:"index"`
	POCSetHash          string `gorm:"size:64"`
	EndpointContentHash string `gorm:"size:64"`
	Status              string `gorm:"size:32;index"`
	Outcome             string `gorm:"size:32;index"`
	StartedAt           time.Time
	FinishedAt          time.Time  `gorm:"index"`
	ValidUntil          *time.Time `gorm:"index"`
	ObservationHash     string     `gorm:"size:64"`
	SourceObservationID uint64     `gorm:"index"`
	SourceTaskID        string     `gorm:"index"`
	SourceBatchID       string     `gorm:"index"`
	SourceAttemptID     string     `gorm:"index"`
	Revision            int        `gorm:"default:1"`
	InvalidReason       string     `gorm:"type:text"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ScanWorkClaim serializes execution for one WorkKey. Claim ownership is
// committed atomically with the Attempt's Agent lease and recycled by revision
// after a terminal source releases it.
type ScanWorkClaim struct {
	ID                  uint64     `gorm:"primaryKey;autoIncrement"`
	SchemaVersion       string     `gorm:"size:32"`
	TenantID            string     `gorm:"default:'default';index;uniqueIndex:idx_scan_work_claims_tenant_project_work,priority:1"`
	ProjectID           string     `gorm:"index;uniqueIndex:idx_scan_work_claims_tenant_project_work,priority:2"`
	NetworkZone         string     `gorm:"size:255;index"`
	NormalizedTarget    string     `gorm:"type:text"`
	TargetHash          string     `gorm:"size:64;index"`
	Stage               string     `gorm:"size:64;index"`
	WorkKeyHash         string     `gorm:"size:64;uniqueIndex:idx_scan_work_claims_tenant_project_work,priority:3"`
	ScopeHash           string     `gorm:"size:64"`
	ConfigHash          string     `gorm:"size:64"`
	RuleVersion         string     `gorm:"index"`
	POCSetHash          string     `gorm:"size:64"`
	EndpointContentHash string     `gorm:"size:64"`
	Status              string     `gorm:"size:32;index"`
	OwnerTaskID         string     `gorm:"index"`
	OwnerBatchID        string     `gorm:"index"`
	OwnerAttemptID      string     `gorm:"index"`
	OwnerAgentID        string     `gorm:"index"`
	LeaseTokenHash      string     `gorm:"size:64"`
	LeaseExpiresAt      *time.Time `gorm:"index"`
	ClaimedAt           time.Time
	ReleasedAt          *time.Time
	Revision            int    `gorm:"default:1"`
	LastError           string `gorm:"type:text"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// TaskCoverageLink explains whether work for a destination Task/Batch/Attempt
// was executed, reused from history, or attached to another in-flight claim.
type TaskCoverageLink struct {
	ID              uint64 `gorm:"primaryKey;autoIncrement"`
	SchemaVersion   string `gorm:"size:32"`
	TenantID        string `gorm:"default:'default';index;uniqueIndex:idx_task_coverage_links_destination_work,priority:1"`
	ProjectID       string `gorm:"index;uniqueIndex:idx_task_coverage_links_destination_work,priority:2"`
	RootTaskID      string `gorm:"index;uniqueIndex:idx_task_coverage_links_destination_work,priority:3"`
	BatchID         string `gorm:"index;uniqueIndex:idx_task_coverage_links_destination_work,priority:4"`
	AttemptID       string `gorm:"index;uniqueIndex:idx_task_coverage_links_destination_work,priority:5"`
	WorkKeyHash     string `gorm:"size:64;index;uniqueIndex:idx_task_coverage_links_destination_work,priority:6"`
	LinkType        string `gorm:"size:32;index;uniqueIndex:idx_task_coverage_links_destination_work,priority:7"`
	Status          string `gorm:"size:32;index"`
	CoverageID      uint64 `gorm:"index"`
	ClaimID         uint64 `gorm:"index"`
	SourceTaskID    string `gorm:"index"`
	SourceBatchID   string `gorm:"index"`
	SourceAttemptID string `gorm:"index"`
	Reason          string `gorm:"type:text"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
