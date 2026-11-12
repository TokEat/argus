package db

import "time"

// ExpEgressAudit contains only control-plane metadata. Raw TCP payloads and
// HTTP bodies are deliberately never persisted in this table.
type ExpEgressAudit struct {
	ID              uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	RouteID         string     `gorm:"size:64;uniqueIndex" json:"route_id"`
	TenantID        string     `gorm:"size:128;index" json:"tenant_id"`
	OperatorID      string     `gorm:"size:128;index" json:"operator_id"`
	AgentID         string     `gorm:"size:255;index" json:"agent_id"`
	Targets         string     `gorm:"type:jsonb" json:"targets"`
	ResolvedIPs     string     `gorm:"type:jsonb;default:'[]'" json:"resolved_ips"`
	Status          string     `gorm:"size:32;index" json:"status"`
	ErrorCode       string     `gorm:"size:64;index" json:"error_code,omitempty"`
	ConnectionCount int        `json:"connection_count"`
	BytesToAgent    int64      `json:"bytes_to_agent"`
	BytesFromAgent  int64      `json:"bytes_from_agent"`
	IssuedAt        time.Time  `gorm:"index" json:"issued_at"`
	ClaimedAt       *time.Time `json:"claimed_at,omitempty"`
	FinishedAt      *time.Time `gorm:"index" json:"finished_at,omitempty"`
	ExpiresAt       time.Time  `gorm:"index" json:"expires_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
