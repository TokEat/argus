package db

import "time"

const AssetDiscoverySnapshotSchemaVersion = "argus.asset-discovery-snapshot/v1"

// AssetDiscoverySnapshot is one immutable, successful provider query owned by
// a tenant and project. Expression is project data used by the future query
// history module; it must never be copied into generic audit or application
// logs. Provider credentials and raw responses have no columns in this model.
type AssetDiscoverySnapshot struct {
	ID             uint   `gorm:"primaryKey;autoIncrement"`
	SchemaVersion  string `gorm:"size:64"`
	TenantID       string `gorm:"default:'default';index"`
	ProjectID      string `gorm:"index"`
	AuditID        uint   `gorm:"uniqueIndex"`
	Provider       string `gorm:"size:32;index"`
	Expression     string `gorm:"type:text"`
	QueryHash      string `gorm:"size:64;index"`
	ConfigVersion  int
	ConfigHash     string `gorm:"size:64"`
	RequestedLimit int
	ProviderTotal  int
	ReturnedCount  int
	SkippedRows    int
	Truncated      bool
	CreatedBy      string    `gorm:"index"`
	CreatedAt      time.Time `gorm:"index"`
}

// AssetDiscoverySnapshotItem is one normalized discovery candidate captured
// in a snapshot. TenantID and ProjectID are intentionally repeated so every
// future query can apply object boundaries without joining first.
type AssetDiscoverySnapshotItem struct {
	ID               uint   `gorm:"primaryKey;autoIncrement"`
	TenantID         string `gorm:"default:'default';index"`
	ProjectID        string `gorm:"index"`
	SnapshotID       uint   `gorm:"index;uniqueIndex:idx_asset_discovery_snapshot_items_target,priority:1"`
	Position         int
	NormalizedTarget string `gorm:"type:text"`
	TargetHash       string `gorm:"size:64;uniqueIndex:idx_asset_discovery_snapshot_items_target,priority:2"`
	IP               string `gorm:"size:64;index"`
	Port             int
	Domain           string `gorm:"size:255;index"`
	Protocol         string `gorm:"size:32;index"`
	Title            string `gorm:"type:text"`
	ICP              string `gorm:"type:text"`
	Country          string `gorm:"size:128"`
	City             string `gorm:"size:128"`
	Company          string `gorm:"type:text"`
	StatusCode       int
	Source           string    `gorm:"size:32;index"`
	ObservedAt       time.Time `gorm:"index"`
	CreatedAt        time.Time
}
