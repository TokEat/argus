package db

import "time"

// AssetDiscoveryNotebookItem is a tenant- and project-scoped normalized target
// retained from an asset discovery snapshot. It contains no provider query,
// credential, token, raw response, or expression data.
type AssetDiscoveryNotebookItem struct {
	ID               uint       `gorm:"primaryKey;autoIncrement"`
	TenantID         string     `gorm:"default:'default';index;uniqueIndex:idx_asset_discovery_notebook_items_target,priority:1"`
	ProjectID        string     `gorm:"index;uniqueIndex:idx_asset_discovery_notebook_items_target,priority:2"`
	NormalizedTarget string     `gorm:"type:text"`
	TargetHash       string     `gorm:"size:64;uniqueIndex:idx_asset_discovery_notebook_items_target,priority:3"`
	CreatedBy        string     `gorm:"index"`
	CreatedAt        time.Time  `gorm:"index"`
	UpdatedAt        time.Time  `gorm:"index"`
	UpdatedBy        string     `gorm:"index"`
	Note             string     `gorm:"type:text"`
	RemovedAt        *time.Time `gorm:"index"`
	RemovedBy        string     `gorm:"index"`
}

// AssetDiscoveryNotebookTag is deliberately project-scoped: equal labels in
// different projects are not shared authorization objects.
type AssetDiscoveryNotebookTag struct {
	ID        uint   `gorm:"primaryKey"`
	TenantID  string `gorm:"index;uniqueIndex:idx_adn_tag,priority:1"`
	ProjectID string `gorm:"index;uniqueIndex:idx_adn_tag,priority:2"`
	Name      string `gorm:"size:64;uniqueIndex:idx_adn_tag,priority:3"`
	CreatedAt time.Time
}
type AssetDiscoveryNotebookItemTag struct {
	ID             uint   `gorm:"primaryKey"`
	TenantID       string `gorm:"index;uniqueIndex:idx_adn_item_tag,priority:1"`
	ProjectID      string `gorm:"index;uniqueIndex:idx_adn_item_tag,priority:2"`
	NotebookItemID uint   `gorm:"index;uniqueIndex:idx_adn_item_tag,priority:3"`
	TagID          uint   `gorm:"index;uniqueIndex:idx_adn_item_tag,priority:4"`
	CreatedAt      time.Time
}

// AssetDiscoveryNotebookSource records the scoped snapshot evidence for a
// notebook item. Archive metadata is retained for auditability rather than
// deleting the source record.
type AssetDiscoveryNotebookSource struct {
	ID             uint      `gorm:"primaryKey;autoIncrement"`
	TenantID       string    `gorm:"default:'default';index;uniqueIndex:idx_asset_discovery_notebook_sources_snapshot_item,priority:1"`
	ProjectID      string    `gorm:"index;uniqueIndex:idx_asset_discovery_notebook_sources_snapshot_item,priority:2"`
	NotebookItemID uint      `gorm:"index"`
	SnapshotID     uint      `gorm:"index;uniqueIndex:idx_asset_discovery_notebook_sources_snapshot_item,priority:3"`
	SnapshotItemID uint      `gorm:"index;uniqueIndex:idx_asset_discovery_notebook_sources_snapshot_item,priority:4"`
	AuditID        uint      `gorm:"index"`
	ArchivedBy     string    `gorm:"index"`
	ArchivedAt     time.Time `gorm:"index"`
}
