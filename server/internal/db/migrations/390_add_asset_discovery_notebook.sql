CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_scope_id
    ON asset_discovery_snapshot_items (tenant_id, project_id, snapshot_id, id);

CREATE TABLE IF NOT EXISTS asset_discovery_notebook_items (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    normalized_target TEXT NOT NULL,
    target_hash VARCHAR(64) NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_asset_discovery_notebook_items_target
        CHECK (octet_length(normalized_target) BETWEEN 1 AND 8192),
    CONSTRAINT chk_asset_discovery_notebook_items_target_hash
        CHECK (char_length(target_hash) = 64)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_target
    ON asset_discovery_notebook_items (tenant_id, project_id, target_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_scope_id
    ON asset_discovery_notebook_items (tenant_id, project_id, id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_tenant_id
    ON asset_discovery_notebook_items (tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_project_id
    ON asset_discovery_notebook_items (project_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_created_by
    ON asset_discovery_notebook_items (created_by);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_created_at
    ON asset_discovery_notebook_items (created_at);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_updated_at
    ON asset_discovery_notebook_items (updated_at);

CREATE TABLE IF NOT EXISTS asset_discovery_notebook_sources (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    notebook_item_id BIGINT NOT NULL,
    snapshot_id BIGINT NOT NULL,
    snapshot_item_id BIGINT NOT NULL,
    audit_id BIGINT NOT NULL,
    archived_by TEXT NOT NULL,
    archived_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT chk_asset_discovery_notebook_sources_archive
        CHECK (octet_length(archived_by) BETWEEN 1 AND 1024),
    CONSTRAINT fk_asset_discovery_notebook_sources_item
        FOREIGN KEY (tenant_id, project_id, notebook_item_id)
        REFERENCES asset_discovery_notebook_items (tenant_id, project_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_asset_discovery_notebook_sources_snapshot_item
        FOREIGN KEY (tenant_id, project_id, snapshot_id, snapshot_item_id)
        REFERENCES asset_discovery_snapshot_items (tenant_id, project_id, snapshot_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_asset_discovery_notebook_sources_audit
        FOREIGN KEY (tenant_id, project_id, audit_id)
        REFERENCES asset_discovery_audits (tenant_id, project_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_discovery_notebook_sources_snapshot_item
    ON asset_discovery_notebook_sources (tenant_id, project_id, snapshot_id, snapshot_item_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_sources_tenant_id
    ON asset_discovery_notebook_sources (tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_sources_project_id
    ON asset_discovery_notebook_sources (project_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_sources_notebook_item_id
    ON asset_discovery_notebook_sources (notebook_item_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_sources_snapshot_id
    ON asset_discovery_notebook_sources (snapshot_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_sources_snapshot_item_id
    ON asset_discovery_notebook_sources (snapshot_item_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_sources_audit_id
    ON asset_discovery_notebook_sources (audit_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_sources_archived_by
    ON asset_discovery_notebook_sources (archived_by);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_sources_archived_at
    ON asset_discovery_notebook_sources (archived_at);
