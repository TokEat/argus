CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_discovery_audits_scope_id ON asset_discovery_audits (tenant_id, project_id, id);

CREATE TABLE IF NOT EXISTS asset_discovery_snapshots (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(64) NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    audit_id BIGINT NOT NULL,
    provider VARCHAR(32) NOT NULL,
    expression TEXT NOT NULL,
    query_hash VARCHAR(64) NOT NULL,
    config_version INTEGER NOT NULL DEFAULT 0,
    config_hash VARCHAR(64) NOT NULL DEFAULT '',
    requested_limit INTEGER NOT NULL DEFAULT 0,
    provider_total INTEGER NOT NULL DEFAULT 0,
    returned_count INTEGER NOT NULL DEFAULT 0,
    skipped_rows INTEGER NOT NULL DEFAULT 0,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_asset_discovery_snapshots_expression CHECK (octet_length(expression) BETWEEN 1 AND 4096),
    CONSTRAINT chk_asset_discovery_snapshots_counts CHECK (
        requested_limit >= 0 AND provider_total >= 0 AND returned_count >= 0 AND skipped_rows >= 0
    ),
    CONSTRAINT fk_asset_discovery_snapshots_audit FOREIGN KEY (tenant_id, project_id, audit_id)
        REFERENCES asset_discovery_audits (tenant_id, project_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_discovery_snapshots_audit_id ON asset_discovery_snapshots (audit_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshots_tenant_id ON asset_discovery_snapshots (tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshots_project_id ON asset_discovery_snapshots (project_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshots_provider ON asset_discovery_snapshots (provider);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshots_query_hash ON asset_discovery_snapshots (query_hash);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshots_created_by ON asset_discovery_snapshots (created_by);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshots_created_at ON asset_discovery_snapshots (created_at);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshots_project_created ON asset_discovery_snapshots (tenant_id, project_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_discovery_snapshots_scope_id ON asset_discovery_snapshots (tenant_id, project_id, id);

CREATE TABLE IF NOT EXISTS asset_discovery_snapshot_items (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    snapshot_id BIGINT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    normalized_target TEXT NOT NULL,
    target_hash VARCHAR(64) NOT NULL,
    ip VARCHAR(64) NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    domain VARCHAR(255) NOT NULL DEFAULT '',
    protocol VARCHAR(32) NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    icp TEXT NOT NULL DEFAULT '',
    country VARCHAR(128) NOT NULL DEFAULT '',
    city VARCHAR(128) NOT NULL DEFAULT '',
    company TEXT NOT NULL DEFAULT '',
    status_code INTEGER NOT NULL DEFAULT 0,
    source VARCHAR(32) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_asset_discovery_snapshot_items_target CHECK (octet_length(normalized_target) BETWEEN 1 AND 8192),
    CONSTRAINT chk_asset_discovery_snapshot_items_position CHECK (position >= 0),
    CONSTRAINT chk_asset_discovery_snapshot_items_port CHECK (port BETWEEN 0 AND 65535),
    CONSTRAINT chk_asset_discovery_snapshot_items_status_code CHECK (status_code BETWEEN 0 AND 999),
    CONSTRAINT fk_asset_discovery_snapshot_items_snapshot FOREIGN KEY (tenant_id, project_id, snapshot_id)
        REFERENCES asset_discovery_snapshots (tenant_id, project_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_target ON asset_discovery_snapshot_items (snapshot_id, target_hash);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_tenant_id ON asset_discovery_snapshot_items (tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_project_id ON asset_discovery_snapshot_items (project_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_snapshot_id ON asset_discovery_snapshot_items (snapshot_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_ip ON asset_discovery_snapshot_items (ip);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_domain ON asset_discovery_snapshot_items (domain);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_protocol ON asset_discovery_snapshot_items (protocol);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_source ON asset_discovery_snapshot_items (source);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_observed_at ON asset_discovery_snapshot_items (observed_at);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_project_snapshot ON asset_discovery_snapshot_items (tenant_id, project_id, snapshot_id, position);
