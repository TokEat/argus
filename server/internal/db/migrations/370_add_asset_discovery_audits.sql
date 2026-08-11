CREATE TABLE IF NOT EXISTS asset_discovery_audits (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    provider VARCHAR(32) NOT NULL,
    action VARCHAR(64) NOT NULL,
    operator_id TEXT NOT NULL,
    query_hash VARCHAR(64) NOT NULL,
    config_version INTEGER NOT NULL DEFAULT 0,
    config_hash VARCHAR(64) NOT NULL DEFAULT '',
    requested_limit INTEGER NOT NULL DEFAULT 0,
    provider_total INTEGER NOT NULL DEFAULT 0,
    returned_count INTEGER NOT NULL DEFAULT 0,
    skipped_rows INTEGER NOT NULL DEFAULT 0,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL,
    error_code VARCHAR(64) NOT NULL DEFAULT '',
    duration_ms BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_tenant_id ON asset_discovery_audits (tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_project_id ON asset_discovery_audits (project_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_provider ON asset_discovery_audits (provider);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_action ON asset_discovery_audits (action);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_operator_id ON asset_discovery_audits (operator_id);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_query_hash ON asset_discovery_audits (query_hash);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_status ON asset_discovery_audits (status);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_error_code ON asset_discovery_audits (error_code);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_created_at ON asset_discovery_audits (created_at);
