CREATE TABLE IF NOT EXISTS active_fingerprint_rules (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    artifact_id TEXT,
    source_file TEXT NOT NULL,
    name TEXT NOT NULL,
    product_name TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    state TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    declared_auto_profile TEXT,
    computed_auto_profile TEXT NOT NULL,
    auto_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    max_requests INTEGER NOT NULL DEFAULT 1,
    classification_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_active_finger_rule_unique ON active_fingerprint_rules (tenant_id, source_file);
CREATE INDEX IF NOT EXISTS idx_active_fingerprint_rules_artifact_id ON active_fingerprint_rules (artifact_id);
CREATE INDEX IF NOT EXISTS idx_active_fingerprint_rules_product_name ON active_fingerprint_rules (product_name);
CREATE INDEX IF NOT EXISTS idx_active_fingerprint_rules_content_hash ON active_fingerprint_rules (content_hash);
CREATE INDEX IF NOT EXISTS idx_active_fingerprint_rules_state ON active_fingerprint_rules (state);
CREATE INDEX IF NOT EXISTS idx_active_fingerprint_rules_enabled ON active_fingerprint_rules (enabled);
CREATE INDEX IF NOT EXISTS idx_active_fingerprint_rules_auto_eligible ON active_fingerprint_rules (auto_eligible);
CREATE INDEX IF NOT EXISTS idx_active_fingerprint_rules_tenant_auto ON active_fingerprint_rules (tenant_id, enabled, auto_eligible, source_file);

ALTER TABLE rule_catalog_bootstraps ADD COLUMN IF NOT EXISTS active_finger_count INTEGER;
