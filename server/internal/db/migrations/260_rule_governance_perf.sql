-- 260_rule_governance_perf.sql
-- Performance indexes and materialized workflow relationship summary for
-- arsenal governance pages and MCP context reads.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE UNIQUE INDEX IF NOT EXISTS idx_arsenals_tenant_type_file
    ON arsenals (tenant_id, type, file_name);
CREATE INDEX IF NOT EXISTS idx_arsenals_tenant_type_state_updated
    ON arsenals (tenant_id, type, state, updated_at DESC, id);

CREATE INDEX IF NOT EXISTS idx_poc_rules_tenant_enabled_updated
    ON poc_rules (tenant_id, enabled, updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_poc_rules_tenant_severity_updated
    ON poc_rules (tenant_id, severity, updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_poc_rules_tenant_compat_updated
    ON poc_rules (tenant_id, compatibility_status, updated_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_tenant_enabled_product
    ON fingerprint_rules (tenant_id, enabled, product_name);
CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_tenant_state_product
    ON fingerprint_rules (tenant_id, state, product_name);

CREATE INDEX IF NOT EXISTS idx_workflow_rules_tenant_enabled_product
    ON workflow_rules (tenant_id, enabled, product_name);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_tenant_poc
    ON workflow_rules (tenant_id, poc_name);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_tenant_state_product
    ON workflow_rules (tenant_id, state, product_name);

CREATE INDEX IF NOT EXISTS idx_exploit_rules_tenant_enabled_updated
    ON exploit_rules (tenant_id, enabled, updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_exploit_rules_tenant_state_updated
    ON exploit_rules (tenant_id, state, updated_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_product_trgm
    ON fingerprint_rules USING gin (product_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_poc_rules_name_trgm
    ON poc_rules USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_poc_rules_source_file_trgm
    ON poc_rules USING gin (source_file gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_poc_rules_target_product_trgm
    ON poc_rules USING gin (target_product gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_poc_rules_cve_trgm
    ON poc_rules USING gin (cve gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_poc_rules_tags_trgm
    ON poc_rules USING gin (tags gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_product_trgm
    ON workflow_rules USING gin (product_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_poc_trgm
    ON workflow_rules USING gin (poc_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_exploit_rules_rule_id_trgm
    ON exploit_rules USING gin (rule_id gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_exploit_rules_name_trgm
    ON exploit_rules USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_exploit_rules_source_file_trgm
    ON exploit_rules USING gin (source_file gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_exploit_rules_target_product_trgm
    ON exploit_rules USING gin (target_product gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_exploit_rules_cve_trgm
    ON exploit_rules USING gin (cve gin_trgm_ops);

CREATE TABLE IF NOT EXISTS workflow_product_summaries (
    tenant_id TEXT NOT NULL DEFAULT 'default',
    product_name TEXT NOT NULL,
    is_general_poc BOOLEAN NOT NULL DEFAULT FALSE,
    match_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    poc_names JSONB NOT NULL DEFAULT '[]'::jsonb,
    poc_count INTEGER NOT NULL DEFAULT 0,
    missing_poc_names JSONB NOT NULL DEFAULT '[]'::jsonb,
    missing_poc_count INTEGER NOT NULL DEFAULT 0,
    fingerprint_bound BOOLEAN NOT NULL DEFAULT FALSE,
    fingerprint_rule_count INTEGER NOT NULL DEFAULT 0,
    state TEXT,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    content_hash TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, product_name)
);

CREATE INDEX IF NOT EXISTS idx_workflow_product_summaries_tenant_general
    ON workflow_product_summaries (tenant_id, is_general_poc, product_name);
CREATE INDEX IF NOT EXISTS idx_workflow_product_summaries_tenant_health
    ON workflow_product_summaries (tenant_id, fingerprint_bound, missing_poc_count, product_name);
CREATE INDEX IF NOT EXISTS idx_workflow_product_summaries_tenant_enabled
    ON workflow_product_summaries (tenant_id, enabled, product_name);
CREATE INDEX IF NOT EXISTS idx_workflow_product_summaries_product_trgm
    ON workflow_product_summaries USING gin (product_name gin_trgm_ops);
