BEGIN;

SET client_min_messages TO WARNING;
SET search_path TO public;

CREATE TABLE IF NOT EXISTS root_tasks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    user_id TEXT,
    name TEXT,
    original_targets TEXT,
    status TEXT,
    total_chunks INTEGER,
    completed_chunks INTEGER,
    config TEXT,
    priority INTEGER,
    timeout_sec INTEGER,
    rule_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sub_tasks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    root_task_id TEXT,
    chunk_targets TEXT,
    status TEXT,
    agent_id TEXT,
    config TEXT,
    stream_msg_id TEXT,
    priority INTEGER NOT NULL DEFAULT 1,
    agent_selector TEXT,
    timeout_sec INTEGER,
    retry_count INTEGER,
    max_retry INTEGER NOT NULL DEFAULT 3,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nodes (
    agent_id TEXT PRIMARY KEY,
    ip TEXT,
    status TEXT,
    token TEXT,
    tags TEXT,
    version TEXT,
    capacity INTEGER NOT NULL DEFAULT 1,
    running_tasks INTEGER NOT NULL DEFAULT 0,
    rule_version TEXT,
    last_beat BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    username TEXT,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'viewer',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS system_configs (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS assets (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    task_id TEXT,
    target TEXT,
    protocol TEXT,
    port INTEGER,
    url TEXT,
    title TEXT,
    service TEXT,
    cert_subject TEXT,
    cert_expiry TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fingerprint_hits (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    task_id TEXT,
    target TEXT,
    product_name TEXT,
    rule_name TEXT,
    evidence TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    task_id TEXT,
    target TEXT,
    plugin TEXT,
    severity TEXT,
    payload TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS arsenals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    type TEXT,
    file_name TEXT,
    content TEXT,
    hash TEXT,
    previous_hash TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'Draft',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_logs (
    id BIGSERIAL PRIMARY KEY,
    agent_id TEXT,
    level TEXT,
    message TEXT,
    timestamp BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rule_catalog_bootstraps (
    key TEXT PRIMARY KEY,
    schema_version INTEGER,
    source TEXT,
    status TEXT,
    aggregate_hash TEXT,
    arsenal_count INTEGER,
    fingerprint_count INTEGER,
    workflow_count INTEGER,
    dir_probe_count INTEGER,
    poc_count INTEGER,
    last_error TEXT,
    last_seeded_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fingerprint_rules (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    artifact_id TEXT,
    source_file TEXT,
    product_name TEXT NOT NULL,
    rule_expr TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'web',
    content_hash TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    state TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS poc_rules (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    artifact_id TEXT,
    source_file TEXT,
    name TEXT NOT NULL,
    content_hash TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    tags TEXT,
    author TEXT,
    description TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    state TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workflow_rules (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    artifact_id TEXT,
    source_file TEXT,
    product_name TEXT NOT NULL,
    poc_name TEXT NOT NULL,
    match_type TEXT NOT NULL,
    content_hash TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    state TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dir_rules (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    artifact_id TEXT,
    source_file TEXT,
    path TEXT NOT NULL,
    product_name TEXT NOT NULL,
    content_hash TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    state TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);

CREATE INDEX IF NOT EXISTS idx_root_tasks_tenant_id ON root_tasks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_root_tasks_user_id ON root_tasks (user_id);
CREATE INDEX IF NOT EXISTS idx_root_tasks_status ON root_tasks (status);

CREATE INDEX IF NOT EXISTS idx_sub_tasks_tenant_id ON sub_tasks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_root_task_id ON sub_tasks (root_task_id);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_status ON sub_tasks (status);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_agent_id ON sub_tasks (agent_id);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_priority ON sub_tasks (priority);

CREATE INDEX IF NOT EXISTS idx_assets_tenant_id ON assets (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_dedupe ON assets (task_id, target, protocol);

CREATE INDEX IF NOT EXISTS idx_fingerprint_hits_tenant_id ON fingerprint_hits (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fp_dedupe ON fingerprint_hits (task_id, target, product_name);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_tenant_id ON vulnerabilities (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_new_dedupe ON vulnerabilities (task_id, target, plugin);

CREATE INDEX IF NOT EXISTS idx_arsenals_tenant_id ON arsenals (tenant_id);
CREATE INDEX IF NOT EXISTS idx_arsenals_type ON arsenals (type);
CREATE INDEX IF NOT EXISTS idx_arsenals_file_name ON arsenals (file_name);
CREATE INDEX IF NOT EXISTS idx_arsenals_state ON arsenals (state);

CREATE INDEX IF NOT EXISTS idx_agent_logs_agent_id ON agent_logs (agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_logs_timestamp ON agent_logs (timestamp);

CREATE INDEX IF NOT EXISTS idx_rule_catalog_bootstraps_status ON rule_catalog_bootstraps (status);
CREATE INDEX IF NOT EXISTS idx_rule_catalog_bootstraps_aggregate_hash ON rule_catalog_bootstraps (aggregate_hash);

CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_tenant_id ON fingerprint_rules (tenant_id);
CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_artifact_id ON fingerprint_rules (artifact_id);
CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_source_file ON fingerprint_rules (source_file);
CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_product_name ON fingerprint_rules (product_name);
CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_category ON fingerprint_rules (category);
CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_content_hash ON fingerprint_rules (content_hash);
CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_state ON fingerprint_rules (state);
CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_enabled ON fingerprint_rules (enabled);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fp_rule_unique ON fingerprint_rules (tenant_id, product_name, rule_expr);

CREATE INDEX IF NOT EXISTS idx_poc_rules_tenant_id ON poc_rules (tenant_id);
CREATE INDEX IF NOT EXISTS idx_poc_rules_artifact_id ON poc_rules (artifact_id);
CREATE INDEX IF NOT EXISTS idx_poc_rules_source_file ON poc_rules (source_file);
CREATE INDEX IF NOT EXISTS idx_poc_rules_name ON poc_rules (name);
CREATE INDEX IF NOT EXISTS idx_poc_rules_content_hash ON poc_rules (content_hash);
CREATE INDEX IF NOT EXISTS idx_poc_rules_severity ON poc_rules (severity);
CREATE INDEX IF NOT EXISTS idx_poc_rules_state ON poc_rules (state);
CREATE INDEX IF NOT EXISTS idx_poc_rules_enabled ON poc_rules (enabled);
CREATE UNIQUE INDEX IF NOT EXISTS idx_poc_rule_unique ON poc_rules (tenant_id, source_file);

CREATE INDEX IF NOT EXISTS idx_workflow_rules_tenant_id ON workflow_rules (tenant_id);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_artifact_id ON workflow_rules (artifact_id);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_source_file ON workflow_rules (source_file);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_product_name ON workflow_rules (product_name);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_poc_name ON workflow_rules (poc_name);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_match_type ON workflow_rules (match_type);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_content_hash ON workflow_rules (content_hash);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_state ON workflow_rules (state);
CREATE INDEX IF NOT EXISTS idx_workflow_rules_enabled ON workflow_rules (enabled);
CREATE UNIQUE INDEX IF NOT EXISTS idx_workflow_rule_unique ON workflow_rules (tenant_id, product_name, poc_name, match_type);

CREATE INDEX IF NOT EXISTS idx_dir_rules_tenant_id ON dir_rules (tenant_id);
CREATE INDEX IF NOT EXISTS idx_dir_rules_artifact_id ON dir_rules (artifact_id);
CREATE INDEX IF NOT EXISTS idx_dir_rules_source_file ON dir_rules (source_file);
CREATE INDEX IF NOT EXISTS idx_dir_rules_path ON dir_rules (path);
CREATE INDEX IF NOT EXISTS idx_dir_rules_product_name ON dir_rules (product_name);
CREATE INDEX IF NOT EXISTS idx_dir_rules_content_hash ON dir_rules (content_hash);
CREATE INDEX IF NOT EXISTS idx_dir_rules_state ON dir_rules (state);
CREATE INDEX IF NOT EXISTS idx_dir_rules_enabled ON dir_rules (enabled);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dir_rule_unique ON dir_rules (tenant_id, path, product_name);

COMMIT;
