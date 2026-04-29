CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    owner_user_id TEXT,
    name TEXT,
    description TEXT,
    tags JSONB,
    seed_targets JSONB,
    scope JSONB,
    default_config JSONB,
    node_affinity JSONB,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS project_members (
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE IF NOT EXISTS cron_tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    name TEXT,
    cron_expr TEXT,
    targets JSONB,
    config JSONB,
    next_run_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

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

CREATE TABLE IF NOT EXISTS domains (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT,
    name TEXT,
    task_id TEXT,
    tags JSONB,
    records JSONB,
    icp TEXT,
    whois JSONB,
    status TEXT NOT NULL DEFAULT 'alive',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    name TEXT,
    type TEXT,
    content TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
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

CREATE TABLE IF NOT EXISTS notification_rules (
    id BIGSERIAL PRIMARY KEY,
    project_id TEXT,
    event TEXT,
    channel TEXT,
    config JSONB,
    status TEXT NOT NULL DEFAULT 'enabled',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS asset_change_logs (
    id BIGSERIAL PRIMARY KEY,
    project_id TEXT,
    task_id TEXT,
    entity_type TEXT,
    entity_id BIGINT,
    change_type TEXT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    name TEXT,
    type TEXT,
    format TEXT,
    file_url TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_by TEXT,
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

ALTER TABLE root_tasks ADD COLUMN IF NOT EXISTS project_id TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS owner_user_id TEXT;
ALTER TABLE project_members ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE project_members ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE root_tasks ADD COLUMN IF NOT EXISTS cron_task_id TEXT;
ALTER TABLE root_tasks ADD COLUMN IF NOT EXISTS total_targets INTEGER NOT NULL DEFAULT 0;
ALTER TABLE root_tasks ADD COLUMN IF NOT EXISTS completed_targets INTEGER NOT NULL DEFAULT 0;
UPDATE root_tasks SET tenant_id = 'default' WHERE tenant_id IS NULL OR tenant_id = '';
UPDATE root_tasks SET project_id = 'default_project' WHERE project_id IS NULL OR project_id = '';
UPDATE root_tasks SET total_chunks = 0 WHERE total_chunks IS NULL;
UPDATE root_tasks SET completed_chunks = 0 WHERE completed_chunks IS NULL;
UPDATE root_tasks SET total_targets = 0 WHERE total_targets IS NULL;
UPDATE root_tasks SET completed_targets = 0 WHERE completed_targets IS NULL;
UPDATE root_tasks SET priority = 0 WHERE priority IS NULL;
UPDATE root_tasks SET timeout_sec = 0 WHERE timeout_sec IS NULL;

ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS project_id TEXT;
UPDATE sub_tasks SET tenant_id = 'default' WHERE tenant_id IS NULL OR tenant_id = '';
UPDATE sub_tasks SET project_id = 'default_project' WHERE project_id IS NULL OR project_id = '';
UPDATE sub_tasks SET priority = 1 WHERE priority IS NULL;
UPDATE sub_tasks SET retry_count = 0 WHERE retry_count IS NULL;
UPDATE sub_tasks SET max_retry = 3 WHERE max_retry IS NULL;
UPDATE sub_tasks SET timeout_sec = 0 WHERE timeout_sec IS NULL;

ALTER TABLE nodes ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS running_task_ids TEXT NOT NULL DEFAULT '[]';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS os TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS arch TEXT;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS cpu_usage REAL;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS mem_usage REAL;
UPDATE nodes SET tenant_id = 'default' WHERE tenant_id IS NULL OR tenant_id = '';
UPDATE nodes SET running_task_ids = '[]' WHERE running_task_ids IS NULL OR running_task_ids = '';
UPDATE nodes SET running_tasks = 0 WHERE running_tasks IS NULL;
UPDATE nodes SET capacity = 1 WHERE capacity IS NULL;

ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'viewer';
ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
UPDATE users SET tenant_id = 'default' WHERE tenant_id IS NULL OR tenant_id = '';
UPDATE users SET role = 'viewer' WHERE role IS NULL OR role = '';
UPDATE users SET status = 'active' WHERE status IS NULL OR status = '';

ALTER TABLE system_configs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE assets ADD COLUMN IF NOT EXISTS project_id TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS tags JSONB;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'alive';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner_id TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS cred_id TEXT;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
UPDATE assets SET tenant_id = 'default' WHERE tenant_id IS NULL OR tenant_id = '';
UPDATE assets SET project_id = 'default_project' WHERE project_id IS NULL OR project_id = '';
UPDATE assets SET status = 'alive' WHERE status IS NULL OR status = '';
UPDATE assets SET updated_at = created_at WHERE updated_at IS NULL;

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

ALTER TABLE fingerprint_hits ADD COLUMN IF NOT EXISTS project_id TEXT;
ALTER TABLE fingerprint_hits ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
UPDATE fingerprint_hits SET tenant_id = 'default' WHERE tenant_id IS NULL OR tenant_id = '';
UPDATE fingerprint_hits SET project_id = 'default_project' WHERE project_id IS NULL OR project_id = '';
UPDATE fingerprint_hits SET updated_at = created_at WHERE updated_at IS NULL;

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS project_id TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS assignee TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ignore_reason TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS verify_task_id TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS request TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS response TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS reference TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS matched_at TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
UPDATE vulnerabilities SET tenant_id = 'default' WHERE tenant_id IS NULL OR tenant_id = '';
UPDATE vulnerabilities SET project_id = 'default_project' WHERE project_id IS NULL OR project_id = '';
UPDATE vulnerabilities SET status = 'open' WHERE status IS NULL OR status = '';
UPDATE vulnerabilities SET updated_at = created_at WHERE updated_at IS NULL;

ALTER TABLE notification_rules ADD COLUMN IF NOT EXISTS config JSONB;
ALTER TABLE notification_rules ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'enabled';
ALTER TABLE notification_rules ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
UPDATE notification_rules SET status = 'enabled' WHERE status IS NULL OR status = '';

ALTER TABLE asset_change_logs ADD COLUMN IF NOT EXISTS details JSONB;
ALTER TABLE asset_change_logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE reports ADD COLUMN IF NOT EXISTS project_id TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS format TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS file_url TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE reports ADD COLUMN IF NOT EXISTS created_by TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
UPDATE reports SET status = 'pending' WHERE status IS NULL OR status = '';

ALTER TABLE arsenals ADD COLUMN IF NOT EXISTS previous_hash TEXT;
ALTER TABLE arsenals ADD COLUMN IF NOT EXISTS previous_content TEXT;
ALTER TABLE arsenals ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE arsenals ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
UPDATE arsenals SET tenant_id = 'default' WHERE tenant_id IS NULL OR tenant_id = '';
UPDATE arsenals SET version = 1 WHERE version IS NULL;
UPDATE arsenals SET state = 'Draft' WHERE state IS NULL OR state = '';

ALTER TABLE agent_logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

DROP INDEX IF EXISTS idx_asset_dedupe;
WITH ranked_assets AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY project_id, target, protocol
               ORDER BY COALESCE(updated_at, created_at) DESC, id DESC
           ) AS rn
    FROM assets
)
DELETE FROM assets a
USING ranked_assets r
WHERE a.id = r.id
  AND r.rn > 1;

DROP INDEX IF EXISTS idx_fp_dedupe;
WITH ranked_fingerprints AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY project_id, target, product_name
               ORDER BY COALESCE(updated_at, created_at) DESC, id DESC
           ) AS rn
    FROM fingerprint_hits
)
DELETE FROM fingerprint_hits f
USING ranked_fingerprints r
WHERE f.id = r.id
  AND r.rn > 1;

DROP INDEX IF EXISTS idx_vuln_new_dedupe;
WITH ranked_vulns AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY project_id, target, plugin
               ORDER BY COALESCE(updated_at, created_at) DESC, id DESC
           ) AS rn
    FROM vulnerabilities
)
DELETE FROM vulnerabilities v
USING ranked_vulns r
WHERE v.id = r.id
  AND r.rn > 1;

DROP INDEX IF EXISTS idx_domain_dedupe;
WITH ranked_domains AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY tenant_id, project_id, name
               ORDER BY COALESCE(updated_at, created_at) DESC, id DESC
           ) AS rn
    FROM domains
)
DELETE FROM domains d
USING ranked_domains r
WHERE d.id = r.id
  AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);

CREATE INDEX IF NOT EXISTS idx_projects_tenant_id ON projects (tenant_id);
CREATE INDEX IF NOT EXISTS idx_projects_name ON projects (name);
CREATE INDEX IF NOT EXISTS idx_projects_status ON projects (status);
CREATE INDEX IF NOT EXISTS idx_projects_deleted_at ON projects (deleted_at);

CREATE INDEX IF NOT EXISTS idx_cron_tasks_project_id ON cron_tasks (project_id);
CREATE INDEX IF NOT EXISTS idx_cron_tasks_cron_expr ON cron_tasks (cron_expr);
CREATE INDEX IF NOT EXISTS idx_cron_tasks_next_run_at ON cron_tasks (next_run_at);
CREATE INDEX IF NOT EXISTS idx_cron_tasks_status ON cron_tasks (status);
CREATE INDEX IF NOT EXISTS idx_cron_tasks_deleted_at ON cron_tasks (deleted_at);

CREATE INDEX IF NOT EXISTS idx_root_tasks_tenant_id ON root_tasks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_root_tasks_project_id ON root_tasks (project_id);
CREATE INDEX IF NOT EXISTS idx_root_tasks_cron_task_id ON root_tasks (cron_task_id);
CREATE INDEX IF NOT EXISTS idx_root_tasks_user_id ON root_tasks (user_id);
CREATE INDEX IF NOT EXISTS idx_root_tasks_status ON root_tasks (status);

CREATE INDEX IF NOT EXISTS idx_sub_tasks_tenant_id ON sub_tasks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_project_id ON sub_tasks (project_id);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_root_task_id ON sub_tasks (root_task_id);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_status ON sub_tasks (status);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_agent_id ON sub_tasks (agent_id);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_priority ON sub_tasks (priority);

CREATE INDEX IF NOT EXISTS idx_nodes_tenant_id ON nodes (tenant_id);

CREATE INDEX IF NOT EXISTS idx_assets_tenant_id ON assets (tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_task_id ON assets (task_id);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets (status);
CREATE INDEX IF NOT EXISTS idx_assets_owner_id ON assets (owner_id);
CREATE INDEX IF NOT EXISTS idx_assets_cred_id ON assets (cred_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_dedupe ON assets (project_id, target, protocol);

CREATE INDEX IF NOT EXISTS idx_credentials_project_id ON credentials (project_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials (type);
CREATE INDEX IF NOT EXISTS idx_credentials_deleted_at ON credentials (deleted_at);

CREATE INDEX IF NOT EXISTS idx_domains_task_id ON domains (task_id);
CREATE INDEX IF NOT EXISTS idx_domains_status ON domains (status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_dedupe ON domains (tenant_id, project_id, name);

CREATE INDEX IF NOT EXISTS idx_fingerprint_hits_tenant_id ON fingerprint_hits (tenant_id);
CREATE INDEX IF NOT EXISTS idx_fingerprint_hits_task_id ON fingerprint_hits (task_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fp_dedupe ON fingerprint_hits (project_id, target, product_name);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_tenant_id ON vulnerabilities (tenant_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_task_id ON vulnerabilities (task_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities (status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_assignee ON vulnerabilities (assignee);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_verify_task_id ON vulnerabilities (verify_task_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_new_dedupe ON vulnerabilities (project_id, target, plugin);

CREATE INDEX IF NOT EXISTS idx_notification_rules_project_id ON notification_rules (project_id);
CREATE INDEX IF NOT EXISTS idx_notification_rules_event ON notification_rules (event);

CREATE INDEX IF NOT EXISTS idx_asset_change_logs_project_id ON asset_change_logs (project_id);
CREATE INDEX IF NOT EXISTS idx_asset_change_logs_task_id ON asset_change_logs (task_id);
CREATE INDEX IF NOT EXISTS idx_asset_change_logs_entity_type ON asset_change_logs (entity_type);
CREATE INDEX IF NOT EXISTS idx_asset_change_logs_entity_id ON asset_change_logs (entity_id);
CREATE INDEX IF NOT EXISTS idx_asset_change_logs_change_type ON asset_change_logs (change_type);

CREATE INDEX IF NOT EXISTS idx_reports_project_id ON reports (project_id);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports (type);
CREATE INDEX IF NOT EXISTS idx_reports_created_by ON reports (created_by);

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
