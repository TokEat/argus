ALTER TABLE root_tasks ADD COLUMN IF NOT EXISTS current_config_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS config_version INTEGER NOT NULL DEFAULT 1;

UPDATE root_tasks SET current_config_version = 1 WHERE current_config_version IS NULL OR current_config_version < 1;
UPDATE sub_tasks SET config_version = 1 WHERE config_version IS NULL OR config_version < 1;

CREATE TABLE IF NOT EXISTS task_config_revisions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',
    config_hash VARCHAR(64) NOT NULL,
    priority INTEGER NOT NULL DEFAULT 1,
    timeout_sec INTEGER NOT NULL DEFAULT 0,
    agent_selector TEXT NOT NULL DEFAULT '{}',
    agent_selector_rules TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT '',
    change_note TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT idx_task_config_revisions_task_version UNIQUE (root_task_id, version)
);

INSERT INTO task_config_revisions (
    tenant_id, project_id, root_task_id, version, config, config_hash,
    priority, timeout_sec, agent_selector, agent_selector_rules,
    created_by, change_note, created_at
)
SELECT
    rt.tenant_id,
    rt.project_id,
    rt.id,
    1,
    COALESCE(NULLIF(rt.config, ''), '{}'),
    encode(sha256(convert_to(
        COALESCE(NULLIF(rt.config, ''), '{}') || chr(31) ||
        COALESCE(rt.priority, 1)::text || chr(31) ||
        COALESCE(rt.timeout_sec, 0)::text || chr(31) ||
        COALESCE((SELECT (COALESCE(NULLIF(st.agent_selector, ''), '{}')::jsonb - 'target_type')::text FROM sub_tasks st WHERE st.root_task_id = rt.id AND st.tenant_id = rt.tenant_id ORDER BY st.created_at, st.id LIMIT 1), '{}') || chr(31) ||
        COALESCE((SELECT (COALESCE(NULLIF(st.agent_selector_rules, ''), '{}')::jsonb #- '{match,target_type}')::text FROM sub_tasks st WHERE st.root_task_id = rt.id AND st.tenant_id = rt.tenant_id ORDER BY st.created_at, st.id LIMIT 1), '{}'),
        'UTF8'
    )), 'hex'),
    COALESCE(rt.priority, 1),
    COALESCE(rt.timeout_sec, 0),
    COALESCE((SELECT (COALESCE(NULLIF(st.agent_selector, ''), '{}')::jsonb - 'target_type')::text FROM sub_tasks st WHERE st.root_task_id = rt.id AND st.tenant_id = rt.tenant_id ORDER BY st.created_at, st.id LIMIT 1), '{}'),
    COALESCE((SELECT (COALESCE(NULLIF(st.agent_selector_rules, ''), '{}')::jsonb #- '{match,target_type}')::text FROM sub_tasks st WHERE st.root_task_id = rt.id AND st.tenant_id = rt.tenant_id ORDER BY st.created_at, st.id LIMIT 1), '{}'),
    COALESCE(NULLIF(rt.user_id, ''), 'migration'),
    'backfilled from existing task',
    COALESCE(rt.created_at, NOW())
FROM root_tasks rt
ON CONFLICT (root_task_id, version) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_task_config_revisions_tenant_id ON task_config_revisions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_task_config_revisions_project_id ON task_config_revisions (project_id);
CREATE INDEX IF NOT EXISTS idx_task_config_revisions_root_task_id ON task_config_revisions (root_task_id);
CREATE INDEX IF NOT EXISTS idx_task_config_revisions_config_hash ON task_config_revisions (config_hash);
CREATE INDEX IF NOT EXISTS idx_task_config_revisions_created_by ON task_config_revisions (created_by);
