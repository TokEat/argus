ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS batch_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS attempt_no INTEGER NOT NULL DEFAULT 1;
ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS rule_version TEXT NOT NULL DEFAULT '';

UPDATE sub_tasks SET attempt_no = 1 WHERE attempt_no IS NULL OR attempt_no < 1;

CREATE TABLE IF NOT EXISTS task_batches (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'asset_scan',
    target_type TEXT NOT NULL DEFAULT 'legacy',
    targets TEXT NOT NULL DEFAULT '[]',
    target_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    config_version INTEGER NOT NULL DEFAULT 1,
    rule_version TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 1,
    timeout_sec INTEGER NOT NULL DEFAULT 0,
    agent_selector TEXT NOT NULL DEFAULT '{}',
    agent_selector_rules TEXT NOT NULL DEFAULT '{}',
    current_attempt_no INTEGER NOT NULL DEFAULT 1,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    latest_attempt_id TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_at TIMESTAMPTZ,
    CONSTRAINT idx_task_batches_task_sequence UNIQUE (root_task_id, sequence)
);

INSERT INTO task_batches (
    id, tenant_id, project_id, root_task_id, sequence, kind, target_type,
    targets, target_count, status, config_version, rule_version,
    priority, timeout_sec, agent_selector, agent_selector_rules,
    current_attempt_no, attempt_count, latest_attempt_id, created_by,
    created_at, updated_at, archived_at
)
SELECT
    st.id,
    st.tenant_id,
    st.project_id,
    st.root_task_id,
    ROW_NUMBER() OVER (PARTITION BY st.root_task_id ORDER BY st.created_at, st.id) - 1,
    'asset_scan',
    'legacy',
    COALESCE(NULLIF(st.chunk_targets, ''), '[]'),
    CASE WHEN jsonb_typeof(COALESCE(NULLIF(st.chunk_targets, ''), '[]')::jsonb) = 'array' THEN jsonb_array_length(COALESCE(NULLIF(st.chunk_targets, ''), '[]')::jsonb) ELSE 0 END,
    st.status,
    GREATEST(COALESCE(st.config_version, 1), 1),
    COALESCE(NULLIF(st.rule_version, ''), rt.rule_version, ''),
    st.priority,
    st.timeout_sec,
    COALESCE(NULLIF(st.agent_selector, ''), '{}'),
    COALESCE(NULLIF(st.agent_selector_rules, ''), '{}'),
    1,
    1,
    st.id,
    COALESCE(NULLIF(rt.user_id, ''), 'migration'),
    COALESCE(st.created_at, NOW()),
    COALESCE(st.updated_at, st.created_at, NOW()),
    rt.archived_at
FROM sub_tasks st
JOIN root_tasks rt ON rt.id = st.root_task_id AND rt.tenant_id = st.tenant_id
ON CONFLICT (id) DO NOTHING;

UPDATE sub_tasks SET batch_id = id WHERE batch_id IS NULL OR batch_id = '';

CREATE INDEX IF NOT EXISTS idx_sub_tasks_batch_id ON sub_tasks (batch_id);
CREATE INDEX IF NOT EXISTS idx_task_batches_tenant_id ON task_batches (tenant_id);
CREATE INDEX IF NOT EXISTS idx_task_batches_project_id ON task_batches (project_id);
CREATE INDEX IF NOT EXISTS idx_task_batches_root_task_id ON task_batches (root_task_id);
CREATE INDEX IF NOT EXISTS idx_task_batches_kind ON task_batches (kind);
CREATE INDEX IF NOT EXISTS idx_task_batches_target_type ON task_batches (target_type);
CREATE INDEX IF NOT EXISTS idx_task_batches_status ON task_batches (status);
CREATE INDEX IF NOT EXISTS idx_task_batches_latest_attempt_id ON task_batches (latest_attempt_id);
CREATE INDEX IF NOT EXISTS idx_task_batches_created_by ON task_batches (created_by);
CREATE INDEX IF NOT EXISTS idx_task_batches_archived_at ON task_batches (archived_at);
