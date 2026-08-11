ALTER TABLE root_tasks ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_root_tasks_archived_at ON root_tasks (archived_at);

CREATE TABLE IF NOT EXISTS task_audits (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    batch_id TEXT NOT NULL DEFAULT '',
    attempt_id TEXT NOT NULL DEFAULT '',
    operator_id TEXT NOT NULL,
    action TEXT NOT NULL,
    before_status TEXT NOT NULL DEFAULT '',
    after_status TEXT NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_task_audits_tenant_id ON task_audits (tenant_id);
CREATE INDEX IF NOT EXISTS idx_task_audits_project_id ON task_audits (project_id);
CREATE INDEX IF NOT EXISTS idx_task_audits_root_task_id ON task_audits (root_task_id);
CREATE INDEX IF NOT EXISTS idx_task_audits_batch_id ON task_audits (batch_id);
CREATE INDEX IF NOT EXISTS idx_task_audits_attempt_id ON task_audits (attempt_id);
CREATE INDEX IF NOT EXISTS idx_task_audits_operator_id ON task_audits (operator_id);
CREATE INDEX IF NOT EXISTS idx_task_audits_action ON task_audits (action);
CREATE INDEX IF NOT EXISTS idx_task_audits_created_at ON task_audits (created_at);
