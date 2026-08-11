CREATE TABLE IF NOT EXISTS asset_discovery_notebook_distribution_materializations (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    intent_id BIGINT NOT NULL,
    root_task_id TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    task_status VARCHAR(64) NOT NULL,
    batch_ids JSONB NOT NULL,
    attempt_ids JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_addm_ids CHECK (
        octet_length(tenant_id) BETWEEN 1 AND 1024
        AND octet_length(project_id) BETWEEN 1 AND 1024
        AND octet_length(root_task_id) BETWEEN 1 AND 1024
    ),
    CONSTRAINT chk_addm_status CHECK (status IN ('materialized', 'unchanged')),
    CONSTRAINT chk_addm_arrays CHECK (
        jsonb_typeof(batch_ids) = 'array'
        AND jsonb_typeof(attempt_ids) = 'array'
        AND jsonb_array_length(batch_ids) = jsonb_array_length(attempt_ids)
        AND jsonb_array_length(batch_ids) <= 100
        AND (status <> 'unchanged' OR jsonb_array_length(batch_ids) = 0)
    ),
    CONSTRAINT fk_addm_intent FOREIGN KEY (tenant_id, project_id, intent_id)
        REFERENCES asset_discovery_notebook_distribution_intents (tenant_id, project_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_addm_root_task FOREIGN KEY (tenant_id, project_id, root_task_id)
        REFERENCES root_tasks (tenant_id, project_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_addm_scope_id
    ON asset_discovery_notebook_distribution_materializations (tenant_id, project_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_addm_intent
    ON asset_discovery_notebook_distribution_materializations (tenant_id, project_id, intent_id);
CREATE INDEX IF NOT EXISTS idx_addm_task_created
    ON asset_discovery_notebook_distribution_materializations (tenant_id, project_id, root_task_id, created_at);
