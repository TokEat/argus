CREATE TABLE IF NOT EXISTS task_retry_idempotencies (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(64) NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    operation VARCHAR(64) NOT NULL,
    idempotency_key_hash VARCHAR(64) NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    before_status VARCHAR(64) NOT NULL,
    after_status VARCHAR(64) NOT NULL,
    attempt_ids JSONB NOT NULL,
    completed_skipped INTEGER NOT NULL,
    paused_skipped INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_tri_ids CHECK (octet_length(tenant_id) BETWEEN 1 AND 1024 AND octet_length(project_id) BETWEEN 1 AND 1024 AND octet_length(root_task_id) BETWEEN 1 AND 1024 AND octet_length(operator_id) BETWEEN 1 AND 1024),
    CONSTRAINT chk_tri_schema_operation CHECK (octet_length(schema_version) BETWEEN 1 AND 64 AND octet_length(operation) BETWEEN 1 AND 64),
    CONSTRAINT chk_tri_hashes CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$' AND request_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_tri_statuses CHECK (octet_length(before_status) BETWEEN 1 AND 64 AND octet_length(after_status) BETWEEN 1 AND 64),
    CONSTRAINT chk_tri_attempt_ids CHECK (jsonb_typeof(attempt_ids) = 'array' AND jsonb_array_length(attempt_ids) >= 1),
    CONSTRAINT chk_tri_counts CHECK (completed_skipped >= 0 AND paused_skipped >= 0),
    CONSTRAINT fk_tri_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES root_tasks (tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tri_scope_id ON task_retry_idempotencies (tenant_id, project_id, root_task_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tri_idempotency ON task_retry_idempotencies (tenant_id, project_id, root_task_id, operator_id, operation, idempotency_key_hash);
CREATE INDEX IF NOT EXISTS idx_tri_task_created ON task_retry_idempotencies (tenant_id, project_id, root_task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_tri_operator_created ON task_retry_idempotencies (tenant_id, project_id, operator_id, created_at);
