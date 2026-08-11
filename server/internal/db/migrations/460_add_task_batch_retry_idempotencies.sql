CREATE TABLE IF NOT EXISTS task_batch_retry_idempotencies (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(64) NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    operation VARCHAR(64) NOT NULL,
    idempotency_key_hash VARCHAR(64) NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    attempt_id TEXT NOT NULL,
    attempt_no INTEGER NOT NULL,
    config_version INTEGER NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    rule_version TEXT NOT NULL,
    before_status VARCHAR(64) NOT NULL,
    after_status VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_tbri_ids CHECK (octet_length(tenant_id) BETWEEN 1 AND 1024 AND octet_length(project_id) BETWEEN 1 AND 1024 AND octet_length(root_task_id) BETWEEN 1 AND 1024 AND octet_length(batch_id) BETWEEN 1 AND 1024 AND octet_length(operator_id) BETWEEN 1 AND 1024 AND octet_length(attempt_id) BETWEEN 1 AND 1024),
    CONSTRAINT chk_tbri_schema_operation CHECK (octet_length(schema_version) BETWEEN 1 AND 64 AND octet_length(operation) BETWEEN 1 AND 64),
    CONSTRAINT chk_tbri_hashes CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$' AND request_hash ~ '^[0-9a-f]{64}$' AND config_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_tbri_outcome CHECK (attempt_no >= 1 AND config_version >= 1 AND octet_length(rule_version) BETWEEN 1 AND 1024 AND octet_length(before_status) BETWEEN 1 AND 64 AND octet_length(after_status) BETWEEN 1 AND 64),
    CONSTRAINT fk_tbri_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES root_tasks (tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_tbri_batch FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id) REFERENCES task_batches (tenant_id, project_id, root_task_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT fk_tbri_attempt FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id, attempt_id) REFERENCES sub_tasks (tenant_id, project_id, root_task_id, batch_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tbri_scope_id ON task_batch_retry_idempotencies (tenant_id, project_id, root_task_id, batch_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tbri_idempotency ON task_batch_retry_idempotencies (tenant_id, project_id, root_task_id, batch_id, operator_id, operation, idempotency_key_hash);
CREATE INDEX IF NOT EXISTS idx_tbri_batch_created ON task_batch_retry_idempotencies (tenant_id, project_id, root_task_id, batch_id, created_at);
CREATE INDEX IF NOT EXISTS idx_tbri_operator_created ON task_batch_retry_idempotencies (tenant_id, project_id, operator_id, created_at);
