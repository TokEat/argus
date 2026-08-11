CREATE TABLE IF NOT EXISTS task_append_idempotencies (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(64) NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    operation VARCHAR(64) NOT NULL,
    idempotency_key_hash VARCHAR(64) NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    outcome VARCHAR(16) NOT NULL,
    config_version INTEGER NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    rule_version TEXT NOT NULL,
    before_status VARCHAR(64) NOT NULL,
    after_status VARCHAR(64) NOT NULL,
    batch_ids JSONB NOT NULL,
    attempt_ids JSONB NOT NULL,
    requested_targets INTEGER NOT NULL,
    new_targets INTEGER NOT NULL,
    duplicate_targets INTEGER NOT NULL,
    project_scope_added INTEGER NOT NULL,
    project_seeds_added INTEGER NOT NULL,
    total_chunks INTEGER NOT NULL,
    total_targets INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_tai_ids CHECK (octet_length(tenant_id) BETWEEN 1 AND 1024 AND octet_length(project_id) BETWEEN 1 AND 1024 AND octet_length(root_task_id) BETWEEN 1 AND 1024 AND octet_length(operator_id) BETWEEN 1 AND 1024),
    CONSTRAINT chk_tai_schema_operation CHECK (octet_length(schema_version) BETWEEN 1 AND 64 AND octet_length(operation) BETWEEN 1 AND 64),
    CONSTRAINT chk_tai_hashes CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$' AND request_hash ~ '^[0-9a-f]{64}$' AND config_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_tai_outcome CHECK (outcome IN ('appended', 'unchanged')),
    CONSTRAINT chk_tai_statuses CHECK (octet_length(before_status) BETWEEN 1 AND 64 AND octet_length(after_status) BETWEEN 1 AND 64 AND octet_length(rule_version) BETWEEN 1 AND 1024),
    CONSTRAINT chk_tai_ids_json CHECK (jsonb_typeof(batch_ids) = 'array' AND jsonb_typeof(attempt_ids) = 'array'),
    CONSTRAINT chk_tai_counts CHECK (config_version > 0 AND requested_targets >= 0 AND new_targets >= 0 AND duplicate_targets >= 0 AND requested_targets = new_targets + duplicate_targets AND project_scope_added >= 0 AND project_seeds_added >= 0 AND total_chunks >= 0 AND total_targets >= 0),
    CONSTRAINT chk_tai_outcome_ids CHECK ((outcome = 'unchanged' AND new_targets = 0 AND jsonb_array_length(batch_ids) = 0 AND jsonb_array_length(attempt_ids) = 0) OR (outcome = 'appended' AND new_targets > 0 AND jsonb_array_length(batch_ids) > 0 AND jsonb_array_length(batch_ids) = jsonb_array_length(attempt_ids))),
    CONSTRAINT fk_tai_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES root_tasks (tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tai_scope_id ON task_append_idempotencies (tenant_id, project_id, root_task_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tai_idempotency ON task_append_idempotencies (tenant_id, project_id, root_task_id, operator_id, operation, idempotency_key_hash);
CREATE INDEX IF NOT EXISTS idx_tai_task_created ON task_append_idempotencies (tenant_id, project_id, root_task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_tai_operator_created ON task_append_idempotencies (tenant_id, project_id, operator_id, created_at);
