CREATE UNIQUE INDEX IF NOT EXISTS idx_task_batches_scope_id
    ON task_batches (tenant_id, project_id, root_task_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_tasks_scope_attempt_id
    ON sub_tasks (tenant_id, project_id, root_task_id, batch_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_tasks_scope_attempt_agent_id
    ON sub_tasks (tenant_id, project_id, root_task_id, batch_id, id, agent_id);

CREATE TABLE IF NOT EXISTS scan_timing_events (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(64) NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    kind VARCHAR(32) NOT NULL,
    stage VARCHAR(64) NOT NULL DEFAULT '',
    outcome VARCHAR(32) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    duration_ns BIGINT NOT NULL,
    config_version INTEGER NOT NULL,
    rule_version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_scan_timing_event_ids CHECK (
        octet_length(tenant_id) BETWEEN 1 AND 1024
        AND octet_length(project_id) BETWEEN 1 AND 1024
        AND octet_length(root_task_id) BETWEEN 1 AND 1024
        AND octet_length(batch_id) BETWEEN 1 AND 1024
        AND octet_length(attempt_id) BETWEEN 1 AND 1024
        AND octet_length(agent_id) BETWEEN 1 AND 1024
        AND source_event_id ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_scan_timing_event_contract CHECK (
        schema_version = 'argus.timing/v1'
        AND kind IN ('process_startup', 'rule_prepare', 'context_init', 'stage')
        AND outcome IN ('success', 'negative', 'failed', 'skipped')
        AND ((kind = 'stage' AND octet_length(stage) BETWEEN 1 AND 64) OR (kind <> 'stage' AND stage = ''))
        AND config_version >= 1
        AND octet_length(rule_version) BETWEEN 1 AND 8192
    ),
    CONSTRAINT chk_scan_timing_event_interval CHECK (
        duration_ns >= 0 AND duration_ns <= 86400000000000
        AND finished_at >= started_at
        AND finished_at - started_at <= INTERVAL '24 hours'
    ),
    CONSTRAINT fk_scan_timing_event_root FOREIGN KEY (tenant_id, project_id, root_task_id)
        REFERENCES root_tasks (tenant_id, project_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_scan_timing_event_batch FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id)
        REFERENCES task_batches (tenant_id, project_id, root_task_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_scan_timing_event_attempt FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id, attempt_id)
        REFERENCES sub_tasks (tenant_id, project_id, root_task_id, batch_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_scan_timing_event_attempt_agent FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id, attempt_id, agent_id)
        REFERENCES sub_tasks (tenant_id, project_id, root_task_id, batch_id, id, agent_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_timing_events_tenant_source_event
    ON scan_timing_events (tenant_id, source_event_id);
CREATE INDEX IF NOT EXISTS idx_scan_timing_events_scope_created
    ON scan_timing_events (tenant_id, project_id, root_task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scan_timing_events_attempt_created
    ON scan_timing_events (tenant_id, project_id, root_task_id, attempt_id, created_at);
