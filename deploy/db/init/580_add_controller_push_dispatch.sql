-- Controller-push dispatch: per-task dispatch strategy, exponential-retry
-- backoff, and controller routing metadata on sub_tasks; strategy inheritance
-- on root_tasks / task_batches. Empty dispatch_strategy means "inherit the
-- global default at read time" so upgrades never hard-flip existing rows.

ALTER TABLE sub_tasks
    ADD COLUMN IF NOT EXISTS dispatch_strategy VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS next_eligible_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS routed_agent_id VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS routed_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_sub_tasks_dispatch
    ON sub_tasks (status, dispatch_strategy, next_eligible_at);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_routed_agent
    ON sub_tasks (routed_agent_id, routed_at);

ALTER TABLE root_tasks
    ADD COLUMN IF NOT EXISTS dispatch_strategy VARCHAR(32) NOT NULL DEFAULT '';

ALTER TABLE task_batches
    ADD COLUMN IF NOT EXISTS dispatch_strategy VARCHAR(32) NOT NULL DEFAULT '';
