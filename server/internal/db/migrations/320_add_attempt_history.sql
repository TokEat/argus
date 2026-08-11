ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS parent_attempt_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS trigger TEXT NOT NULL DEFAULT 'initial';
ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS failure_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ;

UPDATE sub_tasks
SET trigger = CASE WHEN attempt_no > 1 THEN 'legacy_retry' ELSE 'initial' END
WHERE trigger IS NULL OR trigger = '';

UPDATE sub_tasks
SET started_at = created_at
WHERE started_at IS NULL
  AND UPPER(status) IN ('RUNNING', 'DONE', 'FINISHED', 'COMPLETED', 'SUCCESS', 'SUCCEEDED', 'FAILED', 'ERROR', 'TIMEOUT', 'CANCELLED', 'CANCELED');

UPDATE sub_tasks
SET finished_at = COALESCE(updated_at, created_at, NOW())
WHERE finished_at IS NULL
  AND UPPER(status) IN ('DONE', 'FINISHED', 'COMPLETED', 'SUCCESS', 'SUCCEEDED', 'FAILED', 'ERROR', 'TIMEOUT', 'CANCELLED', 'CANCELED');

UPDATE sub_tasks
SET failure_reason = CASE
    WHEN UPPER(status) IN ('FAILED', 'ERROR') THEN 'legacy attempt failed'
    WHEN UPPER(status) = 'TIMEOUT' THEN 'legacy attempt timed out'
    WHEN UPPER(status) IN ('CANCELLED', 'CANCELED') THEN 'legacy attempt cancelled'
    ELSE failure_reason
END
WHERE failure_reason IS NULL OR failure_reason = '';

CREATE INDEX IF NOT EXISTS idx_sub_tasks_parent_attempt_id ON sub_tasks (parent_attempt_id);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_trigger ON sub_tasks (trigger);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_started_at ON sub_tasks (started_at);
CREATE INDEX IF NOT EXISTS idx_sub_tasks_finished_at ON sub_tasks (finished_at);
