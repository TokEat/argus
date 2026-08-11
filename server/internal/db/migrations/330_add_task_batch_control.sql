ALTER TABLE task_batches
    ADD COLUMN IF NOT EXISTS control_state TEXT NOT NULL DEFAULT 'active';

UPDATE task_batches
SET control_state = 'active'
WHERE control_state IS NULL OR BTRIM(control_state) = '';

CREATE INDEX IF NOT EXISTS idx_task_batches_control_state
    ON task_batches (control_state);
