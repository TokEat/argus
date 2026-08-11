ALTER TABLE scan_observations
    ADD COLUMN IF NOT EXISTS checkpoint JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE scan_observations
    ADD COLUMN IF NOT EXISTS checkpoint_hash VARCHAR(64) NOT NULL DEFAULT '';
