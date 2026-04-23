-- 030_add_root_task_id.sql
-- Add root_task_id to result tables to maintain relation with root tasks even when task_id is overwritten by upserts

ALTER TABLE assets ADD COLUMN IF NOT EXISTS root_task_id TEXT;
CREATE INDEX IF NOT EXISTS idx_assets_root_task_id ON assets(root_task_id);

ALTER TABLE fingerprint_hits ADD COLUMN IF NOT EXISTS root_task_id TEXT;
CREATE INDEX IF NOT EXISTS idx_fingerprint_hits_root_task_id ON fingerprint_hits(root_task_id);

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS root_task_id TEXT;
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_root_task_id ON vulnerabilities(root_task_id);
