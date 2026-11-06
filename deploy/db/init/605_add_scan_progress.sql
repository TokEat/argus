-- 细粒度扫描进度：agent 在扫描过程中实时上报当前阶段与活动计数，
-- 避免单个大批次内 root_tasks 进度长时间不前进（"卡在一个点"）。
-- 幂等：可重复执行。

ALTER TABLE sub_tasks
    ADD COLUMN IF NOT EXISTS progress_phase VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE sub_tasks
    ADD COLUMN IF NOT EXISTS progress_done INT NOT NULL DEFAULT 0;
ALTER TABLE sub_tasks
    ADD COLUMN IF NOT EXISTS progress_total INT NOT NULL DEFAULT 0;
ALTER TABLE sub_tasks
    ADD COLUMN IF NOT EXISTS progress_updated_at TIMESTAMPTZ;

ALTER TABLE root_tasks
    ADD COLUMN IF NOT EXISTS progress_done BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_sub_tasks_progress_updated
    ON sub_tasks (tenant_id, root_task_id, progress_updated_at);

INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('605', 'add_scan_progress', 'psql-managed', now())
ON CONFLICT (version) DO NOTHING;
