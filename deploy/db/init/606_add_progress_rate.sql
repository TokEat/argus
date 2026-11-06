-- 细粒度进度扩展：单元模式（x/y 占比 + 吞吐 + ETA）。
-- Agent 引擎对端口扫描、协议识别等阶段按「已处理单元/总单元」上报（done/total 同口径），
-- 并携带吞吐 rate（单元/秒）与预计剩余 eta_ms；发现模式阶段二者为 0（仅活跃信号）。
-- 幂等：可重复执行。

ALTER TABLE sub_tasks
    ADD COLUMN IF NOT EXISTS progress_rate DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE sub_tasks
    ADD COLUMN IF NOT EXISTS progress_eta_ms BIGINT NOT NULL DEFAULT 0;

-- root 层聚合各运行中子任务吞吐之和 = 任务总吞吐（活动信号，非完成度）。
ALTER TABLE root_tasks
    ADD COLUMN IF NOT EXISTS progress_rate DOUBLE PRECISION NOT NULL DEFAULT 0;

INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('606', 'add_progress_rate', 'psql-managed', now())
ON CONFLICT (version) DO NOTHING;
