-- 存量库一次性切换：旧 010..570（无 510）增量链 → v001 新基线。
-- 前置条件（由 deploy/db-init.sh 检测）：schema_migrations 恰为旧终态版本集合。
-- 旧终态 schema 与 v001 基线的差异仅为下列废弃对象，故切换 = 清理废弃对象 + 重写版本记录。
BEGIN;

DROP VIEW IF EXISTS public.tenant_quota;

DROP TABLE IF EXISTS public.cron_tasks CASCADE;
DROP TABLE IF EXISTS public.notification_rules CASCADE;
DROP TABLE IF EXISTS public.asset_change_logs CASCADE;

ALTER TABLE public.root_tasks DROP COLUMN IF EXISTS cron_task_id;

DELETE FROM public.schema_migrations;
INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('001', 'init_baseline', 'psql-managed', now());

COMMIT;
