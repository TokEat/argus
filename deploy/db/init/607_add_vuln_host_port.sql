-- 漏洞结果增强（Feature: host/port 过滤维度）：vulnerabilities 增加 host/port 两列，
-- 入库时从归一化 target 解析（AddResultAsync -> extractHostAndPort），用于按主机/端口精确过滤与 facet 多选。
-- 纯增量列，不参与 (project_id,target,plugin) dedupe 唯一键；历史行不回填（host=''/port=0，不参与新过滤），仅新扫描生效。
-- 幂等：可重复执行。

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS host TEXT NOT NULL DEFAULT '';
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS port INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host ON public.vulnerabilities USING btree (host);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_port ON public.vulnerabilities USING btree (port);

INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('607', 'add_vuln_host_port', 'psql-managed', now())
ON CONFLICT (version) DO NOTHING;
