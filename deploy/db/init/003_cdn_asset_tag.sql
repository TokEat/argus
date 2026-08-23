--
-- Name: assets.cdn; Type: COLUMN; Schema: public; Owner: -
--
-- 疑似 CDN 资产标记。CDN-Domain 记录本身，以及来自被判定为 CDN 域名的
-- Web / Domain-Bind 探测结果置为 true；仅用于资产列表展示与过滤，
-- 不影响扫描行为，也绝不进入 vulnerabilities 表。
--

ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS cdn boolean NOT NULL DEFAULT false;


INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('003', 'cdn_asset_tag', 'psql-managed', now())
ON CONFLICT (version) DO NOTHING;
