-- 路径前缀应用/隐藏端点发现：给 crawl_site_candidates 加 site_type 列。
-- 区分三类候选：''=端口/子域关联站点（既有行为）；'path_app'=按路径反代的独立应用；
-- 'hidden_path'=仅 JS 出现的隐藏端点（/api、/internal 等）。path_* 类确认后回流为
-- 带路径的资产 target（scheme://host:port/首段），见 promoteConfirmedCrawlSites。
ALTER TABLE crawl_site_candidates
    ADD COLUMN IF NOT EXISTS site_type TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_crawlsite_sitetype ON crawl_site_candidates (site_type);
