-- 主动页面爬取（WebCrawl）+ 敏感信息收集（SensitiveInfo）两张候选结果表。
-- Agent 在严格同 host:port 范围内爬取页面/JS，hash 去重后提取两类候选上报；
-- ai_control=false 时直接确认为 confirmed，=true 时进入服务端 AI Worker 研判。

-- 关联资产候选：页面/JS 中提取的"同主机不同站点"（跨端口 / 同主域子域）链接。
-- 候选站点本身未被抓取，由 AI/规则判定是否值得收录为资产（asset_promoted 标记回流）。
CREATE TABLE IF NOT EXISTS crawl_site_candidates (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL DEFAULT '',
    task_id TEXT NOT NULL DEFAULT '',
    root_task_id TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',     -- 发现该链接的页面 URL
    url TEXT NOT NULL DEFAULT '',
    scheme TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    link_context TEXT NOT NULL DEFAULT '',
    dedupe_hash TEXT NOT NULL,               -- sha256(project_id|url)
    ai_control BOOLEAN NOT NULL DEFAULT FALSE,
    ai_status TEXT NOT NULL DEFAULT 'pending', -- pending | confirmed | duplicate | rejected
    ai_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    ai_reason TEXT NOT NULL DEFAULT '',
    asset_promoted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_crawlsite_dedupe ON crawl_site_candidates (dedupe_hash);
CREATE INDEX IF NOT EXISTS idx_crawlsite_project ON crawl_site_candidates (project_id);
CREATE INDEX IF NOT EXISTS idx_crawlsite_task ON crawl_site_candidates (task_id);
CREATE INDEX IF NOT EXISTS idx_crawlsite_root_task ON crawl_site_candidates (root_task_id);
CREATE INDEX IF NOT EXISTS idx_crawlsite_host ON crawl_site_candidates (host);
CREATE INDEX IF NOT EXISTS idx_crawlsite_status ON crawl_site_candidates (ai_status);

-- 敏感信息候选：页面/JS 中提取的可用于钓鱼暴露面分析的敏感信息（邮箱/电话/身份证/账号/keyword）。
CREATE TABLE IF NOT EXISTS sensitive_findings (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL DEFAULT '',
    task_id TEXT NOT NULL DEFAULT '',
    root_task_id TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT '',           -- email | phone | idcard | account | keyword | custom
    value TEXT NOT NULL DEFAULT '',
    snippet TEXT NOT NULL DEFAULT '',
    context TEXT NOT NULL DEFAULT '',        -- AI 结构化提取结果（jsonb 文本）
    dedupe_hash TEXT NOT NULL,               -- sha256(project_id|host|kind|value)
    ai_control BOOLEAN NOT NULL DEFAULT FALSE,
    ai_status TEXT NOT NULL DEFAULT 'pending',
    ai_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    ai_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sensitive_dedupe ON sensitive_findings (dedupe_hash);
CREATE INDEX IF NOT EXISTS idx_sensitive_project ON sensitive_findings (project_id);
CREATE INDEX IF NOT EXISTS idx_sensitive_task ON sensitive_findings (task_id);
CREATE INDEX IF NOT EXISTS idx_sensitive_root_task ON sensitive_findings (root_task_id);
CREATE INDEX IF NOT EXISTS idx_sensitive_host ON sensitive_findings (host);
CREATE INDEX IF NOT EXISTS idx_sensitive_kind ON sensitive_findings (kind);
CREATE INDEX IF NOT EXISTS idx_sensitive_status ON sensitive_findings (ai_status);
