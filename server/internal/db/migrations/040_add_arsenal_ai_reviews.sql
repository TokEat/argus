CREATE TABLE IF NOT EXISTS arsenal_ai_reviews (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    type TEXT NOT NULL,
    file_name TEXT,
    content_hash TEXT NOT NULL,
    suggestion TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    summary TEXT,
    reason TEXT,
    issues JSONB,
    duplicate_candidates JSONB,
    raw_response JSONB,
    provider TEXT,
    model TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_arsenal_ai_reviews_tenant_id ON arsenal_ai_reviews (tenant_id);
CREATE INDEX IF NOT EXISTS idx_arsenal_ai_reviews_type ON arsenal_ai_reviews (type);
CREATE INDEX IF NOT EXISTS idx_arsenal_ai_reviews_file_name ON arsenal_ai_reviews (file_name);
CREATE INDEX IF NOT EXISTS idx_arsenal_ai_reviews_content_hash ON arsenal_ai_reviews (content_hash);
CREATE INDEX IF NOT EXISTS idx_arsenal_ai_reviews_suggestion ON arsenal_ai_reviews (suggestion);
CREATE INDEX IF NOT EXISTS idx_arsenal_ai_reviews_created_by ON arsenal_ai_reviews (created_by);
CREATE INDEX IF NOT EXISTS idx_arsenal_ai_reviews_cache ON arsenal_ai_reviews (tenant_id, type, content_hash, created_at DESC);

