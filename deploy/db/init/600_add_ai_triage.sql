ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_status text NOT NULL DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_confidence double precision NOT NULL DEFAULT 0;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_reason text NOT NULL DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_triaged_at timestamp with time zone;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS ai_review_id bigint;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_ai_status ON vulnerabilities (ai_status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_ai_triaged_at ON vulnerabilities (ai_triaged_at);

CREATE TABLE IF NOT EXISTS ai_finding_reviews (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    vulnerability_id BIGINT NOT NULL,
    root_task_id TEXT,
    project_id TEXT,
    plugin TEXT,
    severity TEXT,
    target TEXT,
    evidence_hash TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    reason TEXT,
    raw_response TEXT,
    provider TEXT,
    model TEXT,
    overridden_by TEXT,
    override_verdict TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_finding_reviews_vuln ON ai_finding_reviews (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_ai_finding_reviews_evidence ON ai_finding_reviews (evidence_hash);
CREATE INDEX IF NOT EXISTS idx_ai_finding_reviews_verdict ON ai_finding_reviews (verdict);
