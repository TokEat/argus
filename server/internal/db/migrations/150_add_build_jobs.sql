CREATE TABLE IF NOT EXISTS build_jobs (
    id BIGSERIAL PRIMARY KEY,
    platform TEXT NOT NULL,
    arch TEXT NOT NULL,
    pack BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'queued',
    artifact TEXT,
    log_tail TEXT,
    log_text TEXT,
    error TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_build_jobs_platform ON build_jobs (platform);
CREATE INDEX IF NOT EXISTS idx_build_jobs_arch ON build_jobs (arch);
CREATE INDEX IF NOT EXISTS idx_build_jobs_status ON build_jobs (status);

ALTER TABLE build_jobs ADD COLUMN IF NOT EXISTS log_text TEXT;
