CREATE TABLE IF NOT EXISTS arsenal_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    artifact_id TEXT NOT NULL,
    type TEXT NOT NULL,
    file_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    hash TEXT NOT NULL,
    state TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id TEXT,
    content TEXT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_arsenal_event_artifact ON arsenal_events (tenant_id, artifact_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_arsenal_events_type ON arsenal_events (type);
CREATE INDEX IF NOT EXISTS idx_arsenal_events_file_name ON arsenal_events (file_name);
CREATE INDEX IF NOT EXISTS idx_arsenal_events_version ON arsenal_events (version);
CREATE INDEX IF NOT EXISTS idx_arsenal_events_hash ON arsenal_events (hash);
CREATE INDEX IF NOT EXISTS idx_arsenal_events_state ON arsenal_events (state);
CREATE INDEX IF NOT EXISTS idx_arsenal_events_action ON arsenal_events (action);
CREATE INDEX IF NOT EXISTS idx_arsenal_events_actor_id ON arsenal_events (actor_id);
CREATE INDEX IF NOT EXISTS idx_arsenal_events_created_at ON arsenal_events (created_at);
