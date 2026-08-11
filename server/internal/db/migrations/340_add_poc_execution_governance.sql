-- Add POC execution governance metadata without changing the raw Arsenal authority.
-- Legacy/unclassified rules remain compatible as detection + unknown risk and
-- still require explicit risk-validation confirmation before execution.

ALTER TABLE poc_rules ADD COLUMN IF NOT EXISTS execution_class TEXT NOT NULL DEFAULT 'detection';
ALTER TABLE poc_rules ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT 'unknown';

UPDATE poc_rules
SET execution_class = 'detection'
WHERE execution_class IS NULL OR BTRIM(execution_class) = '';

UPDATE poc_rules
SET risk_level = 'unknown'
WHERE risk_level IS NULL OR BTRIM(risk_level) = '';

CREATE INDEX IF NOT EXISTS idx_poc_rules_execution_class ON poc_rules (execution_class);
CREATE INDEX IF NOT EXISTS idx_poc_rules_risk_level ON poc_rules (risk_level);
