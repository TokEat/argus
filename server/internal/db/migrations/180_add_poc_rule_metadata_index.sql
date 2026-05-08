-- 180_add_poc_rule_metadata_index.sql
-- Searchable GoPoc/POC metadata used by governance and EXP correlation.

ALTER TABLE poc_rules ADD COLUMN IF NOT EXISTS target_product TEXT;
ALTER TABLE poc_rules ADD COLUMN IF NOT EXISTS cve TEXT;
ALTER TABLE poc_rules ADD COLUMN IF NOT EXISTS compatibility_status TEXT DEFAULT 'unknown';
ALTER TABLE poc_rules ADD COLUMN IF NOT EXISTS source_version TEXT;

CREATE INDEX IF NOT EXISTS idx_poc_rules_target_product ON poc_rules (target_product);
CREATE INDEX IF NOT EXISTS idx_poc_rules_cve ON poc_rules (cve);
CREATE INDEX IF NOT EXISTS idx_poc_rules_compatibility_status ON poc_rules (compatibility_status);
