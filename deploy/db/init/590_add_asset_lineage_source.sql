-- Asset scan-lineage provenance: each asset records its parent target (already
-- normalized via targetutil.NormalizeTarget) so the UI can trace how an asset
-- was obtained (input -> subdomain -> ip -> ip:port -> url). Empty string means
-- root / unknown parent. Fingerprint/vuln provenance is derived by matching
-- their Target to an asset, so only assets need this column.

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS source VARCHAR(512) NOT NULL DEFAULT '';
