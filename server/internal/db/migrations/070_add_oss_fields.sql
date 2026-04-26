-- Add OSS fields to cloud_accounts for Agent binary distribution
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS oss_bucket TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS oss_endpoint TEXT NOT NULL DEFAULT '';
