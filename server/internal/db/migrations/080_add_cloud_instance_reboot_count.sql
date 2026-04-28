-- Add reboot_count column to cloud_instances for gradient fault tolerance strategy
-- (reboot < 2 → OS reboot, reboot >= 2 → terminate)
ALTER TABLE cloud_instances ADD COLUMN IF NOT EXISTS reboot_count INTEGER NOT NULL DEFAULT 0;
