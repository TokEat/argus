ALTER TABLE cloud_scaling_policies ADD COLUMN IF NOT EXISTS spot_duration_hours integer NOT NULL DEFAULT 1;
