ALTER TABLE exps
    ADD COLUMN IF NOT EXISTS product_name VARCHAR(160) NOT NULL DEFAULT '未分类',
    ADD COLUMN IF NOT EXISTS parent_exp_id VARCHAR(36) NULL,
    ADD COLUMN IF NOT EXISTS variant_key VARCHAR(64) NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_exps_tenant_id_id ON exps (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_exps_tenant_product ON exps (tenant_id, product_name);
CREATE INDEX IF NOT EXISTS idx_exps_parent_exp_id ON exps (parent_exp_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exps_parent_variant
    ON exps (parent_exp_id, variant_key)
    WHERE parent_exp_id IS NOT NULL;

ALTER TABLE exps
    DROP CONSTRAINT IF EXISTS chk_exps_family_shape;
ALTER TABLE exps
    ADD CONSTRAINT chk_exps_family_shape CHECK (
        (parent_exp_id IS NULL AND variant_key = '')
        OR
        (parent_exp_id IS NOT NULL AND variant_key ~ '^[a-z0-9][a-z0-9._-]{0,63}$')
    );

ALTER TABLE exps
    DROP CONSTRAINT IF EXISTS fk_exps_parent_same_tenant;
ALTER TABLE exps
    ADD CONSTRAINT fk_exps_parent_same_tenant
    FOREIGN KEY (tenant_id, parent_exp_id)
    REFERENCES exps (tenant_id, id)
    ON DELETE RESTRICT;
