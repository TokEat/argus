-- 130_add_user_exp_authorization.sql
-- EXP 使用权限统一收敛到用户级授权；默认关闭，历史 admin 保持可管理/可执行。
ALTER TABLE users ADD COLUMN IF NOT EXISTS exp_authorized BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users
SET exp_authorized = TRUE
WHERE role = 'admin' AND status = 'active';
