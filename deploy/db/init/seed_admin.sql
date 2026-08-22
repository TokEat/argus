-- 默认管理员种子（幂等）。与旧 migrations/020_seed-admin-and-fix-roles.sql 等价：
-- 1) 修复空 role，防止登录端点提权；2) 种入开发/初装默认管理员。
-- 生产环境首次登录后必须立即修改密码。
UPDATE users SET role = 'viewer' WHERE role = '' OR role IS NULL;

INSERT INTO users (tenant_id, username, password_hash, role, status, created_at, updated_at)
VALUES (
    'default',
    'admin',
    '$2a$10$PKNTpO5NRQJDH/OWvp/K.u8NnQYRv7tqRO8mpju.CjkxzEfHPYBey',
    'admin',
    'active',
    NOW(),
    NOW()
) ON CONFLICT (username) DO NOTHING;
