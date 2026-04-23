-- 020_seed_admin_and_fix_roles.sql
-- 1) Fix empty roles: prevent privilege escalation via login endpoint
UPDATE users SET role = 'viewer' WHERE role = '' OR role IS NULL;

-- 2) Seed default admin user for development/testing (idempotent)
-- Password: admin123  (bcrypt hash, cost=10)
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
