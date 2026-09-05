-- Run in Supabase SQL Editor — SRS-001 (Login) + SRS-002 (Forgot Password)

-- 1. Proper roles table (SRS wants a normalized roles table, not just a text column)
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL
);
INSERT INTO roles (name) VALUES ('SuperAdmin'), ('OrganizationAdmin'), ('DepartmentManager')
ON CONFLICT (name) DO NOTHING;

-- 2. Give users a proper account status + link to roles table
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'; -- active / suspended
ALTER TABLE users ADD COLUMN IF NOT EXISTS role_id INT REFERENCES roles(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;

-- Map the existing text role values to the new roles table
UPDATE users SET role_id = (SELECT id FROM roles WHERE name = 'SuperAdmin') WHERE role = 'super_admin' AND role_id IS NULL;
UPDATE users SET role_id = (SELECT id FROM roles WHERE name = 'OrganizationAdmin') WHERE role_id IS NULL;

-- 3. Sessions (tracks refresh tokens + active sessions per SRS-001 FR-06)
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    refresh_token VARCHAR(255) NOT NULL,
    ip_address VARCHAR(60),
    browser_info TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE
);

-- 4. Audit logs (generic — reused by many later SRS modules, not just login)
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    organization_id INT REFERENCES organizations(id),
    action VARCHAR(100) NOT NULL,          -- e.g. "login_success", "login_failed", "password_reset"
    status VARCHAR(20),                    -- success / failure
    ip_address VARCHAR(60),
    browser_info TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 5. Password reset tokens (OTP flow — SRS-002)
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    otp_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    used BOOLEAN DEFAULT FALSE,
    attempts INT DEFAULT 0,
    resend_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);
