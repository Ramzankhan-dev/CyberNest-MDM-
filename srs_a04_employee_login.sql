-- Run in Supabase SQL Editor — SRS-A04 Employee Login

-- 1. Password storage on employees (set by an admin from the dashboard —
--    employees don't self-register).
ALTER TABLE employees ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);

-- 2. Employee-side sessions (refresh tokens) — kept separate from the
--    existing `sessions` table because that one's user_id has a FK to
--    `users(id)` (Admin/SuperAdmin accounts), a different id space.
CREATE TABLE IF NOT EXISTS employee_sessions (
    id SERIAL PRIMARY KEY,
    employee_id INT REFERENCES employees(id) ON DELETE CASCADE,
    refresh_token VARCHAR(255) NOT NULL,
    device_uid VARCHAR(100),
    ip_address VARCHAR(60),
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE
);

-- 3. SRS-A04's own design note: login is optional and controlled per
--    Enrollment Profile (shared/kiosk devices can skip it; dedicated
--    employee devices require it).
ALTER TABLE enrollment_profiles ADD COLUMN IF NOT EXISTS require_employee_login BOOLEAN DEFAULT FALSE;
