-- Run in Supabase SQL Editor — SRS-017 System Settings

CREATE TABLE IF NOT EXISTS organization_settings (
    id SERIAL PRIMARY KEY,
    organization_id INT UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    time_zone VARCHAR(50) DEFAULT 'Asia/Karachi',
    date_format VARCHAR(20) DEFAULT 'DD/MM/YYYY',
    max_failed_login_attempts INT DEFAULT 5,
    lockout_duration_minutes INT DEFAULT 15,
    session_timeout_days INT DEFAULT 7,
    default_qr_expiry_hours INT DEFAULT 24,
    default_policy_id INT REFERENCES policies(id),
    default_department_id INT REFERENCES departments(id),
    default_notification_priority VARCHAR(20) DEFAULT 'Medium',
    updated_at TIMESTAMP DEFAULT NOW()
);
