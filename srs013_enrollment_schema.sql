-- Run in Supabase SQL Editor — SRS-013 Device Enrollment

CREATE TABLE IF NOT EXISTS enrollment_profiles (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    default_policy_id INT REFERENCES policies(id),
    default_department_id INT REFERENCES departments(id),
    token_expiry_hours INT DEFAULT 24,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Token expiry + which profile (if any) a pending device was created from
ALTER TABLE devices ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMP;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS enrollment_profile_id INT REFERENCES enrollment_profiles(id);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS enrollment_method VARCHAR(30) DEFAULT 'QR Code';
