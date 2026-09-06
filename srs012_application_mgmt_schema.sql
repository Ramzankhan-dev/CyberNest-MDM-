-- Run in Supabase SQL Editor — SRS-012 Application Management

CREATE TABLE IF NOT EXISTS applications (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    package_name VARCHAR(200) NOT NULL,
    version VARCHAR(50),
    category VARCHAR(20) DEFAULT 'Public', -- Enterprise / Public / Restricted
    install_type VARCHAR(20) DEFAULT 'Optional', -- Required / Optional / Blocked
    status VARCHAR(20) DEFAULT 'active', -- active / blocked
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS application_assignments (
    id SERIAL PRIMARY KEY,
    application_id INT REFERENCES applications(id) ON DELETE CASCADE,
    device_id INT REFERENCES devices(id) ON DELETE CASCADE,
    assigned_by INT REFERENCES users(id),
    assigned_at TIMESTAMP DEFAULT NOW()
);
