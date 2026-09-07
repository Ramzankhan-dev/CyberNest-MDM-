-- Run in Supabase SQL Editor — SRS-A09 Support Screen

CREATE TABLE IF NOT EXISTS support_requests (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    device_id INT REFERENCES devices(id) ON DELETE CASCADE,
    ticket_number VARCHAR(20) UNIQUE NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'open', -- open / in_progress / resolved
    created_at TIMESTAMP DEFAULT NOW()
);
