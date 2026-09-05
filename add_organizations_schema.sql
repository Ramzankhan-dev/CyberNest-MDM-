-- Run in Supabase SQL Editor — sets up Organizations, Departments, Employees

-- 1. Organizations (each admin who registers gets their own)
CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 2. Link existing tables to an organization
ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id INT REFERENCES organizations(id);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS organization_id INT REFERENCES organizations(id);
ALTER TABLE policies ADD COLUMN IF NOT EXISTS organization_id INT REFERENCES organizations(id);

-- 3. Departments (belong to one organization)
CREATE TABLE departments (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    default_policy_id INT REFERENCES policies(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- 4. Employees (belong to one department, optionally have one device)
CREATE TABLE employees (
    id SERIAL PRIMARY KEY,
    department_id INT REFERENCES departments(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    employee_code VARCHAR(50),
    device_id INT REFERENCES devices(id),
    status VARCHAR(20) DEFAULT 'active',   -- active / suspended
    created_at TIMESTAMP DEFAULT NOW()
);

-- 5. Migrate existing data — create a default org for everything already in
-- the system, so nothing you've already built/tested breaks.
INSERT INTO organizations (name) VALUES ('My Organization');

UPDATE users SET organization_id = (SELECT id FROM organizations WHERE name = 'My Organization') WHERE organization_id IS NULL;
UPDATE devices SET organization_id = (SELECT id FROM organizations WHERE name = 'My Organization') WHERE organization_id IS NULL;
UPDATE policies SET organization_id = (SELECT id FROM organizations WHERE name = 'My Organization') WHERE organization_id IS NULL;

-- 6. Notifications also need to be scoped per organization
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS organization_id INT REFERENCES organizations(id);
UPDATE notifications SET organization_id = (SELECT id FROM organizations WHERE name = 'My Organization') WHERE organization_id IS NULL;
