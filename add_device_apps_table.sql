-- Run this in Supabase SQL Editor to add app management support
-- (does not touch your existing tables)

CREATE TABLE device_apps (
    id SERIAL PRIMARY KEY,
    device_id INT REFERENCES devices(id) ON DELETE CASCADE,
    package_name VARCHAR(150) NOT NULL,
    app_name VARCHAR(150),
    status VARCHAR(20) DEFAULT 'allowed',   -- allowed / blocked
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (device_id, package_name)
);

CREATE INDEX idx_device_apps_device ON device_apps(device_id);
