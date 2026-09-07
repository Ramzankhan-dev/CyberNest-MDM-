-- Run in Supabase SQL Editor — APK install history + duplicate prevention

CREATE TABLE IF NOT EXISTS app_installs (
    id SERIAL PRIMARY KEY,
    app_package_id INT REFERENCES app_packages(id) ON DELETE CASCADE,
    device_id INT REFERENCES devices(id) ON DELETE CASCADE,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    installed_by INT REFERENCES users(id),
    installed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_app_installs_package ON app_installs(app_package_id);
CREATE INDEX IF NOT EXISTS idx_app_installs_device ON app_installs(device_id);

-- Lets the /ack flow trace an install_app command back to which
-- package it was for, so a successful ack can record the install.
ALTER TABLE commands ADD COLUMN IF NOT EXISTS package_id INT REFERENCES app_packages(id);
