-- Run in Supabase SQL Editor — Direct APK Upload + Silent Install
-- APK bytes are stored directly in Postgres (bytea) rather than a
-- separate object-storage service — simplest option that needs no new
-- external setup, reasonable for FYP-scale usage (a handful of APKs,
-- not hundreds of large files).

CREATE TABLE IF NOT EXISTS app_packages (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    app_name VARCHAR(150) NOT NULL,
    package_name VARCHAR(150) NOT NULL,
    version_name VARCHAR(50),
    file_size_bytes BIGINT,
    apk_data BYTEA NOT NULL,
    uploaded_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_app_packages_org ON app_packages(organization_id);
