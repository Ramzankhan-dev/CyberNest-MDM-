-- Run in Supabase SQL Editor — SRS-009 Policy Management (full category set)

ALTER TABLE policies ADD COLUMN IF NOT EXISTS policy_code VARCHAR(20);
ALTER TABLE policies ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'; -- active / disabled
ALTER TABLE policies ADD COLUMN IF NOT EXISTS version INT DEFAULT 1;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;

-- Device Restrictions (beyond what already existed: camera/bluetooth/wifi/usb)
ALTER TABLE policies ADD COLUMN IF NOT EXISTS screenshot_blocked BOOLEAN DEFAULT FALSE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS usb_debugging_blocked BOOLEAN DEFAULT FALSE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS nfc_blocked BOOLEAN DEFAULT FALSE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS mobile_hotspot_blocked BOOLEAN DEFAULT FALSE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS airplane_mode_blocked BOOLEAN DEFAULT FALSE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS location_services_blocked BOOLEAN DEFAULT FALSE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS factory_reset_blocked BOOLEAN DEFAULT FALSE;

-- Password Policy
ALTER TABLE policies ADD COLUMN IF NOT EXISTS password_required BOOLEAN DEFAULT FALSE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS password_min_length INT;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS max_failed_attempts INT;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS auto_lock_timeout_minutes INT;

-- Application Policy (policy-level, distinct from the ad-hoc per-device
-- block/unblock command already built in App Management)
ALTER TABLE policies ADD COLUMN IF NOT EXISTS blocked_apps TEXT; -- comma-separated package names
ALTER TABLE policies ADD COLUMN IF NOT EXISTS prevent_unknown_sources BOOLEAN DEFAULT FALSE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS prevent_play_store BOOLEAN DEFAULT FALSE;

-- Security Policy
ALTER TABLE policies ADD COLUMN IF NOT EXISTS root_detection_enabled BOOLEAN DEFAULT TRUE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS developer_options_disabled BOOLEAN DEFAULT FALSE;

-- Network Policy (stored for record-keeping; VPN/proxy enforcement is
-- documented as a known gap — see PROGRESS notes)
ALTER TABLE policies ADD COLUMN IF NOT EXISTS vpn_required BOOLEAN DEFAULT FALSE;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS mobile_data_restricted BOOLEAN DEFAULT FALSE;

-- Give existing policies a code so nothing breaks
UPDATE policies SET policy_code = 'POL' || id WHERE policy_code IS NULL;

-- Policy version history (BR-03: updates create a new version record)
CREATE TABLE IF NOT EXISTS policy_versions (
    id SERIAL PRIMARY KEY,
    policy_id INT REFERENCES policies(id) ON DELETE CASCADE,
    version INT NOT NULL,
    snapshot JSONB NOT NULL,
    changed_by INT REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);
