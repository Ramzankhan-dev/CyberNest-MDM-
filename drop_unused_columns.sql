-- Removes the table/columns that the code no longer uses.
-- Run this ONLY AFTER the updated backend is deployed on Render
-- (the old backend still writes some of these columns).
-- Safe to run twice (IF EXISTS everywhere).

BEGIN;

-- Unused table
DROP TABLE IF EXISTS activity_logs;

-- Unused columns
ALTER TABLE organization_settings DROP COLUMN IF EXISTS session_timeout_days;
ALTER TABLE organizations         DROP COLUMN IF EXISTS logo_url;
ALTER TABLE password_reset_tokens DROP COLUMN IF EXISTS resend_count;
ALTER TABLE policies              DROP COLUMN IF EXISTS nfc_blocked;
ALTER TABLE notification_reads    DROP COLUMN IF EXISTS read_at;

-- Saved but never used by any feature
ALTER TABLE organization_settings DROP COLUMN IF EXISTS default_policy_id;
ALTER TABLE organization_settings DROP COLUMN IF EXISTS default_department_id;
ALTER TABLE organization_settings DROP COLUMN IF EXISTS default_notification_priority;
ALTER TABLE policies              DROP COLUMN IF EXISTS root_detection_enabled;
ALTER TABLE policies              DROP COLUMN IF EXISTS developer_options_disabled;
ALTER TABLE policies              DROP COLUMN IF EXISTS vpn_required;
ALTER TABLE policies              DROP COLUMN IF EXISTS mobile_data_restricted;
ALTER TABLE devices               DROP COLUMN IF EXISTS device_owner_confirmed_at;

-- Duplicate of departments.manager_id
ALTER TABLE departments           DROP COLUMN IF EXISTS manager_employee_id;

COMMIT;
