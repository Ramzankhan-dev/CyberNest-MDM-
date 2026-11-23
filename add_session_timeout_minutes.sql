-- Run in Supabase SQL Editor — session timeout is now set in minutes (default 24 hours = 1440)
ALTER TABLE organization_settings ADD COLUMN IF NOT EXISTS session_timeout_minutes INT DEFAULT 1440;

-- Carry over existing values: the old default (7 days) becomes the new default (24 hours);
-- any custom day value is converted to minutes.
UPDATE organization_settings
SET session_timeout_minutes = CASE WHEN session_timeout_days IS NULL OR session_timeout_days = 7 THEN 1440 ELSE session_timeout_days * 1440 END
WHERE session_timeout_minutes IS NULL OR session_timeout_minutes = 1440;
