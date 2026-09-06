-- Run in Supabase SQL Editor — SRS-A03 Device Owner Setup
-- Tracks when Device Owner provisioning was actually verified/completed,
-- separate from devices.enrolled_at (which marks the earlier
-- /api/devices/confirm step from SRS-A02).

ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_owner_confirmed_at TIMESTAMP;
