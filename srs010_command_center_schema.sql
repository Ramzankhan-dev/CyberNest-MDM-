-- Run in Supabase SQL Editor — SRS-010 Command Center
ALTER TABLE commands ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE commands ADD COLUMN IF NOT EXISTS retry_of INT REFERENCES commands(id);
-- Existing status values used: 'pending', 'sent', 'executed'
-- New ones this module adds: 'failed', 'cancelled'
