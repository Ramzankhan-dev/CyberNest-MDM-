-- Run in Supabase SQL Editor — Persistent Admin Lock feature

ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT FALSE;
