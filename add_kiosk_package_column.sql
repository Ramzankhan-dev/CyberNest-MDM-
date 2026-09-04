-- Run in Supabase SQL Editor
ALTER TABLE policies ADD COLUMN IF NOT EXISTS kiosk_package VARCHAR(150);
