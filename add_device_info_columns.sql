-- Run this in Supabase SQL Editor — adds real device-info columns
ALTER TABLE devices ADD COLUMN IF NOT EXISTS manufacturer VARCHAR(50);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_identifier VARCHAR(100);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS ram_gb NUMERIC(5,1);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS storage_total_gb NUMERIC(6,1);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS storage_used_gb NUMERIC(6,1);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS network_info VARCHAR(100);
