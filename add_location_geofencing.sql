-- Run in Supabase SQL Editor — Live Location + Geofencing

-- Last known location (on-demand "Locate Device")
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_lat DOUBLE PRECISION;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_lng DOUBLE PRECISION;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_location_at TIMESTAMP;

-- Circular geofence config — one per device, admin-set via manual
-- lat/lng + radius (no Google Maps API key/billing needed this way).
ALTER TABLE devices ADD COLUMN IF NOT EXISTS geofence_lat DOUBLE PRECISION;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS geofence_lng DOUBLE PRECISION;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS geofence_radius_meters INT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS geofence_enabled BOOLEAN DEFAULT FALSE;

-- Geofence exit history — so admin can see past violations, not just
-- the most recent one.
CREATE TABLE IF NOT EXISTS geofence_alerts (
    id SERIAL PRIMARY KEY,
    device_id INT REFERENCES devices(id) ON DELETE CASCADE,
    organization_id INT REFERENCES organizations(id) ON DELETE CASCADE,
    lat DOUBLE PRECISION,
    lng DOUBLE PRECISION,
    triggered_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_geofence_alerts_device ON geofence_alerts(device_id, triggered_at DESC);
