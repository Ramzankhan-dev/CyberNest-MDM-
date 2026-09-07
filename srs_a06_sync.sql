-- Run in Supabase SQL Editor — SRS-A06 Synchronization Screen

CREATE TABLE IF NOT EXISTS sync_history (
    id SERIAL PRIMARY KEY,
    device_id INT REFERENCES devices(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'success', -- success / failed
    apps_count INT DEFAULT 0,
    policy_name VARCHAR(150),
    duration_ms INT,
    synced_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sync_history_device ON sync_history(device_id, synced_at DESC);
