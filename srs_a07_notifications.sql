-- Run in Supabase SQL Editor — SRS-A07 Notifications Screen

CREATE TABLE IF NOT EXISTS notification_reads (
    id SERIAL PRIMARY KEY,
    notification_id INT REFERENCES notifications(id) ON DELETE CASCADE,
    device_id INT REFERENCES devices(id) ON DELETE CASCADE,
    read_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (notification_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_notification_reads_device ON notification_reads(device_id);
