-- Run in Supabase SQL Editor
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    message TEXT NOT NULL,
    target_device_uid VARCHAR(100),   -- NULL means sent to everyone
    sent_by INT REFERENCES users(id),
    sent_at TIMESTAMP DEFAULT NOW(),
    device_count INT DEFAULT 0
);
