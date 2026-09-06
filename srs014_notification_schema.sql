-- Run in Supabase SQL Editor — SRS-014 Notification Management

ALTER TABLE notifications ADD COLUMN IF NOT EXISTS title VARCHAR(150);
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS notification_type VARCHAR(30) DEFAULT 'Custom Message';
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS priority VARCHAR(20) DEFAULT 'Medium';
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMP;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'delivered'; -- draft/scheduled/sending/delivered/failed/cancelled
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS failed_count INT DEFAULT 0;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS sent_by_name VARCHAR(100);

-- Existing rows: they were all sent immediately, so mark them accordingly
UPDATE notifications SET title = LEFT(message, 50), status = 'delivered' WHERE title IS NULL;
