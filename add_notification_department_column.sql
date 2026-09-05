-- Run in Supabase SQL Editor
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS target_department_id INT REFERENCES departments(id);
