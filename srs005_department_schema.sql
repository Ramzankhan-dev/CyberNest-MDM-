-- Run in Supabase SQL Editor — SRS-005 Department Management
ALTER TABLE departments ADD COLUMN IF NOT EXISTS code VARCHAR(20);
ALTER TABLE departments ADD COLUMN IF NOT EXISTS manager_employee_id INT REFERENCES employees(id);
ALTER TABLE departments ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE departments ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'; -- active / disabled

-- Give existing departments a code so nothing breaks
UPDATE departments SET code = 'DEPT' || id WHERE code IS NULL;
