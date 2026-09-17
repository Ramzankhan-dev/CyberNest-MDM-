-- Run in Supabase SQL Editor — RBAC 3-tier hierarchy refactor

-- One manager per department, enforced two ways by a single UNIQUE
-- constraint on manager_id: (a) a department can only have ONE
-- manager_id value at a time (obviously, it's one column), and (b)
-- UNIQUE means no two department ROWS can share the same manager_id,
-- so one user can't end up managing two departments at once.
-- Nullable — a freshly created department has no manager assigned yet
-- until an Organization Admin creates/assigns one.
ALTER TABLE departments ADD COLUMN IF NOT EXISTS manager_id INT REFERENCES users(id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'unique_department_manager'
  ) THEN
    ALTER TABLE departments ADD CONSTRAINT unique_department_manager UNIQUE (manager_id);
  END IF;
END $$;

-- Tracks the dashboard-login "users" account created for an employee
-- when they're made a Department Manager — lets role changes cleanly
-- find and update/detach that account later (promote/demote).
ALTER TABLE employees ADD COLUMN IF NOT EXISTS linked_user_id INT REFERENCES users(id);

-- Direct department binding on the device itself (separate from the
-- indirect device->employee->department link). Needed so:
-- (a) a device can be pre-bound to a department at enrollment time,
--     before any specific employee is assigned to it, and
-- (b) "Unassigned Devices" can distinguish truly-global unassigned
--     (department_id IS NULL) from unassigned-but-bound-to-a-specific-
--     department (department_id = X) — the latter should only be
--     visible to that department's own Manager, not everyone.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS department_id INT REFERENCES departments(id);
