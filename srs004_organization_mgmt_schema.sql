-- Run in Supabase SQL Editor — SRS-004 Organization Management

-- 1. Super Admin flag — a Super Admin's queries are NOT scoped to one
-- organization; they see/manage every organization on the platform.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_super_admin BOOLEAN DEFAULT FALSE;

-- 2. Extra organization fields the SRS requires
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS code VARCHAR(20) UNIQUE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS industry VARCHAR(100);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS email VARCHAR(150);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS contact_number VARCHAR(30);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS country VARCHAR(100);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS city VARCHAR(100);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS address TEXT;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS logo_url TEXT;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'; -- active / suspended / inactive

-- 3. Give existing orgs a code so the UNIQUE constraint doesn't choke on them
UPDATE organizations SET code = 'ORG' || id WHERE code IS NULL;

-- 4. Make YOUR account the platform Super Admin — replace the email below
-- with whichever admin account you want to use to manage all organizations.
UPDATE users SET is_super_admin = TRUE WHERE email = 'admin@cybernest.com';
