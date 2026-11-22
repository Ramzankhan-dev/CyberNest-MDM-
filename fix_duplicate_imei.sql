-- Run in Supabase SQL Editor — one-time cleanup + protection against the same phone (IMEI) being listed twice.
-- Run the blocks in order.

-- 1. (Optional) Preview: which IMEIs are currently listed more than once?
SELECT organization_id, imei, COUNT(*) AS copies,
       array_agg(device_uid ORDER BY last_seen DESC NULLS LAST) AS device_uids
FROM devices
WHERE imei IS NOT NULL
GROUP BY organization_id, imei
HAVING COUNT(*) > 1;

-- 2. Remove text that was stored as an IMEI ("Not available", "Permission not granted", all zeros ...)
UPDATE devices SET imei = NULL WHERE imei IS NOT NULL AND imei !~ '^[0-9]{15}$';
UPDATE devices SET imei = NULL WHERE imei ~ '^0+$';

-- 3. For every duplicated IMEI keep ONE device (the one with an assigned employee, otherwise the most recently
--    seen) and clear the IMEI on the older copies. No device is deleted — remove the leftover old cards from the
--    dashboard (Devices -> Remove) when you are ready.
WITH ranked AS (
  SELECT dv.id,
         ROW_NUMBER() OVER (
           PARTITION BY dv.organization_id, dv.imei
           ORDER BY EXISTS (SELECT 1 FROM employees e WHERE e.device_id = dv.id) DESC,
                    dv.last_seen DESC NULLS LAST,
                    dv.id DESC
         ) AS rn
  FROM devices dv
  WHERE dv.imei IS NOT NULL
)
UPDATE devices SET imei = NULL WHERE id IN (SELECT id FROM ranked WHERE rn > 1);

-- 4. From now on the database itself refuses a second device with the same IMEI in an organization.
CREATE UNIQUE INDEX IF NOT EXISTS devices_org_imei_unique
  ON devices (organization_id, imei)
  WHERE imei IS NOT NULL;
