-- Run in Supabase SQL Editor (optional, one time).
-- APKs uploaded earlier through the old "Direct APK Install" section have no row
-- in the Applications list. This adds one Applications row per such APK so they
-- show up in the unified table (with Install to Device available).

INSERT INTO applications (organization_id, name, package_name, version, category, install_type)
SELECT DISTINCT ON (p.organization_id, p.package_name)
       p.organization_id, p.app_name, p.package_name, p.version_name, 'Public', 'Optional'
FROM app_packages p
WHERE NOT EXISTS (
  SELECT 1 FROM applications a
  WHERE a.organization_id = p.organization_id AND a.package_name = p.package_name
)
ORDER BY p.organization_id, p.package_name, p.uploaded_at DESC;
