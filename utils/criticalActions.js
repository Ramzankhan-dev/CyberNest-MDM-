// Single source of truth for "critical security events" — shared by the
// Audit Logs filter/stats (routes/auditLogs.js) and the platform Reports
// (routes/reports.js) so the two never disagree.
//
// Keys are the category shown in reports; values are audit_logs.action values.
const CRITICAL_CATEGORIES = {
  "Failed Login": ["login_failed", "employee_login_failed"],
  "Remote Wipe / Lock": ["command_wipe", "command_factory_reset", "command_lock"],
  "Organization": ["organization_suspended", "organization_deleted"],
  "Device": ["device_removed", "device_unenroll_requested", "geofence_exit"],
  "Policy / Employee": ["policy_deleted", "employee_deleted"],
};

const CRITICAL_ACTIONS = Object.values(CRITICAL_CATEGORIES).flat();

// SQL helpers. These only ever interpolate the constants above (never user
// input), so they are safe to inline into a query string.
function criticalActionsSql() {
  return CRITICAL_ACTIONS.map((a) => `'${a}'`).join(", ");
}

function categorySql(alias = "al") {
  const whens = Object.entries(CRITICAL_CATEGORIES)
    .map(([cat, actions]) => `WHEN ${alias}.action IN (${actions.map((a) => `'${a}'`).join(", ")}) THEN '${cat}'`)
    .join(" ");
  return `CASE ${whens} ELSE 'Other' END`;
}

module.exports = { CRITICAL_CATEGORIES, CRITICAL_ACTIONS, criticalActionsSql, categorySql };
