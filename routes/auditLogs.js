const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");

const router = express.Router();

// Derives a friendly "module" name from the audit_logs.action prefix —
// avoids needing a separate module column since our action names already
// carry this information (e.g. "policy_created" -> Policy).
function moduleForAction(action) {
  if (!action) return "Other";
  if (action.startsWith("login") || action.startsWith("password")) return "Authentication";
  if (action.startsWith("device_")) return "Device";
  if (action.startsWith("policy_")) return "Policy";
  if (action.startsWith("command_")) return "Command";
  if (action.startsWith("application_")) return "Application";
  if (action.startsWith("employee_")) return "Employee";
  if (action.startsWith("department_")) return "Department";
  if (action.startsWith("organization_")) return "Organization";
  if (action.startsWith("notification_")) return "Notification";
  if (action.startsWith("compliance_")) return "Compliance";
  if (action.startsWith("enrollment_")) return "Enrollment";
  if (action.startsWith("dashboard_")) return "Dashboard";
  return "Other";
}

const MODULES = ["Authentication", "Device", "Policy", "Command", "Application", "Employee", "Department", "Organization", "Notification", "Compliance", "Enrollment", "Dashboard", "Other"];

// Turns a row's joined role/department info into the label shown next
// to the user's name in the dashboard (e.g. "Super Admin",
// "Organization Admin", "Manager - Sales"). Rows with no linked user
// (system events, failed logins before the account was found) get no
// badge at all.
function roleBadge(row) {
  if (row.user_role === "SuperAdmin") return "Super Admin";
  if (row.user_role === "OrganizationAdmin") return "Organization Admin";
  if (row.user_role === "DepartmentManager") return `Manager - ${row.managed_department_name || "Unassigned"}`;
  return null;
}

// Builds the role-tier WHERE clause (+ matching params) shared by both
// GET / and GET /stats, so the log list and the KPI cards above it are
// always looking at the exact same slice of audit_logs:
//
//   SuperAdmin        — their own activity, everywhere, PLUS every
//                        Organization Admin's activity across every
//                        org. Department Manager rows are excluded.
//                        An optional organization_id further narrows
//                        the Organization Admin half to one org (the
//                        SuperAdmin's own rows are unaffected by it).
//   OrganizationAdmin — their own activity PLUS every Department
//                        Manager's activity, scoped to their own
//                        organization only.
//   anything else      — the Audit Logs page isn't exposed to any
//                        other role in the UI, so the API denies it
//                        too rather than silently returning nothing.
//
// Requires the query to LEFT JOIN roles r ON u.role_id = r.id (u being
// the LEFT JOIN'd users row) — r.name is what the OR conditions below
// match against.
function buildTierFilter(req, organizationIdParam) {
  const conditions = [];
  const params = [];

  if (req.user.is_super_admin) {
    params.push(req.user.id);
    conditions.push(`(al.user_id = $${params.length} OR r.name = 'OrganizationAdmin')`);
    if (organizationIdParam) {
      params.push(organizationIdParam);
      conditions.push(`al.organization_id = $${params.length}`);
    }
  } else if (req.user.role === "OrganizationAdmin") {
    if (!req.user.organization_id) return null;
    params.push(req.user.organization_id);
    conditions.push(`al.organization_id = $${params.length}`);
    params.push(req.user.id);
    conditions.push(`(al.user_id = $${params.length} OR r.name = 'DepartmentManager')`);
  } else {
    return null;
  }

  return { conditions, params };
}

// GET /api/audit-logs   (SRS-016) — search, filter, pagination
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, module: moduleFilter, status, date_from, date_to, page = 1, limit = 50, organization_id } = req.query;

    const tier = buildTierFilter(req, organization_id);
    if (!tier) return res.status(403).json({ error: "You don't have permission to view audit logs" });

    const conditions = [...tier.conditions];
    const params = [...tier.params];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(al.action ILIKE $${params.length} OR al.details ILIKE $${params.length} OR u.name ILIKE $${params.length})`);
    }
    if (status) {
      params.push(status);
      conditions.push(`al.status = $${params.length}`);
    }
    if (date_from) {
      params.push(date_from);
      conditions.push(`al.created_at >= $${params.length}`);
    }
    if (date_to) {
      params.push(date_to);
      conditions.push(`al.created_at <= $${params.length}`);
    }

    const filterParamCount = params.length;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit) * 3, offset); // fetch extra since module filter is applied in JS

    const result = await pool.query(
      `SELECT al.*, u.name AS user_name, u.email AS user_email, r.name AS user_role, d.name AS managed_department_name
       FROM audit_logs al
       LEFT JOIN users u ON al.user_id = u.id
       LEFT JOIN roles r ON u.role_id = r.id
       LEFT JOIN departments d ON d.manager_id = u.id
       WHERE ${conditions.join(" AND ")}
       ORDER BY al.created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    let rows = result.rows.map((r) => ({ ...r, module: moduleForAction(r.action), role_badge: roleBadge(r) }));
    if (moduleFilter) rows = rows.filter((r) => r.module === moduleFilter);
    rows = rows.slice(0, parseInt(limit));

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM audit_logs al
       LEFT JOIN users u ON al.user_id = u.id
       LEFT JOIN roles r ON u.role_id = r.id
       WHERE ${conditions.join(" AND ")}`,
      params.slice(0, filterParamCount)
    );

    res.json({ logs: rows, total: parseInt(countResult.rows[0].count), page: parseInt(page), limit: parseInt(limit), modules: MODULES });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/audit-logs/stats   (SRS-016) — the 6 dashboard cards
router.get("/stats", requireAuth, async (req, res) => {
  try {
    const tier = buildTierFilter(req, req.query.organization_id);
    if (!tier) return res.status(403).json({ error: "You don't have permission to view audit logs" });

    const all = await pool.query(
      `SELECT al.action, al.status
       FROM audit_logs al
       LEFT JOIN users u ON al.user_id = u.id
       LEFT JOIN roles r ON u.role_id = r.id
       WHERE ${tier.conditions.join(" AND ")}`,
      tier.params
    );
    let total = all.rows.length, login = 0, policyChanges = 0, commands = 0, failed = 0, critical = 0;

    all.rows.forEach((r) => {
      if (r.action.startsWith("login")) login++;
      if (r.action.startsWith("policy_")) policyChanges++;
      if (r.action.startsWith("command_")) commands++;
      if (r.status === "failure") failed++;
      if (["device_removed", "policy_deleted", "organization_suspended", "login_failed"].includes(r.action)) critical++;
    });

    res.json({
      total_events: total,
      login_events: login,
      policy_changes: policyChanges,
      commands_executed: commands,
      failed_operations: failed,
      critical_security_events: critical,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
