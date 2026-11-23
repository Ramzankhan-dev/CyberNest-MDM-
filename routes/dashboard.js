const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const { CRITICAL_ACTIONS } = require("../utils/criticalActions");

const router = express.Router();

// GET /api/dashboard/summary — the 8 KPI cards, scoped by role:
// SuperAdmin sees a true system-wide aggregate across every
// organization (no WHERE filter at all — SuperAdmin accounts aren't
// tied to any one org); OrganizationAdmin sees only their own org;
// DepartmentManager sees only their own department within their org.
router.get("/summary", requireAuth, async (req, res) => {
  try {
    const roleName = req.user.is_super_admin ? "SuperAdmin" : req.user.role;
    let deviceWhere = "1=1";
    let policyWhere = "1=1";
    const deviceParams = [];
    const policyParams = [];

    if (roleName === "OrganizationAdmin") {
      deviceWhere = "dv.organization_id = $1";
      deviceParams.push(req.user.organization_id);
      policyWhere = "organization_id = $1";
      policyParams.push(req.user.organization_id);
    } else if (roleName === "DepartmentManager") {
      const managedDeptResult = await pool.query("SELECT id FROM departments WHERE manager_id = $1", [req.user.id]);
      const managedDeptId = managedDeptResult.rows[0]?.id || 0; // 0 never matches — an unassigned manager sees all-zero stats
      deviceWhere = "dv.organization_id = $1 AND COALESCE(dv.department_id, e.department_id) = $2 AND NOT EXISTS (SELECT 1 FROM employees mgr_e WHERE mgr_e.device_id = dv.id AND mgr_e.role = 'DepartmentManager')"; // the manager's own device is Organization Admin only
      deviceParams.push(req.user.organization_id, managedDeptId);
      // Policies aren't department-scoped (a department manager applies
      // org-wide policies, doesn't own any) — count stays at the org level.
      policyWhere = "organization_id = $1";
      policyParams.push(req.user.organization_id);
    }
    // SuperAdmin: deviceWhere/policyWhere stay "1=1", no params — true global count.

    const totalDevices = await pool.query(
      `SELECT COUNT(*) FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id WHERE ${deviceWhere}`,
      deviceParams
    );
    const onlineDevices = await pool.query(
      `SELECT COUNT(*) FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id
       WHERE ${deviceWhere} AND dv.last_seen > NOW() - INTERVAL '90 seconds'`,
      deviceParams
    );
    const totalDevicesCount = parseInt(totalDevices.rows[0].count);
    const onlineCount = parseInt(onlineDevices.rows[0].count);

    const activePolicies = await pool.query(`SELECT COUNT(*) FROM policies WHERE ${policyWhere}`, policyParams);
    const pendingCommands = await pool.query(
      `SELECT COUNT(*) FROM commands c JOIN devices dv ON c.device_id = dv.id
       LEFT JOIN employees e ON e.device_id = dv.id
       WHERE ${deviceWhere} AND c.status = 'sent'`,
      deviceParams
    );
    const rootedDevices = await pool.query(
      `SELECT COUNT(*) FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id
       WHERE ${deviceWhere} AND dv.is_rooted = TRUE`,
      deviceParams
    );
    const todaysAlerts = await pool.query(
      `SELECT COUNT(*) FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id
       WHERE ${deviceWhere} AND
       (dv.is_rooted = TRUE OR (dv.battery_level IS NOT NULL AND dv.battery_level < 15) OR dv.last_seen < NOW() - INTERVAL '90 seconds')`,
      deviceParams
    );

    let totalOrganizations = 1; // OrgAdmin/DeptManager only ever see their own org
    let platform = {};
    if (roleName === "SuperAdmin") {
      const orgCount = await pool.query(
        `SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'active') AS active,
                COUNT(*) FILTER (WHERE status = 'suspended') AS suspended
         FROM organizations`
      );
      const employeeCount = await pool.query("SELECT COUNT(*) FROM employees");
      const criticalWeek = await pool.query(
        "SELECT COUNT(*) FROM audit_logs WHERE action = ANY($1::text[]) AND created_at > NOW() - INTERVAL '7 days'",
        [CRITICAL_ACTIONS]
      );
      const pendingEnrollments = await pool.query("SELECT COUNT(*) FROM devices WHERE status = 'pending'");
      totalOrganizations = parseInt(orgCount.rows[0].total);
      platform = {
        active_organizations: parseInt(orgCount.rows[0].active),
        suspended_organizations: parseInt(orgCount.rows[0].suspended),
        total_employees: parseInt(employeeCount.rows[0].count),
        rooted_devices: parseInt(rootedDevices.rows[0].count),
        pending_devices: parseInt(pendingEnrollments.rows[0].count),
        critical_events_7d: parseInt(criticalWeek.rows[0].count),
      };
    }

    // Department Manager extras: their department's name, employee count and free (unassigned) devices.
    let managerExtra = {};
    if (roleName === "DepartmentManager") {
      const managedDeptId = deviceParams[1];
      const deptRow = await pool.query("SELECT name FROM departments WHERE id = $1", [managedDeptId]);
      const empCount = await pool.query(
        "SELECT COUNT(*) FROM employees WHERE department_id = $1 AND role <> 'DepartmentManager'",
        [managedDeptId]
      );
      const unassigned = await pool.query(
        `SELECT COUNT(*) FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id
          WHERE dv.organization_id = $1 AND COALESCE(dv.department_id, e.department_id) IS NULL`,
        [req.user.organization_id]
      );
      managerExtra = {
        department_name: deptRow.rows[0]?.name || null,
        total_employees: parseInt(empCount.rows[0].count),
        unassigned_devices: parseInt(unassigned.rows[0].count),
      };
    }

    // Organization Admin extras: department / employee counts and devices not in any department.
    if (roleName === "OrganizationAdmin") {
      const depts = await pool.query("SELECT COUNT(*) FROM departments WHERE organization_id = $1", [req.user.organization_id]);
      const emps = await pool.query(
        "SELECT COUNT(*) FROM employees e JOIN departments d ON e.department_id = d.id WHERE d.organization_id = $1",
        [req.user.organization_id]
      );
      const unassigned = await pool.query(
        `SELECT COUNT(*) FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id
          WHERE dv.organization_id = $1 AND COALESCE(dv.department_id, e.department_id) IS NULL`,
        [req.user.organization_id]
      );
      managerExtra = {
        total_departments: parseInt(depts.rows[0].count),
        total_employees: parseInt(emps.rows[0].count),
        unassigned_devices: parseInt(unassigned.rows[0].count),
      };
    }

    res.json({
      total_organizations: totalOrganizations,
      total_devices: totalDevicesCount,
      online_devices: onlineCount,
      offline_devices: totalDevicesCount - onlineCount,
      active_policies: parseInt(activePolicies.rows[0].count),
      policy_violations: parseInt(rootedDevices.rows[0].count),
      pending_commands: parseInt(pendingCommands.rows[0].count),
      todays_alerts: parseInt(todaysAlerts.rows[0].count),
      ...platform,
      ...managerExtra,
    });

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "dashboard_accessed", status: "success", req });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/dashboard/charts — data for the 5 charts
router.get("/charts", requireAuth, async (req, res) => {
  try {
    const roleName = req.user.is_super_admin ? "SuperAdmin" : req.user.role;
    let deviceWhere = "1=1";
    const deviceParams = [];
    let managedDeptId = null;

    if (roleName === "OrganizationAdmin") {
      deviceWhere = "dv.organization_id = $1";
      deviceParams.push(req.user.organization_id);
    } else if (roleName === "DepartmentManager") {
      const managedDeptResult = await pool.query("SELECT id FROM departments WHERE manager_id = $1", [req.user.id]);
      managedDeptId = managedDeptResult.rows[0]?.id || 0;
      deviceWhere = "dv.organization_id = $1 AND COALESCE(dv.department_id, e.department_id) = $2 AND NOT EXISTS (SELECT 1 FROM employees mgr_e WHERE mgr_e.device_id = dv.id AND mgr_e.role = 'DepartmentManager')"; // the manager's own device is Organization Admin only
      deviceParams.push(req.user.organization_id, managedDeptId);
    }
    // SuperAdmin: no filter — true system-wide chart data.

    const devicesResult = await pool.query(
      `SELECT dv.* FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id WHERE ${deviceWhere}`,
      deviceParams
    );
    const devices = devicesResult.rows;

    const online = devices.filter((d) => d.last_seen && (Date.now() - new Date(d.last_seen).getTime()) < 90000).length;
    const offline = devices.length - online;

    // Android version distribution — straight from devices.android_version
    // (reported by the agent at enrollment). Devices still waiting to enroll
    // have no version yet, so they are left out instead of showing as "Unknown".
    const versionResult = await pool.query(
      `SELECT COALESCE(NULLIF(TRIM(dv.android_version), ''), 'Unknown') AS version, COUNT(DISTINCT dv.id) AS count
       FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id
       WHERE ${deviceWhere} AND dv.status <> 'pending'
       GROUP BY 1
       ORDER BY (CASE WHEN SUBSTRING(MAX(dv.android_version) FROM '^[0-9]+') IS NULL THEN -1
                      ELSE SUBSTRING(MAX(dv.android_version) FROM '^[0-9]+')::int END) DESC`,
      deviceParams
    );
    const androidVersions = versionResult.rows.map((r) => ({ version: r.version, count: parseInt(r.count) }));

    // Device distribution — by department for Org Admin/Department
    // Manager (department is meaningful within one org); by
    // organization for Super Admin instead, since "department" isn't
    // a meaningful grouping across different organizations.
    let deviceDistribution;
    if (roleName === "SuperAdmin") {
      const orgDistResult = await pool.query(
        `SELECT org.name, COUNT(dv.id) AS device_count FROM organizations org
         LEFT JOIN devices dv ON dv.organization_id = org.id
         GROUP BY org.id, org.name
         ORDER BY COUNT(dv.id) DESC, org.name`
      );
      deviceDistribution = orgDistResult.rows.map((r) => ({ department: r.name, count: parseInt(r.device_count) }));
    } else if (roleName === "DepartmentManager") {
      deviceDistribution = [{ department: "Your department", count: devices.length }];
    } else {
      const deptResult = await pool.query(
        `SELECT dep.name, COUNT(dv.id) AS device_count FROM departments dep
         LEFT JOIN devices dv ON dv.department_id = dep.id
         WHERE dep.organization_id = $1 GROUP BY dep.name`,
        [req.user.organization_id]
      );
      deviceDistribution = deptResult.rows.map((r) => ({ department: r.name, count: parseInt(r.device_count) }));
    }

    // Policy compliance — devices that currently have a policy assigned vs not
    const compliantResult = await pool.query(
      `SELECT COUNT(DISTINCT dp.device_id) FROM device_policies dp
       JOIN devices dv ON dp.device_id = dv.id
       LEFT JOIN employees e ON e.device_id = dv.id
       WHERE ${deviceWhere}`,
      deviceParams
    );
    const compliant = parseInt(compliantResult.rows[0].count);

    // Device health — avg battery + avg storage used %
    const withBattery = devices.filter((d) => d.battery_level != null);
    const avgBattery = withBattery.length > 0
      ? Math.round(withBattery.reduce((s, d) => s + d.battery_level, 0) / withBattery.length)
      : 0;

    res.json({
      device_status: { online, offline },
      device_distribution: deviceDistribution,
      android_versions: androidVersions,
      policy_compliance: { compliant, non_compliant: devices.length - compliant },
      device_health: { avg_battery: avgBattery },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/dashboard/activity — latest 20 activities
router.get("/activity", requireAuth, async (req, res) => {
  try {
    // Super Admin has no organization of their own — show platform-wide audit
    // activity instead (mapped onto the same row shape the dashboard table uses).
    if (req.user.is_super_admin) {
      const platform = await pool.query(
        `SELECT al.id, al.action, al.created_at, u.name AS user_name, u.email AS user_email, org.name AS organization
         FROM audit_logs al
         LEFT JOIN users u ON al.user_id = u.id
         LEFT JOIN roles r ON u.role_id = r.id
         LEFT JOIN organizations org ON al.organization_id = org.id
         WHERE COALESCE(r.name, u.role) IS DISTINCT FROM 'DepartmentManager'
           AND al.action <> 'dashboard_accessed'
         ORDER BY al.created_at DESC LIMIT 20`
      );
      return res.json(platform.rows.map((r) => ({
        id: r.id,
        command_type: r.action,
        status: null,
        issued_at: r.created_at,
        employee_name: [r.organization, r.user_name || r.user_email].filter(Boolean).join(" — ") || "System",
        device_uid: null,
      })));
    }
    if (req.user.role === "DepartmentManager") {
      // Manager sees only commands for their own department's devices.
      const managedDeptId = (await pool.query("SELECT id FROM departments WHERE manager_id = $1", [req.user.id])).rows[0]?.id || 0;
      const scoped = await pool.query(
        `SELECT c.id, c.command_type, c.status, c.issued_at, dv.employee_name, dv.device_uid
         FROM commands c JOIN devices dv ON c.device_id = dv.id
         LEFT JOIN employees e ON e.device_id = dv.id
         WHERE dv.organization_id = $1 AND COALESCE(dv.department_id, e.department_id) = $2 AND NOT EXISTS (SELECT 1 FROM employees mgr_e WHERE mgr_e.device_id = dv.id AND mgr_e.role = 'DepartmentManager')
         ORDER BY c.issued_at DESC LIMIT 20`,
        [req.user.organization_id, managedDeptId]
      );
      return res.json(scoped.rows);
    }
    const result = await pool.query(
      `SELECT c.id, c.command_type, c.status, c.issued_at, d.employee_name, d.device_uid
       FROM commands c JOIN devices d ON c.device_id = d.id
       WHERE d.organization_id = $1 ORDER BY c.issued_at DESC LIMIT 20`,
      [req.user.organization_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/dashboard/alerts — active alerts (same logic as Alerts page)
router.get("/alerts", requireAuth, async (req, res) => {
  try {
    // Super Admin: platform-level critical events only — organization suspended/deleted,
    // and failed logins with no organization (unknown accounts and the Super Admin account).
    // Org-level events (wipe/lock, device removed, ...) stay in the Critical Security Events tab.
    if (req.user.is_super_admin) {
      const events = await pool.query(
        `SELECT al.action, al.details, org.name AS organization
         FROM audit_logs al
         LEFT JOIN organizations org ON al.organization_id = org.id
         WHERE al.action IN ('organization_suspended', 'organization_deleted')
            OR (al.action = 'login_failed' AND al.organization_id IS NULL)
         ORDER BY al.created_at DESC LIMIT 10`
      );
      return res.json(events.rows.map((r) => ({
        type: "critical_event",
        device: r.organization || "Platform",
        message: r.details ? `${r.action} — ${r.details}` : r.action,
      })));
    }
    let result;
    if (req.user.role === "DepartmentManager") {
      // Manager sees alerts only for their own department's devices.
      const managedDeptId = (await pool.query("SELECT id FROM departments WHERE manager_id = $1", [req.user.id])).rows[0]?.id || 0;
      result = await pool.query(
        `SELECT dv.* FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id
         WHERE dv.organization_id = $1 AND COALESCE(dv.department_id, e.department_id) = $2 AND NOT EXISTS (SELECT 1 FROM employees mgr_e WHERE mgr_e.device_id = dv.id AND mgr_e.role = 'DepartmentManager')`,
        [req.user.organization_id, managedDeptId]
      );
    } else {
      result = await pool.query("SELECT * FROM devices WHERE organization_id = $1", [req.user.organization_id]);
    }
    const devices = result.rows;
    const alerts = [];

    devices.forEach((d) => {
      const name = d.employee_name || d.device_uid;
      if (d.battery_level != null && d.battery_level < 15) {
        alerts.push({ type: "battery_low", device: name, message: `Battery at ${d.battery_level}%` });
      }
      const isOnline = d.last_seen && (Date.now() - new Date(d.last_seen).getTime()) < 90000;
      if (d.last_seen && !isOnline) {
        alerts.push({ type: "offline", device: name, message: "Device offline" });
      }
      if (d.is_rooted) {
        alerts.push({ type: "root_detected", device: name, message: "Root access detected" });
      }
    });

    res.json(alerts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/dashboard/commands — pending commands
router.get("/commands", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, d.employee_name, d.device_uid FROM commands c
       JOIN devices d ON c.device_id = d.id
       WHERE d.organization_id = $1 AND c.status = 'sent'
       ORDER BY c.issued_at DESC LIMIT 20`,
      [req.user.organization_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/dashboard/search?q=...  — global search (FR-09)
router.get("/search", requireAuth, async (req, res) => {
  try {
    const q = (req.query.q || "").slice(0, 100); // Validation: max 100 chars
    if (!q.trim()) {
      return res.json({ devices: [], employees: [], departments: [], policies: [] });
    }
    const orgId = req.user.organization_id;
    const like = `%${q}%`;

    const devices = await pool.query(
      "SELECT device_uid, employee_name, model FROM devices WHERE organization_id = $1 AND (employee_name ILIKE $2 OR device_uid ILIKE $2 OR model ILIKE $2) LIMIT 5",
      [orgId, like]
    );
    const employees = await pool.query(
      `SELECT e.id, e.name FROM employees e JOIN departments d ON e.department_id = d.id
       WHERE d.organization_id = $1 AND e.name ILIKE $2 LIMIT 5`,
      [orgId, like]
    );
    const departments = await pool.query(
      "SELECT id, name FROM departments WHERE organization_id = $1 AND name ILIKE $2 LIMIT 5",
      [orgId, like]
    );
    const policies = await pool.query(
      "SELECT id, name FROM policies WHERE organization_id = $1 AND name ILIKE $2 LIMIT 5",
      [orgId, like]
    );

    res.json({
      devices: devices.rows,
      employees: employees.rows,
      departments: departments.rows,
      policies: policies.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
