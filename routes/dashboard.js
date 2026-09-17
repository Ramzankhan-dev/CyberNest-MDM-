const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

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
      deviceWhere = "dv.organization_id = $1 AND COALESCE(dv.department_id, e.department_id) = $2";
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
    if (roleName === "SuperAdmin") {
      const orgCount = await pool.query("SELECT COUNT(*) FROM organizations");
      totalOrganizations = parseInt(orgCount.rows[0].count);
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
      deviceWhere = "dv.organization_id = $1 AND COALESCE(dv.department_id, e.department_id) = $2";
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

    // Android version distribution
    const versionCounts = {};
    devices.forEach((d) => {
      const v = d.android_version || "Unknown";
      versionCounts[v] = (versionCounts[v] || 0) + 1;
    });

    // Device distribution — by department for Org Admin/Department
    // Manager (department is meaningful within one org); by
    // organization for Super Admin instead, since "department" isn't
    // a meaningful grouping across different organizations.
    let deviceDistribution;
    if (roleName === "SuperAdmin") {
      const orgDistResult = await pool.query(
        `SELECT org.name, COUNT(dv.id) AS device_count FROM organizations org
         LEFT JOIN devices dv ON dv.organization_id = org.id
         GROUP BY org.name`
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
      android_versions: Object.entries(versionCounts).map(([version, count]) => ({ version, count })),
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
    const result = await pool.query("SELECT * FROM devices WHERE organization_id = $1", [req.user.organization_id]);
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
