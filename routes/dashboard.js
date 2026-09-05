const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

// GET /api/dashboard/summary — the 8 KPI cards
router.get("/summary", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.organization_id;

    const totalDevices = await pool.query("SELECT COUNT(*) FROM devices WHERE organization_id = $1", [orgId]);
    const onlineDevices = await pool.query(
      "SELECT COUNT(*) FROM devices WHERE organization_id = $1 AND last_seen > NOW() - INTERVAL '90 seconds'",
      [orgId]
    );
    const totalDevicesCount = parseInt(totalDevices.rows[0].count);
    const onlineCount = parseInt(onlineDevices.rows[0].count);

    const activePolicies = await pool.query("SELECT COUNT(*) FROM policies WHERE organization_id = $1", [orgId]);
    const pendingCommands = await pool.query(
      `SELECT COUNT(*) FROM commands c JOIN devices d ON c.device_id = d.id
       WHERE d.organization_id = $1 AND c.status = 'sent'`,
      [orgId]
    );
    const rootedDevices = await pool.query(
      "SELECT COUNT(*) FROM devices WHERE organization_id = $1 AND is_rooted = TRUE",
      [orgId]
    );
    const todaysAlerts = await pool.query(
      `SELECT COUNT(*) FROM devices WHERE organization_id = $1 AND
       (is_rooted = TRUE OR (battery_level IS NOT NULL AND battery_level < 15) OR last_seen < NOW() - INTERVAL '90 seconds')`,
      [orgId]
    );

    res.json({
      total_organizations: 1, // this admin only ever sees their own org
      total_devices: totalDevicesCount,
      online_devices: onlineCount,
      offline_devices: totalDevicesCount - onlineCount,
      active_policies: parseInt(activePolicies.rows[0].count),
      policy_violations: parseInt(rootedDevices.rows[0].count),
      pending_commands: parseInt(pendingCommands.rows[0].count),
      todays_alerts: parseInt(todaysAlerts.rows[0].count),
    });

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "dashboard_accessed", status: "success", req });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/dashboard/charts — data for the 5 charts
router.get("/charts", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.organization_id;

    const devicesResult = await pool.query("SELECT * FROM devices WHERE organization_id = $1", [orgId]);
    const devices = devicesResult.rows;

    const online = devices.filter((d) => d.last_seen && (Date.now() - new Date(d.last_seen).getTime()) < 90000).length;
    const offline = devices.length - online;

    // Android version distribution
    const versionCounts = {};
    devices.forEach((d) => {
      const v = d.android_version || "Unknown";
      versionCounts[v] = (versionCounts[v] || 0) + 1;
    });

    // Department distribution
    const deptResult = await pool.query(
      `SELECT dep.name, COUNT(e.id) AS device_count FROM departments dep
       LEFT JOIN employees e ON e.department_id = dep.id AND e.device_id IS NOT NULL
       WHERE dep.organization_id = $1 GROUP BY dep.name`,
      [orgId]
    );

    // Policy compliance — devices that currently have a policy assigned vs not
    const compliantResult = await pool.query(
      `SELECT COUNT(DISTINCT dp.device_id) FROM device_policies dp
       JOIN devices d ON dp.device_id = d.id WHERE d.organization_id = $1`,
      [orgId]
    );
    const compliant = parseInt(compliantResult.rows[0].count);

    // Device health — avg battery + avg storage used %
    const withBattery = devices.filter((d) => d.battery_level != null);
    const avgBattery = withBattery.length > 0
      ? Math.round(withBattery.reduce((s, d) => s + d.battery_level, 0) / withBattery.length)
      : 0;

    res.json({
      device_status: { online, offline },
      device_distribution: deptResult.rows.map((r) => ({ department: r.name, count: parseInt(r.device_count) })),
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
