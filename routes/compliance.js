const express = require("express");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

// Works out a device's compliance status from what we actually know:
// its latest policy assignment, whether it's synced since, whether any
// recent commands for it failed, and whether it's online right now.
function computeStatus(device, latestFailed) {
  if (!device.policy_id) return "Unknown";
  if (latestFailed) return "Policy Failed";
  if (!device.last_seen || new Date(device.last_seen) < new Date(device.assigned_at)) return "Pending Sync";
  const isOnline = new Date(device.last_seen).getTime() > Date.now() - 90000;
  return isOnline ? "Compliant" : "Non-Compliant";
}

// GET /api/compliance   (SRS-011) — one row per device that has a policy assigned
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, status, department_id, page = 1, limit = 50, organization_id } = req.query;
    const orgId = req.user.is_super_admin ? organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const result = await pool.query(
      `SELECT DISTINCT ON (dv.id)
              dv.id, dv.device_uid, dv.model, dv.last_seen, dv.employee_name,
              e.name AS assigned_employee_name, dept.id AS department_id, dept.name AS department_name,
              p.id AS policy_id, p.name AS policy_name, p.version AS policy_version,
              dp.assigned_at
       FROM devices dv
       LEFT JOIN device_policies dp ON dp.device_id = dv.id
       LEFT JOIN policies p ON dp.policy_id = p.id
       LEFT JOIN employees e ON e.device_id = dv.id
       LEFT JOIN departments dept ON e.department_id = dept.id
       WHERE dv.organization_id = $1
       ORDER BY dv.id, dp.assigned_at DESC`,
      [orgId]
    );

    const rows = [];
    for (const device of result.rows) {
      let latestFailed = false;
      if (device.policy_id) {
        const failCheck = await pool.query(
          `SELECT id FROM commands WHERE device_id = $1 AND status = 'failed' AND issued_at > $2 LIMIT 1`,
          [device.id, device.assigned_at || new Date(0)]
        );
        latestFailed = failCheck.rows.length > 0;
      }
      const complianceStatus = computeStatus(device, latestFailed);
      if (status && complianceStatus.toLowerCase().replace(" ", "-") !== status) continue;
      if (department_id && String(device.department_id) !== String(department_id)) continue;
      if (search) {
        const s = search.toLowerCase();
        const haystack = `${device.model} ${device.device_uid} ${device.assigned_employee_name || device.employee_name || ""}`.toLowerCase();
        if (!haystack.includes(s)) continue;
      }
      rows.push({ ...device, compliance_status: complianceStatus });
    }

    const offset = (parseInt(page) - 1) * parseInt(limit);
    const paged = rows.slice(offset, offset + parseInt(limit));

    res.json({ compliance: paged, total: rows.length, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/compliance/summary   (SRS-011) — the 6 summary cards
router.get("/summary", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? req.query.organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const result = await pool.query(
      `SELECT DISTINCT ON (dv.id)
              dv.id, dv.last_seen,
              dp.assigned_at, p.id AS policy_id
       FROM devices dv
       LEFT JOIN device_policies dp ON dp.device_id = dv.id
       LEFT JOIN policies p ON dp.policy_id = p.id
       WHERE dv.organization_id = $1
       ORDER BY dv.id, dp.assigned_at DESC`,
      [orgId]
    );

    let compliant = 0, nonCompliant = 0, pendingSync = 0, failed = 0;
    for (const device of result.rows) {
      let latestFailed = false;
      if (device.policy_id) {
        const failCheck = await pool.query(
          `SELECT id FROM commands WHERE device_id = $1 AND status = 'failed' AND issued_at > $2 LIMIT 1`,
          [device.id, device.assigned_at || new Date(0)]
        );
        latestFailed = failCheck.rows.length > 0;
      }
      const s = computeStatus(device, latestFailed);
      if (s === "Compliant") compliant++;
      else if (s === "Non-Compliant") nonCompliant++;
      else if (s === "Pending Sync") pendingSync++;
      else if (s === "Policy Failed") failed++;
    }

    const total = result.rows.length;
    res.json({
      total_devices: total,
      compliant_devices: compliant,
      non_compliant_devices: nonCompliant,
      pending_sync: pendingSync,
      failed_policies: failed,
      compliance_percentage: total > 0 ? Math.round((compliant / total) * 100) : 0,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/compliance/sync   (SRS-011 FR-06) — force re-sync a device's policy
router.post("/sync", requireAuth, async (req, res) => {
  try {
    const { device_uid } = req.body;
    if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

    const orgId = req.user.is_super_admin ? req.body.organization_id || req.user.organization_id : req.user.organization_id;
    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, orgId]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Selected device does not exist" });
    if (!device.fcm_token) return res.status(400).json({ error: "Sync will occur later — device is currently offline" });

    const commandLog = await pool.query(
      `INSERT INTO commands (device_id, command_type, issued_by, status) VALUES ($1, 'refresh_policy', $2, 'pending') RETURNING *`,
      [device.id, req.user.id]
    );
    try {
      await admin.messaging().send({ token: device.fcm_token, data: { command: "refresh_policy", command_id: String(commandLog.rows[0].id) } });
      await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1", [commandLog.rows[0].id]);
    } catch (err) {
      await pool.query("UPDATE commands SET status = 'failed', error_message = $1 WHERE id = $2", [err.message, commandLog.rows[0].id]);
      return res.status(502).json({ error: "Unable to synchronize" });
    }

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "compliance_force_sync", status: "success", req, details: device_uid });
    res.json({ message: "Sync requested" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
