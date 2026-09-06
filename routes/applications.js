const express = require("express");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

function isValidPackage(pkg) {
  return /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/.test(pkg);
}

// POST /api/applications   (SRS-012 FR-01/02)
router.post("/", requireAuth, async (req, res) => {
  try {
    const { name, package_name, version, category, install_type, organization_id } = req.body;
    const orgId = req.user.is_super_admin ? (organization_id || req.user.organization_id) : req.user.organization_id;

    if (!name || !name.trim()) return res.status(400).json({ error: "Application name is required" });
    if (!package_name || !isValidPackage(package_name)) return res.status(400).json({ error: "Package name is invalid" });

    const dup = await pool.query("SELECT id FROM applications WHERE organization_id = $1 AND package_name = $2", [orgId, package_name]);
    if (dup.rows.length > 0) return res.status(409).json({ error: "Package already exists" });

    const result = await pool.query(
      `INSERT INTO applications (organization_id, name, package_name, version, category, install_type)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [orgId, name.trim(), package_name, version || null, category || "Public", install_type || "Optional"]
    );

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "application_registered", status: "success", req, details: package_name });
    res.status(201).json({ message: "Application registered", application: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/applications   (SRS-012) — search, filter, pagination
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, category, status, installed, page = 1, limit = 50, organization_id } = req.query;
    const orgId = req.user.is_super_admin ? organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const conditions = ["a.organization_id = $1"];
    const params = [orgId];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(a.name ILIKE $${params.length} OR a.package_name ILIKE $${params.length})`);
    }
    if (category) {
      params.push(category);
      conditions.push(`a.category = $${params.length}`);
    }
    if (status) {
      params.push(status);
      conditions.push(`a.status = $${params.length}`);
    }

    const filterParamCount = params.length;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), offset);

    const result = await pool.query(
      `SELECT a.*,
              (SELECT COUNT(DISTINCT device_id) FROM application_assignments aa WHERE aa.application_id = a.id) AS assigned_devices_count,
              (SELECT COUNT(DISTINCT da.device_id) FROM device_apps da JOIN devices dv ON da.device_id = dv.id
                WHERE da.package_name = a.package_name AND dv.organization_id = a.organization_id) AS installed_count
       FROM applications a
       WHERE ${conditions.join(" AND ")}
       ORDER BY a.created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countResult = await pool.query(`SELECT COUNT(*) FROM applications a WHERE ${conditions.join(" AND ")}`, params.slice(0, filterParamCount));

    res.json({ applications: result.rows, total: parseInt(countResult.rows[0].count), page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/applications/stats   (SRS-012) — the 6 dashboard cards
router.get("/stats", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? req.query.organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const total = await pool.query("SELECT COUNT(*) FROM applications WHERE organization_id = $1", [orgId]);
    const enterprise = await pool.query("SELECT COUNT(*) FROM applications WHERE organization_id = $1 AND category = 'Enterprise'", [orgId]);
    const publicApps = await pool.query("SELECT COUNT(*) FROM applications WHERE organization_id = $1 AND category = 'Public'", [orgId]);
    const blocked = await pool.query("SELECT COUNT(*) FROM applications WHERE organization_id = $1 AND status = 'blocked'", [orgId]);
    const installed = await pool.query(
      `SELECT COUNT(DISTINCT da.package_name) FROM device_apps da JOIN devices dv ON da.device_id = dv.id
       JOIN applications a ON a.package_name = da.package_name AND a.organization_id = dv.organization_id
       WHERE dv.organization_id = $1`,
      [orgId]
    );
    const pending = await pool.query(
      `SELECT COUNT(*) FROM commands c JOIN devices d ON c.device_id = d.id
       WHERE d.organization_id = $1 AND c.command_type IN ('block_app', 'unblock_app') AND c.status = 'sent'`,
      [orgId]
    );

    res.json({
      total_applications: parseInt(total.rows[0].count),
      enterprise_apps: parseInt(enterprise.rows[0].count),
      public_apps: parseInt(publicApps.rows[0].count),
      blocked_apps: parseInt(blocked.rows[0].count),
      installed_applications: parseInt(installed.rows[0].count),
      pending_installations: parseInt(pending.rows[0].count),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/applications/:id
router.put("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, version, category, install_type } = req.body;
    const result = await pool.query(
      `UPDATE applications SET name = COALESCE($1, name), version = COALESCE($2, version),
        category = COALESCE($3, category), install_type = COALESCE($4, install_type), updated_at = NOW()
       WHERE id = $5 RETURNING *`,
      [name, version, category, install_type, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Application not found" });
    await logAudit({ userId: req.user.id, organizationId: result.rows[0].organization_id, action: "application_updated", status: "success", req });
    res.json({ message: "Application updated", application: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Shared helper — sends block_app/unblock_app to a device via FCM
async function sendAppCommand(device, commandType, packageName, issuedBy, req) {
  const commandLog = await pool.query(
    `INSERT INTO commands (device_id, command_type, issued_by, status) VALUES ($1, $2, $3, 'pending') RETURNING *`,
    [device.id, commandType, issuedBy]
  );
  try {
    await admin.messaging().send({ token: device.fcm_token, data: { command: commandType, command_id: String(commandLog.rows[0].id), package_name: packageName } });
    await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1", [commandLog.rows[0].id]);
  } catch (err) {
    await pool.query("UPDATE commands SET status = 'failed', error_message = $1 WHERE id = $2", [err.message, commandLog.rows[0].id]);
  }
}

// POST /api/applications/:id/assign   (SRS-012 FR-03)
// Records the assignment, and — for Restricted-category apps — actively
// blocks it on the target device(s), since that's the one action we can
// genuinely enforce without a Managed Google Play integration.
router.post("/:id/assign", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { device_uid, department_id } = req.body;
    if (!device_uid && !department_id) return res.status(400).json({ error: "Select at least one device or department" });

    const appResult = await pool.query("SELECT * FROM applications WHERE id = $1", [id]);
    const app = appResult.rows[0];
    if (!app) return res.status(404).json({ error: "Application not found" });

    let targetDevices = [];
    if (device_uid) {
      const d = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, app.organization_id]);
      targetDevices = d.rows;
    } else {
      const d = await pool.query(
        `SELECT dv.* FROM devices dv JOIN employees e ON e.device_id = dv.id WHERE e.department_id = $1`,
        [department_id]
      );
      targetDevices = d.rows;
    }
    if (targetDevices.length === 0) return res.status(404).json({ error: "No matching devices found" });

    for (const device of targetDevices) {
      await pool.query("INSERT INTO application_assignments (application_id, device_id, assigned_by) VALUES ($1, $2, $3)", [app.id, device.id, req.user.id]);
      if (app.category === "Restricted" && device.fcm_token) {
        await sendAppCommand(device, "block_app", app.package_name, req.user.id, req);
      }
    }

    await logAudit({ userId: req.user.id, organizationId: app.organization_id, action: "application_assigned", status: "success", req, details: `${app.name} -> ${targetDevices.length} device(s)` });
    res.json({ message: `Assigned to ${targetDevices.length} device(s)`, enforced: app.category === "Restricted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/applications/:id/block   (SRS-012 FR-04) — blocks on every currently-assigned device
router.patch("/:id/block", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const appResult = await pool.query("UPDATE applications SET status = 'blocked', updated_at = NOW() WHERE id = $1 RETURNING *", [id]);
    const app = appResult.rows[0];
    if (!app) return res.status(404).json({ error: "Application not found" });

    const devices = await pool.query(
      `SELECT DISTINCT dv.* FROM devices dv JOIN application_assignments aa ON aa.device_id = dv.id WHERE aa.application_id = $1 AND dv.fcm_token IS NOT NULL`,
      [id]
    );
    for (const device of devices.rows) {
      await sendAppCommand(device, "block_app", app.package_name, req.user.id, req);
    }

    await logAudit({ userId: req.user.id, organizationId: app.organization_id, action: "application_blocked", status: "success", req, details: app.package_name });
    res.json({ message: "Application blocked", devices_notified: devices.rows.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/applications/:id/allow   (SRS-012 FR-05)
router.patch("/:id/allow", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const appResult = await pool.query("UPDATE applications SET status = 'active', updated_at = NOW() WHERE id = $1 RETURNING *", [id]);
    const app = appResult.rows[0];
    if (!app) return res.status(404).json({ error: "Application not found" });

    const devices = await pool.query(
      `SELECT DISTINCT dv.* FROM devices dv JOIN application_assignments aa ON aa.device_id = dv.id WHERE aa.application_id = $1 AND dv.fcm_token IS NOT NULL`,
      [id]
    );
    for (const device of devices.rows) {
      await sendAppCommand(device, "unblock_app", app.package_name, req.user.id, req);
    }

    await logAudit({ userId: req.user.id, organizationId: app.organization_id, action: "application_allowed", status: "success", req, details: app.package_name });
    res.json({ message: "Application allowed", devices_notified: devices.rows.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/applications/:id
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await pool.query("SELECT * FROM applications WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Application not found" });

    await pool.query("DELETE FROM application_assignments WHERE application_id = $1", [id]);
    await pool.query("DELETE FROM applications WHERE id = $1", [id]);

    await logAudit({ userId: req.user.id, organizationId: existing.rows[0].organization_id, action: "application_deleted", status: "success", req });
    res.json({ message: "Application deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
