const express = require("express");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

// Sends one command to one device — shared by /send and /retry.
async function dispatchCommand(device, commandType, issuedBy, packageName, req) {
  const commandLog = await pool.query(
    `INSERT INTO commands (device_id, command_type, issued_by, status)
     VALUES ($1, $2, $3, 'pending') RETURNING *`,
    [device.id, commandType, issuedBy]
  );

  try {
    const messageData = { command: commandType, command_id: String(commandLog.rows[0].id) };
    if (packageName) messageData.package_name = packageName;

    await admin.messaging().send({ token: device.fcm_token, data: messageData });

    const updated = await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1 RETURNING *", [commandLog.rows[0].id]);

    await logAudit({ userId: issuedBy, organizationId: device.organization_id, action: `command_${commandType}`, status: "success", req, details: `Device ${device.device_uid}` });
    return updated.rows[0];
  } catch (err) {
    // FR-12: record the failure reason instead of leaving it stuck as pending
    await pool.query("UPDATE commands SET status = 'failed', error_message = $1 WHERE id = $2", [err.message, commandLog.rows[0].id]);
    await logAudit({ userId: issuedBy, organizationId: device.organization_id, action: `command_${commandType}`, status: "failure", req, details: err.message });
    throw err;
  }
}

// POST /api/commands/send   (Admin only) — FR-01: supports one or many devices
// Body: { device_uid: "..." } OR { device_uids: ["...", "..."] }, command_type, package_name?
router.post("/send", requireAuth, async (req, res) => {
  try {
    const { device_uid, device_uids, command_type, package_name } = req.body;
    const targets = device_uids && Array.isArray(device_uids) ? device_uids : device_uid ? [device_uid] : [];
    if (targets.length === 0 || !command_type) {
      return res.status(400).json({ error: "device_uid(s) and command_type are required" });
    }

    const results = [];
    for (const uid of targets) {
      const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [uid, req.user.organization_id]);
      const device = deviceResult.rows[0];
      if (!device) {
        results.push({ device_uid: uid, error: "Selected device does not exist" });
        continue;
      }
      if (!device.fcm_token) {
        results.push({ device_uid: uid, error: "This device has no FCM token yet — it may not be enrolled properly" });
        continue;
      }
      try {
        const command = await dispatchCommand(device, command_type, req.user.id, package_name, req);
        results.push({ device_uid: uid, command });
      } catch (err) {
        results.push({ device_uid: uid, error: err.message });
      }
    }

    // Single-device call keeps its old response shape for existing callers
    if (targets.length === 1) {
      if (results[0].error) return res.status(results[0].error.includes("exist") ? 404 : 400).json({ error: results[0].error });
      return res.json({ message: "Command sent", command: results[0].command });
    }

    res.json({ message: `Command dispatched to ${targets.length} device(s)`, results });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// POST /api/commands/:id/ack   (Called by the Android agent app)
router.post("/:id/ack", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      "UPDATE commands SET status = 'executed', executed_at = NOW() WHERE id = $1 RETURNING *",
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Command not found" });
    }
    res.json({ message: "Command acknowledged", command: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/commands/:id/cancel   (SRS-010 FR-09)
// Only meaningful in the brief window before a command is actually sent
// to Firebase — our dispatch is synchronous, so this mostly guards
// against double-submission races rather than a long queue wait.
router.patch("/:id/cancel", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `UPDATE commands c SET status = 'cancelled'
       FROM devices d WHERE c.id = $1 AND c.device_id = d.id AND d.organization_id = $2 AND c.status = 'pending'
       RETURNING c.*`,
      [id, req.user.organization_id]
    );
    if (result.rows.length === 0) {
      return res.status(409).json({ error: "Command has already been delivered and can no longer be cancelled" });
    }
    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "command_cancelled", status: "success", req });
    res.json({ message: "Command cancelled", command: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/commands/:id/retry   (SRS-010 FR-10)
router.post("/:id/retry", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const original = await pool.query(
      `SELECT c.*, d.device_uid, d.fcm_token, d.organization_id AS device_org_id FROM commands c
       JOIN devices d ON c.device_id = d.id
       WHERE c.id = $1 AND d.organization_id = $2`,
      [id, req.user.organization_id]
    );
    const cmd = original.rows[0];
    if (!cmd) return res.status(404).json({ error: "Command not found" });
    if (cmd.status !== "failed") return res.status(409).json({ error: "Only failed commands can be retried" });
    if (!cmd.fcm_token) return res.status(400).json({ error: "This device has no FCM token yet" });

    const device = { id: cmd.device_id, device_uid: cmd.device_uid, fcm_token: cmd.fcm_token, organization_id: cmd.device_org_id };
    const newCommand = await dispatchCommand(device, cmd.command_type, req.user.id, null, req);
    await pool.query("UPDATE commands SET retry_of = $1 WHERE id = $2", [cmd.id, newCommand.id]);

    res.json({ message: "Command retried", command: newCommand });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// GET /api/commands   (SRS-010) — unified command history, with tabs/filters
// ?tab=pending|completed|failed  ?device_uid=  ?department_id=  ?command_type=  ?search=  ?date_from= ?date_to=
router.get("/", requireAuth, async (req, res) => {
  try {
    const { tab, device_uid, department_id, command_type, search, date_from, date_to, page = 1, limit = 50 } = req.query;
    const conditions = ["d.organization_id = $1"];
    const params = [req.user.organization_id];

    if (tab === "pending") conditions.push("c.status IN ('pending', 'sent')");
    else if (tab === "completed") conditions.push("c.status = 'executed'");
    else if (tab === "failed") conditions.push("c.status = 'failed'");

    if (device_uid) {
      params.push(device_uid);
      conditions.push(`d.device_uid = $${params.length}`);
    }
    if (department_id) {
      params.push(department_id);
      conditions.push(`dept.id = $${params.length}`);
    }
    if (command_type) {
      params.push(command_type);
      conditions.push(`c.command_type = $${params.length}`);
    }
    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(d.employee_name ILIKE $${params.length} OR d.device_uid ILIKE $${params.length} OR c.command_type ILIKE $${params.length})`);
    }
    if (date_from) {
      params.push(date_from);
      conditions.push(`c.issued_at >= $${params.length}`);
    }
    if (date_to) {
      params.push(date_to);
      conditions.push(`c.issued_at <= $${params.length}`);
    }

    const filterParamCount = params.length;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), offset);

    const result = await pool.query(
      `SELECT c.id, c.command_type, c.status, c.issued_at, c.executed_at, c.error_message, c.retry_of,
              d.device_uid, d.employee_name, e.name AS employee_full_name, u.name AS admin_name
       FROM commands c
       JOIN devices d ON c.device_id = d.id
       LEFT JOIN employees e ON e.device_id = d.id
       LEFT JOIN departments dept ON e.department_id = dept.id
       LEFT JOIN users u ON c.issued_by = u.id
       WHERE ${conditions.join(" AND ")}
       ORDER BY c.issued_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM commands c
       JOIN devices d ON c.device_id = d.id
       LEFT JOIN employees e ON e.device_id = d.id
       LEFT JOIN departments dept ON e.department_id = dept.id
       WHERE ${conditions.join(" AND ")}`,
      params.slice(0, filterParamCount)
    );

    res.json({ commands: result.rows, total: parseInt(countResult.rows[0].count), page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/commands/:device_uid   (Admin only) — command history for one device
router.get("/:device_uid", requireAuth, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const result = await pool.query(
      `SELECT c.* FROM commands c
       JOIN devices d ON c.device_id = d.id
       WHERE d.device_uid = $1 AND d.organization_id = $2
       ORDER BY c.issued_at DESC`,
      [device_uid, req.user.organization_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
