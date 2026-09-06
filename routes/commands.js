const express = require("express");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

// POST /api/commands/send   (Admin only)
// Body: { device_uid: "...", command_type: "block_camera" | "unblock_camera" | "lock" | "wipe" }
// Looks up the device's FCM token, sends a data message via Firebase,
// and logs the command in the database.
router.post("/send", requireAuth, async (req, res) => {
  try {
    const { device_uid, command_type, package_name } = req.body;
    if (!device_uid || !command_type) {
      return res.status(400).json({ error: "device_uid and command_type are required" });
    }

    const deviceResult = await pool.query(
      "SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2",
      [device_uid, req.user.organization_id]
    );
    const device = deviceResult.rows[0];

    if (!device) {
      return res.status(404).json({ error: "Device not found" });
    }
    if (!device.fcm_token) {
      return res.status(400).json({ error: "This device has no FCM token yet — it may not be enrolled properly" });
    }

    // Log the command first, as "pending"
    const commandLog = await pool.query(
      `INSERT INTO commands (device_id, command_type, issued_by, status)
       VALUES ($1, $2, $3, 'pending') RETURNING *`,
      [device.id, command_type, req.user.id]
    );

    // Send the actual push message via Firebase Cloud Messaging.
    // Data-only message (no "notification" field) so it's delivered
    // silently to the app's background service, not shown as a popup.
    const messageData = {
      command: command_type,
      command_id: String(commandLog.rows[0].id),
    };
    if (package_name) {
      messageData.package_name = package_name;
    }

    const message = {
      token: device.fcm_token,
      data: messageData,
    };

    await admin.messaging().send(message);

    // Mark it as sent (the device will separately confirm execution later)
    await pool.query(
      "UPDATE commands SET status = 'sent' WHERE id = $1",
      [commandLog.rows[0].id]
    );

    // FR-18 (SRS-007): every device operation is recorded in Audit Logs
    await logAudit({
      userId: req.user.id,
      organizationId: device.organization_id,
      action: `command_${command_type}`,
      status: "success",
      req,
      details: `Device ${device.device_uid}`,
    });

    res.json({ message: "Command sent", command: commandLog.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// POST /api/commands/:id/ack   (Called by the Android agent app)
// The device calls this once it has actually applied the command,
// so the admin dashboard can show "executed" instead of just "sent".
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

// GET /api/commands   (Admin only) — unified activity log across ALL devices
router.get("/", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id, c.command_type, c.status, c.issued_at, c.executed_at,
              d.device_uid, d.employee_name, u.name AS admin_name
       FROM commands c
       JOIN devices d ON c.device_id = d.id
       LEFT JOIN users u ON c.issued_by = u.id
       WHERE d.organization_id = $1
       ORDER BY c.issued_at DESC
       LIMIT 200`,
      [req.user.organization_id]
    );
    res.json(result.rows);
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
