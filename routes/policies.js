const express = require("express");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");

const router = express.Router();

// POST /api/policies   (Admin only) — create a named, reusable policy template
router.post("/", requireAuth, async (req, res) => {
  try {
    const {
      name,
      camera_blocked,
      bluetooth_blocked,
      wifi_restricted,
      usb_transfer_blocked,
      kiosk_mode,
      kiosk_package,
      working_hours_start,
      working_hours_end,
    } = req.body;

    if (!name) {
      return res.status(400).json({ error: "name is required" });
    }

    const result = await pool.query(
      `INSERT INTO policies (name, camera_blocked, bluetooth_blocked, wifi_restricted, usb_transfer_blocked, kiosk_mode, kiosk_package, working_hours_start, working_hours_end)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [
        name,
        !!camera_blocked,
        !!bluetooth_blocked,
        !!wifi_restricted,
        !!usb_transfer_blocked,
        !!kiosk_mode,
        kiosk_package || null,
        working_hours_start || null,
        working_hours_end || null,
      ]
    );

    res.status(201).json({ message: "Policy created", policy: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/policies   (Admin only) — list all saved policy templates
router.get("/", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM policies ORDER BY created_at DESC");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Sends one command to a device via FCM and logs it — shared helper
// so applying a policy can fire off several commands in one go.
async function sendCommandToDevice(device, commandType, issuedBy, packageName = null) {
  const commandLog = await pool.query(
    `INSERT INTO commands (device_id, command_type, issued_by, status)
     VALUES ($1, $2, $3, 'pending') RETURNING *`,
    [device.id, commandType, issuedBy]
  );

  const messageData = {
    command: commandType,
    command_id: String(commandLog.rows[0].id),
  };
  if (packageName) messageData.package_name = packageName;

  await admin.messaging().send({
    token: device.fcm_token,
    data: messageData,
  });

  await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1", [commandLog.rows[0].id]);
}

// POST /api/policies/:id/assign   (Admin only)
// Body: { device_uid: "..." }
// Applies every restriction the policy has turned on, by sending the
// matching commands to the device — and remembers the assignment.
router.post("/:id/assign", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { device_uid } = req.body;
    if (!device_uid) {
      return res.status(400).json({ error: "device_uid is required" });
    }

    const policyResult = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    const policy = policyResult.rows[0];
    if (!policy) {
      return res.status(404).json({ error: "Policy not found" });
    }

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) {
      return res.status(404).json({ error: "Device not found" });
    }
    if (!device.fcm_token) {
      return res.status(400).json({ error: "This device has no FCM token yet" });
    }

    const commandsToSend = [];
    if (policy.camera_blocked) commandsToSend.push("block_camera");
    if (policy.bluetooth_blocked) commandsToSend.push("block_bluetooth");
    if (policy.wifi_restricted) commandsToSend.push("block_wifi");
    if (policy.usb_transfer_blocked) commandsToSend.push("block_usb");
    if (policy.kiosk_mode) commandsToSend.push("enable_kiosk");

    for (const cmd of commandsToSend) {
      const pkg = cmd === "enable_kiosk" ? policy.kiosk_package : null;
      await sendCommandToDevice(device, cmd, req.user.id, pkg);
    }

    // Remember this assignment for the record
    await pool.query(
      `INSERT INTO device_policies (device_id, policy_id) VALUES ($1, $2)`,
      [device.id, policy.id]
    );

    res.json({ message: `Policy "${policy.name}" applied`, commands_sent: commandsToSend });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

module.exports = router;
