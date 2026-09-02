const express = require("express");
const crypto = require("crypto");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");

const router = express.Router();

// POST /api/devices/generate-token   (Admin only)
// Admin dashboard calls this to create a new enrollment code before
// handing a phone to IT for provisioning. Returns a device_uid that
// gets turned into a QR code on the frontend later.
router.post("/generate-token", requireAuth, async (req, res) => {
  try {
    const { employee_name } = req.body;
    const device_uid = crypto.randomBytes(8).toString("hex"); // e.g. "a1b2c3d4e5f6a7b8"

    const result = await pool.query(
      `INSERT INTO devices (device_uid, employee_name, status)
       VALUES ($1, $2, 'pending') RETURNING *`,
      [device_uid, employee_name || null]
    );

    res.status(201).json({ message: "Enrollment token generated", device: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/devices/confirm   (Called by the Android agent app itself, no login)
// The agent app sends this once, right after it reads the device_uid
// from the QR code during provisioning, to finish enrollment.
router.post("/confirm", async (req, res) => {
  try {
    const { device_uid, imei, model, android_version, fcm_token } = req.body;
    if (!device_uid) {
      return res.status(400).json({ error: "device_uid is required" });
    }

    const result = await pool.query(
      `UPDATE devices
       SET imei = $1, model = $2, android_version = $3, fcm_token = $4,
           status = 'online', last_seen = NOW()
       WHERE device_uid = $5 RETURNING *`,
      [imei, model, android_version, fcm_token, device_uid]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Invalid device_uid — enroll from the dashboard first" });
    }

    res.json({ message: "Device enrolled successfully", device: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/devices   (Admin only) — list all devices for the dashboard
router.get("/", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM devices ORDER BY enrolled_at DESC");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/devices/:device_uid/heartbeat   (Called periodically by the agent app)
// Keeps last_seen, battery, and status fresh so the dashboard shows live data.
router.patch("/:device_uid/heartbeat", async (req, res) => {
  try {
    const { device_uid } = req.params;
    const { battery_level, fcm_token } = req.body;

    const result = await pool.query(
      `UPDATE devices
       SET status = 'online', battery_level = $1, fcm_token = COALESCE($2, fcm_token), last_seen = NOW()
       WHERE device_uid = $3 RETURNING *`,
      [battery_level, fcm_token, device_uid]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Device not found" });
    }

    res.json({ message: "Heartbeat received", device: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
