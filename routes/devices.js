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
      `INSERT INTO devices (device_uid, employee_name, status, organization_id)
       VALUES ($1, $2, 'pending', $3) RETURNING *`,
      [device_uid, employee_name || null, req.user.organization_id]
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
    const result = await pool.query(
      "SELECT * FROM devices WHERE organization_id = $1 ORDER BY enrolled_at DESC",
      [req.user.organization_id]
    );
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
    const {
      battery_level,
      fcm_token,
      manufacturer,
      device_identifier,
      imei,
      ram_gb,
      storage_total_gb,
      storage_used_gb,
      network_info,
      is_rooted,
    } = req.body;

    const result = await pool.query(
      `UPDATE devices
       SET status = 'online',
           battery_level = $1,
           fcm_token = COALESCE($2, fcm_token),
           manufacturer = COALESCE($3, manufacturer),
           device_identifier = COALESCE($4, device_identifier),
           imei = COALESCE($5, imei),
           ram_gb = COALESCE($6, ram_gb),
           storage_total_gb = COALESCE($7, storage_total_gb),
           storage_used_gb = COALESCE($8, storage_used_gb),
           network_info = COALESCE($9, network_info),
           is_rooted = COALESCE($10, is_rooted),
           last_seen = NOW()
       WHERE device_uid = $11 RETURNING *`,
      [battery_level, fcm_token, manufacturer, device_identifier, imei, ram_gb, storage_total_gb, storage_used_gb, network_info, is_rooted, device_uid]
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

// GET /api/devices/:device_uid/current-policy   (Called by the Android agent)
// Returns the most recently assigned policy's flags, so the device can
// re-apply everything when it receives a "refresh_policy" command.
router.get("/:device_uid/current-policy", async (req, res) => {
  try {
    const { device_uid } = req.params;
    const result = await pool.query(
      `SELECT p.* FROM device_policies dp
       JOIN devices d ON dp.device_id = d.id
       JOIN policies p ON dp.policy_id = p.id
       WHERE d.device_uid = $1
       ORDER BY dp.assigned_at DESC LIMIT 1`,
      [device_uid]
    );

    if (result.rows.length === 0) {
      return res.json({ policy: null });
    }

    res.json({ policy: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/devices/:device_uid/apps   (Called by the Android agent)
// Body: { apps: [{ package_name, app_name }, ...] }
// Device reports its installed apps here whenever it receives a
// "list_apps" command. We upsert so re-runs just refresh the list.
router.post("/:device_uid/apps", async (req, res) => {
  try {
    const { device_uid } = req.params;
    const { apps } = req.body;
    if (!Array.isArray(apps)) {
      return res.status(400).json({ error: "apps must be an array" });
    }

    const deviceResult = await pool.query("SELECT id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) {
      return res.status(404).json({ error: "Device not found" });
    }

    for (const app of apps) {
      await pool.query(
        `INSERT INTO device_apps (device_id, package_name, app_name)
         VALUES ($1, $2, $3)
         ON CONFLICT (device_id, package_name)
         DO UPDATE SET app_name = EXCLUDED.app_name, updated_at = NOW()`,
        [device.id, app.package_name, app.app_name || null]
      );
    }

    // The device's report is the source of truth for what's currently
    // installed — remove any stored app that's no longer in this list
    // (e.g. it was uninstalled since the last report).
    const currentPackageNames = apps.map((a) => a.package_name);
    if (currentPackageNames.length > 0) {
      await pool.query(
        `DELETE FROM device_apps WHERE device_id = $1 AND package_name != ALL($2::text[])`,
        [device.id, currentPackageNames]
      );
    }

    res.json({ message: "App list updated", count: apps.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/devices/:device_uid/apps   (Admin only)
router.get("/:device_uid/apps", requireAuth, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const result = await pool.query(
      `SELECT da.* FROM device_apps da
       JOIN devices d ON da.device_id = d.id
       WHERE d.device_uid = $1 AND d.organization_id = $2
       ORDER BY da.app_name ASC`,
      [device_uid, req.user.organization_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/devices/:device_uid/apps/:package_name/status   (Called by the Android agent)
// Keeps the stored status in sync after a block/unblock command runs.
router.patch("/:device_uid/apps/:package_name/status", async (req, res) => {
  try {
    const { device_uid, package_name } = req.params;
    const { status } = req.body;

    await pool.query(
      `UPDATE device_apps SET status = $1, updated_at = NOW()
       WHERE package_name = $2 AND device_id = (SELECT id FROM devices WHERE device_uid = $3)`,
      [status, package_name, device_uid]
    );

    res.json({ message: "Status updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
