const express = require("express");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");

const router = express.Router();

// POST /api/notifications/send   (Admin only)
// Body: { message: "...", target_device_uid: "..." (optional — omit for everyone) }
router.post("/send", requireAuth, async (req, res) => {
  try {
    const { message, target_device_uid } = req.body;
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "message is required" });
    }

    let devicesResult;
    if (target_device_uid) {
      devicesResult = await pool.query(
        "SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2 AND fcm_token IS NOT NULL",
        [target_device_uid, req.user.organization_id]
      );
    } else {
      devicesResult = await pool.query(
        "SELECT * FROM devices WHERE organization_id = $1 AND fcm_token IS NOT NULL",
        [req.user.organization_id]
      );
    }

    const devices = devicesResult.rows;
    let sentCount = 0;

    for (const device of devices) {
      try {
        await admin.messaging().send({
          token: device.fcm_token,
          data: {
            notification_message: message.trim(),
          },
        });
        sentCount++;
      } catch (err) {
        // One bad/stale token shouldn't stop the rest from sending
        console.error(`Failed to notify device ${device.device_uid}: ${err.message}`);
      }
    }

    await pool.query(
      `INSERT INTO notifications (message, target_device_uid, sent_by, device_count, organization_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [message.trim(), target_device_uid || null, req.user.id, sentCount, req.user.organization_id]
    );

    res.json({ message: "Notification sent", sent_to: sentCount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/notifications   (Admin only) — recently sent notifications
router.get("/", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM notifications WHERE organization_id = $1 ORDER BY sent_at DESC LIMIT 50",
      [req.user.organization_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
