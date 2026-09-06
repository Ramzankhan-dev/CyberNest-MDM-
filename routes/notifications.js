const express = require("express");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

const VALID_TYPES = ["Announcement", "Security Alert", "Policy Update", "Maintenance Notice", "Emergency Alert", "Custom Message"];
const VALID_PRIORITIES = ["Low", "Medium", "High", "Critical"];

// Resolves the device list for a given target, shared by send/resend/scheduler
async function resolveTargetDevices(organizationId, targetDeviceUid, targetDepartmentId) {
  if (targetDeviceUid) {
    const r = await pool.query(
      "SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2 AND fcm_token IS NOT NULL",
      [targetDeviceUid, organizationId]
    );
    return r.rows;
  }
  if (targetDepartmentId) {
    const r = await pool.query(
      `SELECT d.* FROM devices d JOIN employees e ON e.device_id = d.id JOIN departments dep ON e.department_id = dep.id
       WHERE dep.id = $1 AND dep.organization_id = $2 AND d.fcm_token IS NOT NULL`,
      [targetDepartmentId, organizationId]
    );
    return r.rows;
  }
  const r = await pool.query("SELECT * FROM devices WHERE organization_id = $1 AND fcm_token IS NOT NULL", [organizationId]);
  return r.rows;
}

// Actually delivers a notification row to its target devices, updates counts/status
async function deliverNotification(notificationId) {
  const notifResult = await pool.query("SELECT * FROM notifications WHERE id = $1", [notificationId]);
  const notif = notifResult.rows[0];
  if (!notif || notif.status === "cancelled") return;

  const devices = await resolveTargetDevices(notif.organization_id, notif.target_device_uid, notif.target_department_id);
  let sentCount = 0, failedCount = 0;

  for (const device of devices) {
    try {
      await admin.messaging().send({
        token: device.fcm_token,
        data: {
          notification_message: notif.message,
          notification_title: notif.title || "",
          notification_priority: notif.priority || "Medium",
        },
      });
      sentCount++;
    } catch (err) {
      failedCount++;
      console.error(`Failed to notify device ${device.device_uid}: ${err.message}`);
    }
  }

  const newStatus = devices.length === 0 ? "failed" : failedCount === devices.length ? "failed" : "delivered";
  await pool.query(
    "UPDATE notifications SET device_count = $1, failed_count = $2, status = $3, sent_at = NOW() WHERE id = $4",
    [sentCount, failedCount, newStatus, notificationId]
  );
}

// A lightweight in-process scheduler — checks every 30s for scheduled
// notifications whose time has come, and delivers them. Good enough for
// an FYP-scale deployment; a production system would use a real job queue.
setInterval(async () => {
  try {
    const due = await pool.query(
      "SELECT id FROM notifications WHERE status = 'scheduled' AND scheduled_at <= NOW()"
    );
    for (const row of due.rows) {
      await deliverNotification(row.id);
    }
  } catch (err) {
    console.error("Scheduled notification check failed:", err.message);
  }
}, 30000);

// POST /api/notifications/send   (SRS-014 FR-01/02/03) — send immediately
router.post("/send", requireAuth, async (req, res) => {
  try {
    const { title, message, notification_type, priority, target_device_uid, target_department_id } = req.body;
    if (!title || !title.trim()) return res.status(400).json({ error: "Notification title is required" });
    if (!message || !message.trim()) return res.status(400).json({ error: "Notification message is required" });
    if (notification_type && !VALID_TYPES.includes(notification_type)) return res.status(400).json({ error: "Invalid notification type" });
    if (priority && !VALID_PRIORITIES.includes(priority)) return res.status(400).json({ error: "Invalid priority" });

    const insertResult = await pool.query(
      `INSERT INTO notifications (title, message, notification_type, priority, target_device_uid, target_department_id, sent_by, sent_by_name, organization_id, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'sending') RETURNING *`,
      [title.trim(), message.trim(), notification_type || "Custom Message", priority || "Medium", target_device_uid || null, target_department_id || null, req.user.id, req.user.email, req.user.organization_id]
    );
    const notif = insertResult.rows[0];

    await deliverNotification(notif.id);
    const final = await pool.query("SELECT * FROM notifications WHERE id = $1", [notif.id]);

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "notification_sent", status: "success", req, details: title });
    res.json({ message: "Notification sent", sent_to: final.rows[0].device_count, notification: final.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/notifications/schedule   (SRS-014 FR-04)
router.post("/schedule", requireAuth, async (req, res) => {
  try {
    const { title, message, notification_type, priority, target_device_uid, target_department_id, scheduled_at } = req.body;
    if (!title || !title.trim()) return res.status(400).json({ error: "Notification title is required" });
    if (!message || !message.trim()) return res.status(400).json({ error: "Notification message is required" });
    if (!scheduled_at) return res.status(400).json({ error: "scheduled_at is required" });
    if (new Date(scheduled_at) <= new Date()) return res.status(400).json({ error: "Schedule time must be in the future" });

    const result = await pool.query(
      `INSERT INTO notifications (title, message, notification_type, priority, target_device_uid, target_department_id, sent_by, sent_by_name, organization_id, scheduled_at, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'scheduled') RETURNING *`,
      [title.trim(), message.trim(), notification_type || "Custom Message", priority || "Medium", target_device_uid || null, target_department_id || null, req.user.id, req.user.email, req.user.organization_id, scheduled_at]
    );

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "notification_scheduled", status: "success", req, details: title });
    res.status(201).json({ message: "Notification scheduled", notification: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/notifications/:id/cancel   (SRS-014 FR-07, BR-03)
router.patch("/:id/cancel", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      "UPDATE notifications SET status = 'cancelled' WHERE id = $1 AND organization_id = $2 AND status = 'scheduled' RETURNING *",
      [id, req.user.organization_id]
    );
    if (result.rows.length === 0) return res.status(409).json({ error: "Only scheduled notifications that haven't been sent yet can be cancelled" });

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "notification_cancelled", status: "success", req });
    res.json({ message: "Notification cancelled", notification: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/notifications/:id/resend   (SRS-014 table action — Resend)
router.post("/:id/resend", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await pool.query("SELECT * FROM notifications WHERE id = $1 AND organization_id = $2", [id, req.user.organization_id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Notification not found" });

    await deliverNotification(id);
    const final = await pool.query("SELECT * FROM notifications WHERE id = $1", [id]);

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "notification_resent", status: "success", req });
    res.json({ message: "Notification resent", notification: final.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/notifications/stats   (SRS-014) — the 6 dashboard cards
router.get("/stats", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.organization_id;
    const total = await pool.query("SELECT COUNT(*) FROM notifications WHERE organization_id = $1", [orgId]);
    const sentToday = await pool.query("SELECT COUNT(*) FROM notifications WHERE organization_id = $1 AND sent_at::date = CURRENT_DATE", [orgId]);
    const scheduled = await pool.query("SELECT COUNT(*) FROM notifications WHERE organization_id = $1 AND status = 'scheduled'", [orgId]);
    const delivered = await pool.query("SELECT COUNT(*) FROM notifications WHERE organization_id = $1 AND status = 'delivered'", [orgId]);
    const failed = await pool.query("SELECT COUNT(*) FROM notifications WHERE organization_id = $1 AND status = 'failed'", [orgId]);

    res.json({
      total_notifications: parseInt(total.rows[0].count),
      sent_today: parseInt(sentToday.rows[0].count),
      scheduled: parseInt(scheduled.rows[0].count),
      delivered: parseInt(delivered.rows[0].count),
      failed: parseInt(failed.rows[0].count),
      acknowledged: 0, // not implemented — see PROGRESS notes: needs Android-side interactive UI
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/notifications   (SRS-014) — history with search/filter/pagination
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, notification_type, priority, status, page = 1, limit = 30 } = req.query;
    const conditions = ["n.organization_id = $1"];
    const params = [req.user.organization_id];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(n.title ILIKE $${params.length} OR n.message ILIKE $${params.length})`);
    }
    if (notification_type) {
      params.push(notification_type);
      conditions.push(`n.notification_type = $${params.length}`);
    }
    if (priority) {
      params.push(priority);
      conditions.push(`n.priority = $${params.length}`);
    }
    if (status) {
      params.push(status);
      conditions.push(`n.status = $${params.length}`);
    }

    const filterParamCount = params.length;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), offset);

    const result = await pool.query(
      `SELECT n.*, dep.name AS department_name FROM notifications n
       LEFT JOIN departments dep ON n.target_department_id = dep.id
       WHERE ${conditions.join(" AND ")}
       ORDER BY COALESCE(n.scheduled_at, n.sent_at) DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    const countResult = await pool.query(`SELECT COUNT(*) FROM notifications n WHERE ${conditions.join(" AND ")}`, params.slice(0, filterParamCount));

    res.json({ notifications: result.rows, total: parseInt(countResult.rows[0].count), page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
