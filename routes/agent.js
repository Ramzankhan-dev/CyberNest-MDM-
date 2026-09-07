const express = require("express");
const pool = require("../config/db");
const logAudit = require("../utils/auditLog");
const computeStatus = require("../utils/computeCompliance");

const router = express.Router();

// This file holds agent-facing endpoints (no dashboard login — the
// Android agent authenticates itself by device_uid, same pattern as
// the existing /api/devices/confirm and /api/devices/:uid/heartbeat
// routes). SRS-A03 is the first screen to need this namespace; later
// screens (A05 Device Status, A06 Sync, etc.) will add routes here
// too rather than starting yet another top-level router.

// GET /api/agent/dashboard   (SRS-A05 — Device Status / Home screen)
// Server-known fields only — battery, storage, RAM, and network are
// read locally on-device (the same way sendHeartbeat() already does)
// and never round-trip through here.
router.get("/dashboard", async (req, res) => {
  const { device_uid } = req.query;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const result = await pool.query(
      `SELECT dv.id, dv.device_uid, dv.model, dv.android_version, dv.last_seen,
              org.name AS organization_name,
              ep.name AS enrollment_profile_name,
              e.name AS employee_name,
              dept.name AS department_name,
              p.id AS policy_id, p.name AS policy_name, p.version AS policy_version,
              p.camera_blocked, p.bluetooth_blocked, p.wifi_restricted, p.usb_transfer_blocked, p.kiosk_mode,
              dp.assigned_at
       FROM devices dv
       LEFT JOIN organizations org ON dv.organization_id = org.id
       LEFT JOIN enrollment_profiles ep ON dv.enrollment_profile_id = ep.id
       LEFT JOIN employees e ON e.device_id = dv.id
       LEFT JOIN departments dept ON e.department_id = dept.id
       LEFT JOIN device_policies dp ON dp.device_id = dv.id
       LEFT JOIN policies p ON dp.policy_id = p.id
       WHERE dv.device_uid = $1
       ORDER BY dp.assigned_at DESC LIMIT 1`,
      [device_uid]
    );
    const device = result.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    let latestFailed = false;
    if (device.policy_id) {
      const failCheck = await pool.query(
        `SELECT id FROM commands WHERE device_id = $1 AND status = 'failed' AND issued_at > $2 LIMIT 1`,
        [device.id, device.assigned_at || new Date(0)]
      );
      latestFailed = failCheck.rows.length > 0;
    }
    const complianceStatus = computeStatus(device, latestFailed);

    res.json({
      organization_name: device.organization_name || "Unknown Organization",
      employee_name: device.employee_name || null,
      department_name: device.department_name || null,
      device_model: device.model || "Unknown Device",
      android_version: device.android_version || null,
      enrollment_profile_name: device.enrollment_profile_name || null,
      compliance_status: complianceStatus,
      policy_name: device.policy_name || null,
      policy_version: device.policy_version || null,
      restrictions: {
        camera_blocked: !!device.camera_blocked,
        bluetooth_blocked: !!device.bluetooth_blocked,
        wifi_restricted: !!device.wifi_restricted,
        usb_transfer_blocked: !!device.usb_transfer_blocked,
        kiosk_mode: !!device.kiosk_mode,
      },
      last_sync: device.last_seen,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/agent/provisioning/verify   (SRS-A03 FR-01..FR-03)
// Confirms the device is a real enrolled device (completed
// /api/devices/confirm already) before the agent proceeds with
// Device Owner provisioning checks. Read-only.
router.post("/provisioning/verify", async (req, res) => {
  const { device_uid } = req.body;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const result = await pool.query(
      `SELECT dv.device_uid, dv.model, dv.fcm_token, dv.enrolled_at,
              org.name AS organization_name,
              ep.name AS enrollment_profile_name
       FROM devices dv
       LEFT JOIN organizations org ON dv.organization_id = org.id
       LEFT JOIN enrollment_profiles ep ON dv.enrollment_profile_id = ep.id
       WHERE dv.device_uid = $1`,
      [device_uid]
    );
    const device = result.rows[0];

    if (!device) {
      return res.status(404).json({ error: "Device not found — complete enrollment first" });
    }
    if (!device.fcm_token || !device.enrolled_at) {
      return res.status(409).json({ error: "Device has not completed enrollment yet" });
    }

    res.json({
      verified: true,
      organization_name: device.organization_name || "Unknown Organization",
      device_name: device.model || "Unknown Device",
      enrollment_profile_name: device.enrollment_profile_name || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/agent/provisioning/complete   (SRS-A03 FR-11/FR-12)
// Called once the agent has confirmed Device Owner mode is active
// locally (dpm.isDeviceOwnerApp() == true) — records that the device
// finished the SRS-A03 checklist, separate from the earlier
// enrollment-confirm timestamp.
router.post("/provisioning/complete", async (req, res) => {
  const { device_uid } = req.body;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const result = await pool.query(
      `UPDATE devices SET device_owner_confirmed_at = NOW()
       WHERE device_uid = $1 RETURNING organization_id`,
      [device_uid]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Device not found" });
    }

    await logAudit({
      organizationId: result.rows[0].organization_id,
      action: "device_owner_provisioning_complete",
      status: "success",
      req,
      details: device_uid,
    });

    res.json({ message: "Provisioning marked complete" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/agent/policies/default   (SRS-A03 FR-08 — "Download Initial Policies")
// Same underlying data as /api/devices/:uid/current-policy — kept as
// its own route here because SRS-A03 names it separately and later
// agent screens will expect everything agent-facing under /api/agent.
router.get("/policies/default", async (req, res) => {
  const { device_uid } = req.query;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const result = await pool.query(
      `SELECT p.* FROM device_policies dp
       JOIN devices d ON dp.device_id = d.id
       JOIN policies p ON dp.policy_id = p.id
       WHERE d.device_uid = $1
       ORDER BY dp.assigned_at DESC LIMIT 1`,
      [device_uid]
    );
    res.json({ policy: result.rows[0] || null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/agent/sync   (SRS-A06 — manual "Sync Now")
// Records a sync_history entry and returns what actually changed so
// the agent can show real per-item results (not a fake progress bar).
// Device health itself is uploaded via the existing heartbeat
// endpoint — the agent calls that first, then this.
router.post("/sync", async (req, res) => {
  const { device_uid } = req.body;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });
  const startedAt = Date.now();

  try {
    const deviceResult = await pool.query("SELECT id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    const policyResult = await pool.query(
      `SELECT p.name FROM device_policies dp JOIN policies p ON dp.policy_id = p.id
       WHERE dp.device_id = $1 ORDER BY dp.assigned_at DESC LIMIT 1`,
      [device.id]
    );
    const policyName = policyResult.rows[0]?.name || null;

    const appsResult = await pool.query("SELECT COUNT(*) FROM device_apps WHERE device_id = $1", [device.id]);
    const appsCount = parseInt(appsResult.rows[0].count, 10);

    await pool.query("UPDATE devices SET last_seen = NOW() WHERE id = $1", [device.id]);

    const durationMs = Date.now() - startedAt;
    await pool.query(
      `INSERT INTO sync_history (device_id, status, apps_count, policy_name, duration_ms)
       VALUES ($1, 'success', $2, $3, $4)`,
      [device.id, appsCount, policyName, durationMs]
    );

    res.json({
      synced_at: new Date().toISOString(),
      policy_name: policyName,
      apps_count: appsCount,
      duration_ms: durationMs,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/agent/sync/history   (SRS-A06 FR-14)
router.get("/sync/history", async (req, res) => {
  const { device_uid, limit = 10 } = req.query;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const deviceResult = await pool.query("SELECT id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    const result = await pool.query(
      `SELECT status, apps_count, policy_name, duration_ms, synced_at
       FROM sync_history WHERE device_id = $1 ORDER BY synced_at DESC LIMIT $2`,
      [device.id, limit]
    );
    res.json({ history: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/agent/apps   (SRS-A06 enhancement — tappable app list on Sync screen)
// Mirrors GET /api/devices/:uid/apps (admin-facing) but keyed by
// device_uid with no dashboard auth, matching every other agent route.
router.get("/apps", async (req, res) => {
  const { device_uid, blocked_only } = req.query;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const deviceResult = await pool.query("SELECT id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    const query = blocked_only === "true"
      ? `SELECT package_name, app_name, status FROM device_apps WHERE device_id = $1 AND status = 'blocked' ORDER BY app_name`
      : `SELECT package_name, app_name, status FROM device_apps WHERE device_id = $1 ORDER BY app_name`;
    const result = await pool.query(query, [device.id]);
    res.json({ apps: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/agent/policy-history   (SRS-A06 enhancement — tappable
// "policy rules refreshed" row on Sync screen). Same data as the
// dashboard's GET /api/devices/:uid/policy-history, agent-facing.
router.get("/policy-history", async (req, res) => {
  const { device_uid } = req.query;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const deviceResult = await pool.query("SELECT id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    const result = await pool.query(
      `SELECT p.name, p.camera_blocked, p.bluetooth_blocked, p.wifi_restricted,
              p.usb_transfer_blocked, p.kiosk_mode, dp.assigned_at
       FROM device_policies dp JOIN policies p ON dp.policy_id = p.id
       WHERE dp.device_id = $1 ORDER BY dp.assigned_at DESC`,
      [device.id]
    );
    res.json({ history: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/agent/health   (SRS-A06 enhancement — tappable "Device
// health reported" row on Sync screen). Same fields the heartbeat
// endpoint receives, read back so the agent can show what was
// actually last reported — including whether it's stale.
router.get("/health", async (req, res) => {
  const { device_uid } = req.query;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const result = await pool.query(
      `SELECT battery_level, manufacturer, model, ram_gb, storage_used_gb,
              storage_total_gb, network_info, is_rooted, last_seen
       FROM devices WHERE device_uid = $1`,
      [device_uid]
    );
    const device = result.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    res.json(device);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/agent/notifications   (SRS-A07 FR-01..FR-03)
// Returns notifications visible to this device — targeted directly at
// it, at its department, or broadcast org-wide — newest first, each
// flagged with this device's own read status.
router.get("/notifications", async (req, res) => {
  const { device_uid, limit = 50 } = req.query;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const deviceResult = await pool.query(
      `SELECT dv.id, dv.organization_id, e.department_id
       FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id
       WHERE dv.device_uid = $1`,
      [device_uid]
    );
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    const result = await pool.query(
      `SELECT n.id, n.title, n.message, n.notification_type, n.priority, n.sent_at,
              (nr.id IS NOT NULL) AS is_read
       FROM notifications n
       LEFT JOIN notification_reads nr ON nr.notification_id = n.id AND nr.device_id = $1
       WHERE n.organization_id = $2
         AND n.status = 'delivered'
         AND (
           n.target_device_uid = $3
           OR (n.target_department_id IS NOT NULL AND n.target_department_id = $4)
           OR (n.target_device_uid IS NULL AND n.target_department_id IS NULL)
         )
       ORDER BY n.sent_at DESC LIMIT $5`,
      [device.id, device.organization_id, device_uid, device.department_id, limit]
    );

    res.json({
      notifications: result.rows,
      unread_count: result.rows.filter((n) => !n.is_read).length,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/agent/notifications/:id/read   (SRS-A07 FR-06)
router.put("/notifications/:id/read", async (req, res) => {
  const { id } = req.params;
  const { device_uid } = req.body;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const deviceResult = await pool.query("SELECT id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    await pool.query(
      `INSERT INTO notification_reads (notification_id, device_id) VALUES ($1, $2)
       ON CONFLICT (notification_id, device_id) DO NOTHING`,
      [id, device.id]
    );
    res.json({ message: "Marked as read" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/agent/notifications/read-all   (SRS-A07 FR-07)
router.put("/notifications/read-all", async (req, res) => {
  const { device_uid } = req.body;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const deviceResult = await pool.query(
      `SELECT dv.id, dv.organization_id, e.department_id
       FROM devices dv LEFT JOIN employees e ON e.device_id = dv.id
       WHERE dv.device_uid = $1`,
      [device_uid]
    );
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    await pool.query(
      `INSERT INTO notification_reads (notification_id, device_id)
       SELECT n.id, $1 FROM notifications n
       WHERE n.organization_id = $2 AND n.status = 'delivered'
         AND (
           n.target_device_uid = $3
           OR (n.target_department_id IS NOT NULL AND n.target_department_id = $4)
           OR (n.target_device_uid IS NULL AND n.target_department_id IS NULL)
         )
       ON CONFLICT (notification_id, device_id) DO NOTHING`,
      [device.id, device.organization_id, device_uid, device.department_id]
    );
    res.json({ message: "All marked as read" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/agent/unenroll-request   (SRS-A08 More screen — "Unenroll
// device"). Per the mockup, this "requires admin approval" — an
// employee can never self-unenroll a Device-Owner-managed phone (that
// would defeat the point of MDM). This just logs a flagged audit
// event so the admin sees the request and can act on it manually.
router.post("/unenroll-request", async (req, res) => {
  const { device_uid, reason } = req.body;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const deviceResult = await pool.query("SELECT organization_id, model FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    await logAudit({
      organizationId: device.organization_id,
      action: "device_unenroll_requested",
      status: "success",
      req,
      details: `${device.model || device_uid}${reason ? " — " + reason : ""}`,
    });

    res.json({ message: "Unenroll request sent to your administrator" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/agent/support/contact   (SRS-A09 "Contact Admin" row)
router.get("/support/contact", async (req, res) => {
  const { device_uid } = req.query;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const deviceResult = await pool.query("SELECT organization_id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    const adminResult = await pool.query(
      `SELECT u.email, u.name FROM users u
       JOIN roles r ON u.role_id = r.id
       WHERE u.organization_id = $1 AND r.name = 'OrganizationAdmin' AND u.status = 'active'
       ORDER BY u.id ASC LIMIT 1`,
      [device.organization_id]
    );
    let admin = adminResult.rows[0];

    // Fallback: some accounts predate role_id being set consistently
    // at signup — rather than show "no contact" over a data quirk,
    // fall back to any active user in the org.
    if (!admin) {
      const fallbackResult = await pool.query(
        `SELECT email, name FROM users WHERE organization_id = $1 AND status = 'active' ORDER BY id ASC LIMIT 1`,
        [device.organization_id]
      );
      admin = fallbackResult.rows[0];
    }

    res.json({
      admin_name: admin?.name || null,
      admin_email: admin?.email || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/agent/support/tickets   (SRS-A09 FR-01..FR-12, simplified
// to match the mockup — a single description field, no category/
// priority/attachments. Notifies the admin via the existing audit log
// so it's visible immediately without a dedicated dashboard screen.)
router.post("/support/tickets", async (req, res) => {
  const { device_uid, description } = req.body;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });
  if (!description || !description.trim()) return res.status(400).json({ error: "Please describe the issue" });

  try {
    const deviceResult = await pool.query("SELECT id, organization_id, model FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    const insertResult = await pool.query(
      `INSERT INTO support_requests (organization_id, device_id, ticket_number, description)
       VALUES ($1, $2, 'PENDING', $3) RETURNING id`,
      [device.organization_id, device.id, description.trim()]
    );
    const ticketId = insertResult.rows[0].id;
    const ticketNumber = `CN-${String(ticketId).padStart(6, "0")}`;
    await pool.query("UPDATE support_requests SET ticket_number = $1 WHERE id = $2", [ticketNumber, ticketId]);

    await logAudit({
      organizationId: device.organization_id,
      action: "support_ticket_created",
      status: "success",
      req,
      details: `${ticketNumber} (${device.model || device_uid}): ${description.trim().slice(0, 100)}`,
    });

    res.json({ ticket_number: ticketNumber, message: "Support request submitted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
