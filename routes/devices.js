const express = require("express");
const crypto = require("crypto");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");

const logAudit = require("../utils/auditLog");
const admin = require("../config/firebase");

const router = express.Router();

// POST /api/devices/generate-token   (Admin only)
// Admin dashboard calls this to create a new enrollment code before
// handing a phone to IT for provisioning. Returns a device_uid that
// gets turned into a QR code on the frontend later.
router.post("/generate-token", requireAuth, async (req, res) => {
  try {
    const { employee_name, enrollment_profile_id } = req.body;
    const device_uid = crypto.randomBytes(8).toString("hex"); // e.g. "a1b2c3d4e5f6a7b8"

    let expiryHours = 24;
    if (enrollment_profile_id) {
      const profile = await pool.query("SELECT token_expiry_hours FROM enrollment_profiles WHERE id = $1", [enrollment_profile_id]);
      if (profile.rows[0]) expiryHours = profile.rows[0].token_expiry_hours;
    } else {
      // SRS-017: fall back to the organization's configured default QR expiry
      const orgSettings = await pool.query("SELECT default_qr_expiry_hours FROM organization_settings WHERE organization_id = $1", [req.user.organization_id]);
      if (orgSettings.rows[0]) expiryHours = orgSettings.rows[0].default_qr_expiry_hours;
    }
    const tokenExpiresAt = new Date(Date.now() + expiryHours * 60 * 60 * 1000);

    const result = await pool.query(
      `INSERT INTO devices (device_uid, employee_name, status, organization_id, enrollment_profile_id, token_expires_at)
       VALUES ($1, $2, 'pending', $3, $4, $5) RETURNING *`,
      [device_uid, employee_name || null, req.user.organization_id, enrollment_profile_id || null, tokenExpiresAt]
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

    // BR-03 (SRS-013): enrollment tokens expire after their configured validity period
    const existing = await pool.query("SELECT * FROM devices WHERE device_uid = $1", [device_uid]);
    const pendingDevice = existing.rows[0];
    if (!pendingDevice) {
      return res.status(404).json({ error: "Invalid device_uid — enroll from the dashboard first" });
    }
    if (pendingDevice.token_expires_at && new Date(pendingDevice.token_expires_at) < new Date()) {
      return res.status(410).json({ error: "Enrollment token has expired" });
    }

    const result = await pool.query(
      `UPDATE devices
       SET imei = $1, model = $2, android_version = $3, fcm_token = $4,
           status = 'online', last_seen = NOW()
       WHERE device_uid = $5 RETURNING *`,
      [imei, model, android_version, fcm_token, device_uid]
    );

    const device = result.rows[0];

    // FR-09/FR-10 + BR-05: apply the enrollment profile's default policy
    // right away, the moment enrollment completes.
    if (device.enrollment_profile_id) {
      const profile = await pool.query("SELECT * FROM enrollment_profiles WHERE id = $1", [device.enrollment_profile_id]);
      const defaultPolicyId = profile.rows[0]?.default_policy_id;
      if (defaultPolicyId && fcm_token) {
        const policyResult = await pool.query("SELECT * FROM policies WHERE id = $1", [defaultPolicyId]);
        const policy = policyResult.rows[0];
        if (policy) {
          const commandTypes = [];
          if (policy.camera_blocked) commandTypes.push("block_camera");
          if (policy.bluetooth_blocked) commandTypes.push("block_bluetooth");
          if (policy.wifi_restricted) commandTypes.push("block_wifi");
          if (policy.usb_transfer_blocked) commandTypes.push("block_usb");
          for (const cmdType of commandTypes) {
            try {
              const cmdLog = await pool.query(
                `INSERT INTO commands (device_id, command_type, status) VALUES ($1, $2, 'pending') RETURNING *`,
                [device.id, cmdType]
              );
              await admin.messaging().send({ token: fcm_token, data: { command: cmdType, command_id: String(cmdLog.rows[0].id) } });
              await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1", [cmdLog.rows[0].id]);
            } catch (e) { /* best-effort — enrollment still succeeds either way */ }
          }
          await pool.query("INSERT INTO device_policies (device_id, policy_id) VALUES ($1, $2)", [device.id, policy.id]);
        }
      }
    }

    res.json({ message: "Device enrolled successfully", device });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/devices   (Admin only) — SRS-007: search, filter, sort, pagination
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, status, department_id, android_version, sort, page = 1, limit = 50, organization_id } = req.query;
    const orgId = req.user.is_super_admin ? organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const conditions = ["dv.organization_id = $1"];
    const params = [orgId];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(dv.employee_name ILIKE $${params.length} OR dv.device_uid ILIKE $${params.length} OR dv.model ILIKE $${params.length} OR dv.imei ILIKE $${params.length} OR e.name ILIKE $${params.length} OR d.name ILIKE $${params.length})`);
    }
    if (department_id === "unassigned") {
      conditions.push("d.id IS NULL");
    } else if (department_id) {
      params.push(department_id);
      conditions.push(`d.id = $${params.length}`);
    }
    if (android_version) {
      params.push(android_version);
      conditions.push(`dv.android_version = $${params.length}`);
    }
    if (status === "online") conditions.push("dv.last_seen > NOW() - INTERVAL '90 seconds'");
    else if (status === "offline") conditions.push("(dv.last_seen IS NULL OR dv.last_seen <= NOW() - INTERVAL '90 seconds')");
    else if (status === "pending") conditions.push("dv.status = 'pending'");

    let orderBy = "dv.enrolled_at DESC";
    if (sort === "name") orderBy = "dv.employee_name ASC";
    else if (sort === "battery") orderBy = "dv.battery_level DESC NULLS LAST";
    else if (sort === "android_version") orderBy = "dv.android_version ASC";
    else if (sort === "last_sync") orderBy = "dv.last_seen DESC NULLS LAST";

    const filterParamCount = params.length; // exact count of params actually used by `conditions` above
    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), offset);

    const result = await pool.query(
      `SELECT dv.*, e.name AS assigned_employee_name, e.id AS assigned_employee_id, d.name AS department_name
       FROM devices dv
       LEFT JOIN employees e ON e.device_id = dv.id
       LEFT JOIN departments d ON e.department_id = d.id
       WHERE ${conditions.join(" AND ")}
       ORDER BY ${orderBy}
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM devices dv
       LEFT JOIN employees e ON e.device_id = dv.id
       LEFT JOIN departments d ON e.department_id = d.id
       WHERE ${conditions.join(" AND ")}`,
      params.slice(0, filterParamCount)
    );

    res.json({ devices: result.rows, total: parseInt(countResult.rows[0].count), page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/devices/stats   (SRS-007) — the 6 device statistic cards
router.get("/stats", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? req.query.organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const total = await pool.query("SELECT COUNT(*) FROM devices WHERE organization_id = $1", [orgId]);
    const online = await pool.query("SELECT COUNT(*) FROM devices WHERE organization_id = $1 AND last_seen > NOW() - INTERVAL '90 seconds'", [orgId]);
    const pending = await pool.query("SELECT COUNT(*) FROM devices WHERE organization_id = $1 AND status = 'pending'", [orgId]);
    const rooted = await pool.query("SELECT COUNT(*) FROM devices WHERE organization_id = $1 AND is_rooted = TRUE", [orgId]);
    const lockedCount = await pool.query(
      `SELECT COUNT(DISTINCT device_id) FROM commands c JOIN devices d ON c.device_id = d.id
       WHERE d.organization_id = $1 AND c.command_type = 'lock' AND c.status = 'executed'`,
      [orgId]
    );

    const totalCount = parseInt(total.rows[0].count);
    const onlineCount = parseInt(online.rows[0].count);

    res.json({
      total_devices: totalCount,
      online_devices: onlineCount,
      offline_devices: totalCount - onlineCount,
      pending_enrollment: parseInt(pending.rows[0].count),
      locked_devices: parseInt(lockedCount.rows[0].count),
      policy_violations: parseInt(rooted.rows[0].count),
    });
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

// DELETE /api/devices/:device_uid/policy   (unassign + reverse policy for THIS device only)
router.delete("/:device_uid/policy", requireAuth, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const orgId = req.user.is_super_admin ? req.query.organization_id || req.user.organization_id : req.user.organization_id;

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, orgId]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Selected device does not exist" });

    const latest = await pool.query(
      `SELECT p.* FROM device_policies dp JOIN policies p ON dp.policy_id = p.id
       WHERE dp.device_id = $1 ORDER BY dp.assigned_at DESC LIMIT 1`,
      [device.id]
    );
    const policy = latest.rows[0];

    if (policy && device.fcm_token) {
      const commands = [];
      if (policy.camera_blocked) commands.push({ type: "unblock_camera" });
      if (policy.bluetooth_blocked) commands.push({ type: "unblock_bluetooth" });
      if (policy.wifi_restricted) commands.push({ type: "unblock_wifi" });
      if (policy.usb_transfer_blocked) commands.push({ type: "unblock_usb" });
      if (policy.screenshot_blocked) commands.push({ type: "unblock_screenshot" });
      if (policy.usb_debugging_blocked) commands.push({ type: "unblock_usb_debugging" });
      if (policy.mobile_hotspot_blocked) commands.push({ type: "unblock_hotspot" });
      if (policy.airplane_mode_blocked) commands.push({ type: "unblock_airplane_mode" });
      if (policy.location_services_blocked) commands.push({ type: "unblock_location" });
      if (policy.factory_reset_blocked) commands.push({ type: "unblock_factory_reset" });
      if (policy.kiosk_mode) commands.push({ type: "disable_kiosk" });
      if (policy.blocked_apps) {
        policy.blocked_apps.split(",").map((p) => p.trim()).filter(Boolean).forEach((pkg) => {
          commands.push({ type: "unblock_app", extra: { package_name: pkg } });
        });
      }

      for (const cmd of commands) {
        const cmdLog = await pool.query(
          `INSERT INTO commands (device_id, command_type, issued_by, status) VALUES ($1, $2, $3, 'pending') RETURNING *`,
          [device.id, cmd.type, req.user.id]
        );
        try {
          await admin.messaging().send({ token: device.fcm_token, data: { command: cmd.type, command_id: String(cmdLog.rows[0].id), ...(cmd.extra || {}) } });
          await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1", [cmdLog.rows[0].id]);
        } catch (e) {
          await pool.query("UPDATE commands SET status = 'failed', error_message = $1 WHERE id = $2", [e.message, cmdLog.rows[0].id]);
        }
      }
    }

    await pool.query("DELETE FROM device_policies WHERE device_id = $1", [device.id]);

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "device_policy_unassigned", status: "success", req, details: device_uid });
    res.json({ message: policy ? `Policy "${policy.name}" reversed and unassigned` : "No policy was assigned to this device" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/devices/:device_uid/assign   (SRS-007 FR-09)
// Assigns this device to an employee — the reciprocal of the Employees
// module's "assign device to employee" action.
router.patch("/:device_uid/assign", requireAuth, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const { employee_id } = req.body;
    if (!employee_id) return res.status(400).json({ error: "employee_id is required" });

    const orgId = req.user.is_super_admin ? req.body.organization_id || req.user.organization_id : req.user.organization_id;

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, orgId]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Selected device does not exist" });

    const empResult = await pool.query(
      `SELECT e.* FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.id = $1 AND d.organization_id = $2`,
      [employee_id, orgId]
    );
    const employee = empResult.rows[0];
    if (!employee) return res.status(400).json({ error: "Assigned employee must belong to the same organization" });
    if (employee.status === "suspended") return res.status(409).json({ error: "Cannot assign a device to a suspended employee" });

    // BR-02: one device can be assigned to only one employee at a time
    const alreadyAssigned = await pool.query("SELECT id FROM employees WHERE device_id = $1 AND id != $2", [device.id, employee_id]);
    if (alreadyAssigned.rows.length > 0) {
      return res.status(409).json({ error: "This device is already assigned to another employee" });
    }

    await pool.query("UPDATE employees SET device_id = $1 WHERE id = $2", [device.id, employee_id]);
    await logAudit({ userId: req.user.id, organizationId: orgId, action: "device_assigned", status: "success", req, details: `${device.device_uid} -> employee ${employee_id}` });

    res.json({ message: "Device assigned" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/devices/:device_uid/unassign   (SRS-007 FR-10)
router.patch("/:device_uid/unassign", requireAuth, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const orgId = req.user.is_super_admin ? req.query.organization_id || req.user.organization_id : req.user.organization_id;

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, orgId]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Selected device does not exist" });

    await pool.query("UPDATE employees SET device_id = NULL WHERE device_id = $1", [device.id]);
    await logAudit({ userId: req.user.id, organizationId: orgId, action: "device_unassigned", status: "success", req, details: device.device_uid });

    res.json({ message: "Device unassigned" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/devices/:device_uid   (SRS-007 FR-11) — unenroll / remove device
// BR-05: removed devices lose all policy associations.
router.delete("/:device_uid", requireAuth, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const orgId = req.user.is_super_admin ? req.query.organization_id || req.user.organization_id : req.user.organization_id;

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, orgId]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Selected device does not exist" });

    await pool.query("UPDATE employees SET device_id = NULL WHERE device_id = $1", [device.id]);
    await pool.query("DELETE FROM device_policies WHERE device_id = $1", [device.id]);
    await pool.query("DELETE FROM device_apps WHERE device_id = $1", [device.id]);
    await pool.query("DELETE FROM commands WHERE device_id = $1", [device.id]);
    await pool.query("DELETE FROM devices WHERE id = $1", [device.id]);

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "device_removed", status: "success", req, details: device_uid });

    res.json({ message: "Device removed" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
