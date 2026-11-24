const express = require("express");
const crypto = require("crypto");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const requireRole = require("../middleware/roles");
const { getManagedDepartmentId, blockSuperAdmin } = require("../middleware/roles");

const logAudit = require("../utils/auditLog");
const admin = require("../config/firebase");
const { getDevicePolicies, mergePolicies, pushView, buildCommandsForPolicy, buildUnblockDiff, getEffectivePolicyByUid } = require("../utils/policyCommands");
const { cleanImei } = require("../utils/imei");
const { resolveImeiForDevice } = require("../utils/imeiDedupe");

const router = express.Router();

// POST /api/devices/generate-token   (Organization Admin only —
// Department Managers may link an existing unassigned device to an
// employee in their department, but may not create new devices)
// Admin dashboard calls this to create a new enrollment code before
// handing a phone to IT for provisioning. Returns a device_uid that
// gets turned into a QR code on the frontend later.
router.post("/generate-token", requireAuth, requireRole("OrganizationAdmin"), async (req, res) => {
  try {
    const { employee_name, enrollment_profile_id, department_id } = req.body;
    const device_uid = crypto.randomBytes(8).toString("hex"); // e.g. "a1b2c3d4e5f6a7b8"
    // "unassigned" is a frontend-only pseudo-department (the "Unassigned
    // Devices" bucket) — it is not a real department id, so store null.
    const resolvedDepartmentId = (department_id && department_id !== "unassigned") ? department_id : null;

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
      `INSERT INTO devices (device_uid, employee_name, status, organization_id, enrollment_profile_id, token_expires_at, department_id)
       VALUES ($1, $2, 'pending', $3, $4, $5, $6) RETURNING *`,
      [device_uid, employee_name || null, req.user.organization_id, enrollment_profile_id || null, tokenExpiresAt, resolvedDepartmentId]
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
      await logAudit({ action: "device_enrollment_confirm", status: "failed", req, details: `${device_uid} — not found` });
      return res.status(404).json({ error: "Invalid device_uid — enroll from the dashboard first" });
    }
    if (pendingDevice.token_expires_at && new Date(pendingDevice.token_expires_at) < new Date()) {
      await logAudit({ action: "device_enrollment_confirm", status: "failed", req, details: `${device_uid} — token expired` });
      return res.status(410).json({ error: "Enrollment token has expired" });
    }

    const result = await pool.query(
      `UPDATE devices
       SET imei = COALESCE($1, imei), model = $2, android_version = $3, fcm_token = $4,
           status = 'online', last_seen = NOW()
       WHERE device_uid = $5 RETURNING *`,
      [cleanImei(imei), model, android_version, fcm_token, device_uid]
    );

    const device = result.rows[0];
    await logAudit({ organizationId: device.organization_id, action: "device_enrollment_confirm", status: "success", req, details: device_uid });

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
          await pool.query(
            `INSERT INTO device_policies (device_id, policy_id)
             SELECT $1, $2 WHERE NOT EXISTS (SELECT 1 FROM device_policies WHERE device_id = $1 AND policy_id = $2)`,
            [device.id, policy.id]
          );
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
    if (req.user.role === "DepartmentManager") {
      // The device held by a Department Manager is managed by the Organization Admin only.
      conditions.push("NOT EXISTS (SELECT 1 FROM employees mgr_e WHERE mgr_e.device_id = dv.id AND mgr_e.role = 'DepartmentManager')");
      // A Department Manager only ever sees devices bound to their own
      // department (whether an employee has been assigned yet or not)
      // plus the truly-global unassigned pool — never another
      // department's still-unassigned devices. Overrides whatever
      // department_id filter the request asked for, rather than
      // trusting the client to only ever ask for their own.
      const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
      const deptExpr = "COALESCE(dv.department_id, e.department_id)";
      if (department_id === "unassigned") {
        conditions.push(`${deptExpr} IS NULL`); // the Unassigned card: only the global pool
      } else if (department_id) {
        if (managedDeptId && String(department_id) === String(managedDeptId)) {
          params.push(managedDeptId);
          conditions.push(`${deptExpr} = $${params.length}`); // own department card: only own department
        } else {
          conditions.push("1 = 0"); // any other department: nothing
        }
      } else if (managedDeptId) {
        params.push(managedDeptId);
        conditions.push(`(${deptExpr} = $${params.length} OR ${deptExpr} IS NULL)`); // no card chosen: own + pool (e.g. device pickers)
      } else {
        conditions.push(`${deptExpr} IS NULL`); // not managing any department yet — sees only unassigned
      }
    } else if (department_id === "unassigned") {
      conditions.push("COALESCE(dv.department_id, e.department_id) IS NULL");
    } else if (department_id) {
      params.push(department_id);
      conditions.push(`COALESCE(dv.department_id, e.department_id) = $${params.length}`);
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
      `SELECT dv.*, e.name AS assigned_employee_name, e.id AS assigned_employee_id,
              e.email AS assigned_employee_email, e.phone_number AS assigned_employee_phone, e.designation AS assigned_employee_designation,
              d.name AS department_name, ep.name AS enrollment_profile_name,
              CASE WHEN dv.enrollment_profile_id IS NOT NULL THEN 'Profile Enrollment' ELSE 'Normal Enrollment' END AS enrollment_type
       FROM devices dv
       LEFT JOIN employees e ON e.device_id = dv.id
       LEFT JOIN departments d ON d.id = COALESCE(dv.department_id, e.department_id)
       LEFT JOIN enrollment_profiles ep ON ep.id = dv.enrollment_profile_id
       WHERE ${conditions.join(" AND ")}
       ORDER BY ${orderBy}
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM devices dv
       LEFT JOIN employees e ON e.device_id = dv.id
       LEFT JOIN departments d ON d.id = COALESCE(dv.department_id, e.department_id)
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

// Conflict notices are throttled: a heartbeat arrives every 30s, the audit log needs one entry, not hundreds.
const imeiConflictLoggedAt = new Map();

// After a re-enrollment was merged into an old row, the wiped phone has none of its
// restrictions any more — send the policies assigned to that row again.
async function repushAssignedPolicies(device) {
  if (!device.fcm_token) return;
  const effective = mergePolicies(await getDevicePolicies(pool, device.id));
  for (const cmd of buildCommandsForPolicy(pushView(effective))) {
    try {
      const log = await pool.query(
        `INSERT INTO commands (device_id, command_type, status) VALUES ($1, $2, 'pending') RETURNING *`,
        [device.id, cmd.type]
      );
      await admin.messaging().send({ token: device.fcm_token, data: { command: cmd.type, command_id: String(log.rows[0].id), ...(cmd.extra || {}) } });
      await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1", [log.rows[0].id]);
    } catch (e) { /* best-effort */ }
  }
}

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

    const found = await pool.query("SELECT * FROM devices WHERE device_uid = $1", [device_uid]);
    if (found.rows.length === 0) {
      return res.status(404).json({ error: "Device not found" });
    }
    let device = found.rows[0];

    // Only a real 15-digit IMEI is stored ("Not available" etc. are ignored).
    // A new IMEI is checked against the other devices first, so the same phone
    // never ends up listed twice.
    let imeiToStore = null;
    let imeiNotice = null;
    const realImei = cleanImei(imei);
    if (realImei && realImei !== device.imei) {
      const outcome = await resolveImeiForDevice(pool, device, realImei);
      if (outcome.action === "set") {
        imeiToStore = realImei;
      } else if (outcome.action === "merged") {
        device = outcome.device;
        imeiToStore = realImei;
        await logAudit({ organizationId: device.organization_id, action: "device_re_enrolled", status: "success", req, details: `${outcome.previousUid} -> ${device.device_uid} (same IMEI, existing record reused)` });
        repushAssignedPolicies(device).catch(() => {});
      } else {
        imeiNotice = outcome.message;
        const last = imeiConflictLoggedAt.get(device_uid) || 0;
        if (Date.now() - last > 60 * 60 * 1000) {
          imeiConflictLoggedAt.set(device_uid, Date.now());
          await logAudit({ organizationId: device.organization_id, action: "device_imei_conflict", status: "failed", req, details: `${device_uid}: ${outcome.message}` });
        }
      }
    }

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
       WHERE id = $11 RETURNING *`,
      [battery_level, fcm_token, manufacturer, device_identifier, imeiToStore, ram_gb, storage_total_gb, storage_used_gb, network_info, is_rooted, device.id]
    );

    res.json({ message: "Heartbeat received", device: result.rows[0], ...(imeiNotice ? { imei_conflict: imeiNotice } : {}) });
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
    // Merged result of ALL policies assigned to the device (not just the latest).
    const policy = await getEffectivePolicyByUid(pool, device_uid);
    res.json({ policy: policy || null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/devices/:device_uid/policy-history   (Dashboard-facing, admin auth)
// Every policy this device has been assigned, most recent first — the
// first row is the currently-effective one (same one /current-policy
// returns); the rest is assignment history for visibility.
router.get("/:device_uid/policy-history", requireAuth, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const deviceCheck = await pool.query("SELECT organization_id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceCheck.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });
    if (!req.user.is_super_admin && device.organization_id !== req.user.organization_id) {
      return res.status(404).json({ error: "Device not found" });
    }

    const result = await pool.query(
      `SELECT p.id, p.name, p.camera_blocked, p.bluetooth_blocked, p.wifi_restricted,
              p.usb_transfer_blocked, p.kiosk_mode, dp.assigned_at
       FROM device_policies dp
       JOIN devices d ON dp.device_id = d.id
       JOIN policies p ON dp.policy_id = p.id
       WHERE d.device_uid = $1
       ORDER BY dp.assigned_at DESC`,
      [device_uid]
    );
    res.json({ history: result.rows });
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

// DELETE /api/devices/:device_uid/apps/:package_name   (Called by the Android agent)
// Sent after an app was uninstalled from the device, so it stops showing as
// installed and can be installed again later.
router.delete("/:device_uid/apps/:package_name", async (req, res) => {
  try {
    const { device_uid, package_name } = req.params;
    const deviceResult = await pool.query("SELECT id, organization_id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    await pool.query("DELETE FROM device_apps WHERE device_id = $1 AND package_name = $2", [device.id, package_name]);
    await pool.query(
      `DELETE FROM app_installs WHERE device_id = $1 AND app_package_id IN (
         SELECT id FROM app_packages WHERE organization_id = $2 AND package_name = $3)`,
      [device.id, device.organization_id, package_name]
    );
    res.json({ message: "App removed from device" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/devices/:device_uid/apps/:package_name/status   (Called by the Android agent)
// Keeps the stored status in sync after a block/unblock command runs.
// Upserts rather than plain UPDATE — an admin can block an app from the
// catalog before the device has ever reported it via list_apps, and a
// plain UPDATE would silently affect 0 rows in that case.
router.patch("/:device_uid/apps/:package_name/status", async (req, res) => {
  try {
    const { device_uid, package_name } = req.params;
    const { status } = req.body;

    const deviceResult = await pool.query("SELECT id FROM devices WHERE device_uid = $1", [device_uid]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    await pool.query(
      `INSERT INTO device_apps (device_id, package_name, status)
       VALUES ($1, $2, $3)
       ON CONFLICT (device_id, package_name)
       DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()`,
      [device.id, package_name, status]
    );

    res.json({ message: "Status updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/devices/:device_uid/policy   (unassign + reverse policy for THIS device only)
router.delete("/:device_uid/policy", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const orgId = req.user.organization_id;

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, orgId]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Selected device does not exist" });

    // ?policy_id=<id> removes ONLY that policy (the rest stay assigned and enforced);
    // without it every policy on the device is reversed and removed.
    const allPolicies = await getDevicePolicies(pool, device.id);
    const targetId = req.query.policy_id ? String(req.query.policy_id) : null;
    let removed = allPolicies;
    let remaining = [];
    if (targetId) {
      removed = allPolicies.filter((p) => String(p.id) === targetId);
      if (removed.length === 0) return res.status(409).json({ error: "That policy is not assigned to this device" });
      remaining = allPolicies.filter((p) => String(p.id) !== targetId);
    }

    if (removed.length > 0 && device.fcm_token) {
      // Undo only what no remaining policy still needs, then re-assert what the remaining ones require.
      const commands = [
        ...buildUnblockDiff(mergePolicies(allPolicies), mergePolicies(remaining)),
        ...(remaining.length > 0 ? buildCommandsForPolicy(pushView(mergePolicies(remaining))) : []),
      ];

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

    if (targetId) {
      await pool.query("DELETE FROM device_policies WHERE device_id = $1 AND policy_id = $2", [device.id, targetId]);
    } else {
      await pool.query("DELETE FROM device_policies WHERE device_id = $1", [device.id]);
    }

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "device_policy_unassigned", status: "success", req, details: device_uid });
    res.json({ message: removed.length > 0 ? `Policy "${removed.map((p) => p.name).join(", ")}" reversed and unassigned` : "No policy was assigned to this device" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/devices/:device_uid/assign   (SRS-007 FR-09)
// Assigns this device to an employee — the reciprocal of the Employees
// module's "assign device to employee" action.
router.patch("/:device_uid/assign", requireAuth, requireRole("OrganizationAdmin", "DepartmentManager"), async (req, res) => {
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

    // A Department Manager may only link a device to an employee
    // within the department they manage.
    if (req.user.role === "DepartmentManager") {
      const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
      if (!managedDeptId || employee.department_id !== managedDeptId) {
        return res.status(403).json({ error: "You can only assign devices to employees in your own department" });
      }
    }

    // BR-02: one device can be assigned to only one employee at a time
    const alreadyAssigned = await pool.query("SELECT id FROM employees WHERE device_id = $1 AND id != $2", [device.id, employee_id]);
    if (alreadyAssigned.rows.length > 0) {
      return res.status(409).json({ error: "This device is already assigned to another employee" });
    }

    await pool.query("UPDATE employees SET device_id = $1 WHERE id = $2", [device.id, employee_id]);
    // Keeps the device's own department_id in sync with whoever it's
    // now assigned to — the authoritative field going forward for
    // department-scoping, rather than only resolving it indirectly
    // through the employee link every time.
    await pool.query("UPDATE devices SET department_id = $1, employee_name = $2 WHERE id = $3", [employee.department_id, employee.name, device.id]);
    await logAudit({ userId: req.user.id, organizationId: orgId, action: "device_assigned", status: "success", req, details: `${device.device_uid} -> employee ${employee_id}` });

    res.json({ message: "Device assigned" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/devices/:device_uid/unassign   (SRS-007 FR-10)
router.patch("/:device_uid/unassign", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const orgId = req.user.organization_id;

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, orgId]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Selected device does not exist" });

    await pool.query("UPDATE employees SET device_id = NULL WHERE device_id = $1", [device.id]);
    await pool.query("UPDATE devices SET employee_name = NULL WHERE id = $1", [device.id]);
    await logAudit({ userId: req.user.id, organizationId: orgId, action: "device_unassigned", status: "success", req, details: device.device_uid });

    res.json({ message: "Device unassigned" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/devices/:device_uid   (SRS-007 FR-11) — unenroll / remove device
// BR-05: removed devices lose all policy associations.
router.delete("/:device_uid", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const orgId = req.user.organization_id;

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

// POST /api/devices/:device_uid/geofence   (Admin only)
// Body: { lat, lng, radius_meters }. Circular geofence only — Android's
// native GeofencingClient supports circles directly (efficient,
// OS-managed monitoring); a rectangular/2-point boundary would need
// the app to manually poll GPS on its own, which is far less
// battery-friendly and wasn't worth it for what this adds.
router.post("/:device_uid/geofence", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const { lat, lng } = req.body;
    if (lat == null || lng == null || !req.body.radius_meters) {
      return res.status(400).json({ error: "lat, lng, and radius_meters are required" });
    }
    // Small radii (15-50m) are allowed on purpose so geofence alerts can be
    // demonstrated without walking 100m+; accuracy below ~100m depends on
    // GPS/Wi-Fi (the dashboard shows a warning).
    const latNum = Number(lat), lngNum = Number(lng), radiusNum = Number(req.body.radius_meters);
    if (!Number.isFinite(latNum) || latNum < -90 || latNum > 90) return res.status(400).json({ error: "Latitude must be between -90 and 90" });
    if (!Number.isFinite(lngNum) || lngNum < -180 || lngNum > 180) return res.status(400).json({ error: "Longitude must be between -180 and 180" });
    if (!Number.isFinite(radiusNum) || radiusNum < 1 || radiusNum > 100000) return res.status(400).json({ error: "Radius must be between 1 and 100000 meters" });
    const radius_meters = Math.round(radiusNum);

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, req.user.organization_id]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    await pool.query(
      "UPDATE devices SET geofence_lat = $1, geofence_lng = $2, geofence_radius_meters = $3, geofence_enabled = TRUE WHERE id = $4",
      [lat, lng, radius_meters, device.id]
    );

    if (device.fcm_token) {
      try {
        await admin.messaging().send({
          token: device.fcm_token,
          data: { command: "set_geofence", lat: String(lat), lng: String(lng), radius_meters: String(radius_meters) },
        });
      } catch (err) {
        // Geofence is saved either way — device will pick it up on its
        // next policy/heartbeat cycle even if this specific push failed.
      }
    }

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "geofence_set", status: "success", req, details: `${device_uid} — ${radius_meters}m radius` });
    res.json({ message: "Geofence saved" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/devices/:device_uid/geofence   (Admin only)
router.delete("/:device_uid/geofence", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, req.user.organization_id]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    await pool.query("UPDATE devices SET geofence_enabled = FALSE WHERE id = $1", [device.id]);

    if (device.fcm_token) {
      try {
        await admin.messaging().send({ token: device.fcm_token, data: { command: "clear_geofence" } });
      } catch (err) {
        // Same as above — state is saved regardless of push success.
      }
    }

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "geofence_removed", status: "success", req, details: device_uid });
    res.json({ message: "Geofence removed" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/devices/:device_uid/geofence-alerts   (Admin only) — history
router.get("/:device_uid/geofence-alerts", requireAuth, async (req, res) => {
  try {
    const { device_uid } = req.params;
    const deviceResult = await pool.query("SELECT id FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, req.user.organization_id]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    const result = await pool.query(
      "SELECT lat, lng, triggered_at FROM geofence_alerts WHERE device_id = $1 ORDER BY triggered_at DESC LIMIT 50",
      [device.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
