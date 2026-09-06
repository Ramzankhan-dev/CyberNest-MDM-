const express = require("express");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

const POLICY_FIELDS = [
  "camera_blocked", "bluetooth_blocked", "wifi_restricted", "usb_transfer_blocked",
  "screenshot_blocked", "usb_debugging_blocked", "mobile_hotspot_blocked",
  "airplane_mode_blocked", "location_services_blocked", "factory_reset_blocked",
  "password_required", "password_min_length", "max_failed_attempts", "auto_lock_timeout_minutes",
  "blocked_apps", "prevent_unknown_sources", "prevent_play_store",
  "root_detection_enabled", "developer_options_disabled",
  "vpn_required", "mobile_data_restricted",
  "kiosk_mode", "kiosk_package", "working_hours_start", "working_hours_end",
];

function isValidCode(code) {
  return /^[A-Z0-9]{2,20}$/.test(code);
}

async function snapshotVersion(policyId, userId) {
  const result = await pool.query("SELECT * FROM policies WHERE id = $1", [policyId]);
  const policy = result.rows[0];
  await pool.query(
    "INSERT INTO policy_versions (policy_id, version, snapshot, changed_by) VALUES ($1, $2, $3, $4)",
    [policyId, policy.version, JSON.stringify(policy), userId]
  );
}

// POST /api/policies   (SRS-009 FR-01)
router.post("/", requireAuth, async (req, res) => {
  try {
    const { name, policy_code, description, organization_id } = req.body;
    const orgId = req.user.is_super_admin ? (organization_id || req.user.organization_id) : req.user.organization_id;

    if (!name || !name.trim()) {
      return res.status(400).json({ error: "Policy name is required" });
    }
    if (!policy_code || !isValidCode(policy_code)) {
      return res.status(400).json({ error: "Policy code must be 2-20 uppercase letters/numbers" });
    }

    // BR-02: policy names unique within an organization
    const dupName = await pool.query(
      "SELECT id FROM policies WHERE organization_id = $1 AND LOWER(name) = LOWER($2)",
      [orgId, name.trim()]
    );
    if (dupName.rows.length > 0) return res.status(409).json({ error: "Policy name already exists" });

    const dupCode = await pool.query("SELECT id FROM policies WHERE organization_id = $1 AND policy_code = $2", [orgId, policy_code]);
    if (dupCode.rows.length > 0) return res.status(409).json({ error: "Policy code already exists" });

    const columns = ["name", "policy_code", "description", "organization_id"];
    const values = [name.trim(), policy_code, description || null, orgId];
    const placeholders = ["$1", "$2", "$3", "$4"];

    POLICY_FIELDS.forEach((field) => {
      columns.push(field);
      values.push(req.body[field] ?? null);
      placeholders.push(`$${values.length}`);
    });

    const result = await pool.query(
      `INSERT INTO policies (${columns.join(", ")}) VALUES (${placeholders.join(", ")}) RETURNING *`,
      values
    );
    const policy = result.rows[0];
    await snapshotVersion(policy.id, req.user.id);

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "policy_created", status: "success", req, details: name });
    res.status(201).json({ message: "Policy created", policy });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/policies   (SRS-009) — search, filter, sort, pagination
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, status, sort, page = 1, limit = 50, organization_id } = req.query;
    const orgId = req.user.is_super_admin ? organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const conditions = ["p.organization_id = $1"];
    const params = [orgId];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(p.name ILIKE $${params.length} OR p.policy_code ILIKE $${params.length})`);
    }
    if (status) {
      params.push(status);
      conditions.push(`p.status = $${params.length}`);
    }

    let orderBy = "p.updated_at DESC NULLS LAST, p.created_at DESC";
    if (sort === "name") orderBy = "p.name ASC";

    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), offset);

    const result = await pool.query(
      `SELECT p.*,
              (SELECT COUNT(*) FROM device_policies dp WHERE dp.policy_id = p.id) AS assigned_devices_count,
              (SELECT COUNT(*) FROM departments d WHERE d.default_policy_id = p.id) AS assigned_departments_count
       FROM policies p
       WHERE ${conditions.join(" AND ")}
       ORDER BY ${orderBy}
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countResult = await pool.query(`SELECT COUNT(*) FROM policies p WHERE ${conditions.join(" AND ")}`, params.slice(0, conditions.length));

    res.json({ policies: result.rows, total: parseInt(countResult.rows[0].count), page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/policies/:id/versions   (SRS-009 FR-09)
router.get("/:id/versions", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query("SELECT * FROM policy_versions WHERE policy_id = $1 ORDER BY version DESC", [id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/policies/:id   (SRS-009) — BR-03: updates create a new version
router.put("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Policy not found" });
    const policy = existing.rows[0];
    if (!req.user.is_super_admin && policy.organization_id !== req.user.organization_id) {
      return res.status(404).json({ error: "Policy not found" });
    }

    const { name, description } = req.body;
    if (name) {
      const dupName = await pool.query(
        "SELECT id FROM policies WHERE organization_id = $1 AND LOWER(name) = LOWER($2) AND id != $3",
        [policy.organization_id, name.trim(), id]
      );
      if (dupName.rows.length > 0) return res.status(409).json({ error: "Policy name already exists" });
    }

    const setClauses = ["name = COALESCE($1, name)", "description = COALESCE($2, description)", "version = version + 1", "updated_at = NOW()"];
    const values = [name, description];

    POLICY_FIELDS.forEach((field) => {
      if (req.body[field] !== undefined) {
        values.push(req.body[field]);
        setClauses.push(`${field} = $${values.length}`);
      }
    });

    values.push(id);
    const result = await pool.query(`UPDATE policies SET ${setClauses.join(", ")} WHERE id = $${values.length} RETURNING *`, values);
    await snapshotVersion(id, req.user.id);

    await logAudit({ userId: req.user.id, organizationId: policy.organization_id, action: "policy_updated", status: "success", req });
    res.json({ message: "Policy updated", policy: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/policies/:id/duplicate   (SRS-009 FR-03)
router.post("/:id/duplicate", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Policy not found" });
    const src = existing.rows[0];

    let newName = `${src.name} (Copy)`;
    let counter = 2;
    while ((await pool.query("SELECT id FROM policies WHERE organization_id = $1 AND LOWER(name) = LOWER($2)", [src.organization_id, newName])).rows.length > 0) {
      newName = `${src.name} (Copy ${counter})`;
      counter++;
    }
    const newCode = `${src.policy_code}C${Date.now().toString().slice(-4)}`;

    const columns = ["name", "policy_code", "description", "organization_id", ...POLICY_FIELDS];
    const values = [newName, newCode, src.description, src.organization_id, ...POLICY_FIELDS.map((f) => src[f])];
    const placeholders = values.map((_, i) => `$${i + 1}`);

    const result = await pool.query(
      `INSERT INTO policies (${columns.join(", ")}) VALUES (${placeholders.join(", ")}) RETURNING *`,
      values
    );
    await snapshotVersion(result.rows[0].id, req.user.id);

    await logAudit({ userId: req.user.id, organizationId: src.organization_id, action: "policy_duplicated", status: "success", req, details: newName });
    res.status(201).json({ message: "Policy duplicated", policy: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/policies/:id/status   (SRS-009 FR-08)
router.patch("/:id/status", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!["active", "disabled"].includes(status)) return res.status(400).json({ error: "status must be active or disabled" });

    const result = await pool.query("UPDATE policies SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *", [status, id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Policy not found" });

    await logAudit({ userId: req.user.id, organizationId: result.rows[0].organization_id, action: `policy_${status}`, status: "success", req });
    res.json({ message: `Policy ${status}`, policy: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/policies/:id   (SRS-009 BR-05)
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const assigned = await pool.query("SELECT COUNT(*) FROM device_policies WHERE policy_id = $1", [id]);
    if (parseInt(assigned.rows[0].count) > 0) {
      return res.status(409).json({ error: "This policy is currently assigned to devices. Unassign it first." });
    }
    const deptUsing = await pool.query("SELECT COUNT(*) FROM departments WHERE default_policy_id = $1", [id]);
    if (parseInt(deptUsing.rows[0].count) > 0) {
      return res.status(409).json({ error: "This policy is set as a department's default. Unassign it first." });
    }

    const existing = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Policy not found" });

    await pool.query("DELETE FROM policy_versions WHERE policy_id = $1", [id]);
    await pool.query("DELETE FROM policies WHERE id = $1", [id]);

    await logAudit({ userId: req.user.id, organizationId: existing.rows[0].organization_id, action: "policy_deleted", status: "success", req });
    res.json({ message: "Policy deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Sends one command to a device via FCM and logs it — shared helper
// so applying a policy can fire off several commands in one go.
async function sendCommandToDevice(device, commandType, issuedBy, extra = {}) {
  const commandLog = await pool.query(
    `INSERT INTO commands (device_id, command_type, issued_by, status)
     VALUES ($1, $2, $3, 'pending') RETURNING *`,
    [device.id, commandType, issuedBy]
  );

  const messageData = {
    command: commandType,
    command_id: String(commandLog.rows[0].id),
    ...extra,
  };

  await admin.messaging().send({ token: device.fcm_token, data: messageData });
  await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1", [commandLog.rows[0].id]);
}

function buildCommandsForPolicy(policy) {
  const commands = [];
  if (policy.camera_blocked) commands.push({ type: "block_camera" });
  if (policy.bluetooth_blocked) commands.push({ type: "block_bluetooth" });
  if (policy.wifi_restricted) commands.push({ type: "block_wifi" });
  if (policy.usb_transfer_blocked) commands.push({ type: "block_usb" });
  if (policy.screenshot_blocked) commands.push({ type: "block_screenshot" });
  if (policy.usb_debugging_blocked) commands.push({ type: "block_usb_debugging" });
  if (policy.mobile_hotspot_blocked) commands.push({ type: "block_hotspot" });
  if (policy.airplane_mode_blocked) commands.push({ type: "block_airplane_mode" });
  if (policy.location_services_blocked) commands.push({ type: "block_location" });
  if (policy.factory_reset_blocked) commands.push({ type: "block_factory_reset" });
  if (policy.auto_lock_timeout_minutes) commands.push({ type: "set_auto_lock", extra: { minutes: String(policy.auto_lock_timeout_minutes) } });
  if (policy.password_required && policy.password_min_length) {
    commands.push({ type: "set_password_policy", extra: { min_length: String(policy.password_min_length), max_failed: String(policy.max_failed_attempts || 5) } });
  }
  if (policy.blocked_apps) {
    policy.blocked_apps.split(",").map((p) => p.trim()).filter(Boolean).forEach((pkg) => {
      commands.push({ type: "block_app", extra: { package_name: pkg } });
    });
  }
  if (policy.kiosk_mode) commands.push({ type: "enable_kiosk", extra: policy.kiosk_package ? { package_name: policy.kiosk_package } : {} });
  return commands;
}

// POST /api/policies/:id/assign   (SRS-009 FR-04) — assign to one device
router.post("/:id/assign", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { device_uid } = req.body;
    if (!device_uid) return res.status(400).json({ error: "Select at least one device or department" });

    const policyResult = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    const policy = policyResult.rows[0];
    if (!policy) return res.status(404).json({ error: "Policy not found" });

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, policy.organization_id]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Selected device does not exist" });
    if (!device.fcm_token) return res.status(400).json({ error: "This device has no FCM token yet" });

    const commands = buildCommandsForPolicy(policy);
    for (const cmd of commands) {
      await sendCommandToDevice(device, cmd.type, req.user.id, cmd.extra || {});
    }

    await pool.query(`INSERT INTO device_policies (device_id, policy_id) VALUES ($1, $2)`, [device.id, policy.id]);
    await logAudit({ userId: req.user.id, organizationId: policy.organization_id, action: "policy_assigned", status: "success", req, details: `${policy.name} -> ${device_uid}` });

    res.json({ message: `Policy "${policy.name}" applied`, commands_sent: commands.map((c) => c.type) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// POST /api/policies/:id/assign-department   (SRS-009 FR-04) — assign to every
// device currently held by employees in a department
router.post("/:id/assign-department", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { department_id } = req.body;
    if (!department_id) return res.status(400).json({ error: "Select at least one device or department" });

    const policyResult = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    const policy = policyResult.rows[0];
    if (!policy) return res.status(404).json({ error: "Policy not found" });

    const devicesResult = await pool.query(
      `SELECT dv.* FROM devices dv JOIN employees e ON e.device_id = dv.id
       WHERE e.department_id = $1 AND dv.fcm_token IS NOT NULL`,
      [department_id]
    );

    let count = 0;
    for (const device of devicesResult.rows) {
      const commands = buildCommandsForPolicy(policy);
      for (const cmd of commands) {
        await sendCommandToDevice(device, cmd.type, req.user.id, cmd.extra || {});
      }
      await pool.query(`INSERT INTO device_policies (device_id, policy_id) VALUES ($1, $2)`, [device.id, policy.id]);
      count++;
    }

    await pool.query("UPDATE departments SET default_policy_id = $1 WHERE id = $2", [policy.id, department_id]);
    await logAudit({ userId: req.user.id, organizationId: policy.organization_id, action: "policy_assigned_department", status: "success", req, details: `${policy.name} -> dept ${department_id} (${count} devices)` });

    res.json({ message: `Policy applied to ${count} device(s) in department` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

module.exports = router;
