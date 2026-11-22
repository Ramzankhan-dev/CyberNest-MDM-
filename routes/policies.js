const express = require("express");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");
const requireRole = require("../middleware/roles");
const { getManagedDepartmentId, blockSuperAdmin } = require("../middleware/roles");
const logAudit = require("../utils/auditLog");
const {
  mergePolicies, getDevicePolicies, getAssignedPolicies, isActive, pushView,
  buildCommandsForPolicy, buildUnblockDiff,
} = require("../utils/policyCommands");

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
router.post("/", requireAuth, requireRole("OrganizationAdmin"), async (req, res) => {
  try {
    const { name, policy_code, description, organization_id } = req.body;
    const orgId = req.user.organization_id;

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
      const val = req.body[field];
      values.push(val === "" || val === undefined ? null : val);
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

    const filterParamCount = params.length;
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

    const countResult = await pool.query(`SELECT COUNT(*) FROM policies p WHERE ${conditions.join(" AND ")}`, params.slice(0, filterParamCount));

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
router.put("/:id", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Policy not found" });
    const policy = existing.rows[0];
    if (policy.organization_id !== req.user.organization_id) {
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
        const val = req.body[field];
        values.push(val === "" ? null : val);
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
router.post("/:id/duplicate", requireAuth, blockSuperAdmin, async (req, res) => {
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
router.patch("/:id/status", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!["active", "disabled"].includes(status)) return res.status(400).json({ error: "status must be active or disabled" });

    const before = await pool.query("SELECT status FROM policies WHERE id = $1", [id]);
    if (before.rows.length === 0) return res.status(404).json({ error: "Policy not found" });
    const wasActive = (before.rows[0].status || "active") === "active";

    const result = await pool.query("UPDATE policies SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *", [status, id]);

    // Disabling removes this policy's effect from every device it is assigned to
    // (rules another active policy still needs stay); enabling applies it again.
    // The assignment itself is kept, so Enable restores it without re-assigning.
    let devicesUpdated = 0;
    if (wasActive !== (status === "active")) {
      const assignedDevices = await pool.query(
        `SELECT DISTINCT dv.* FROM devices dv JOIN device_policies dp ON dp.device_id = dv.id WHERE dp.policy_id = $1`,
        [id]
      );
      for (const device of assignedDevices.rows) {
        if (!device.fcm_token) continue;
        try {
          const assigned = await getAssignedPolicies(pool, device.id); // statuses already updated
          const beforeSet = assigned.filter((p) => (String(p.id) === String(id) ? wasActive : isActive(p)));
          const afterSet = assigned.filter((p) => (String(p.id) === String(id) ? status === "active" : isActive(p)));
          const unblock = buildUnblockDiff(mergePolicies(beforeSet), mergePolicies(afterSet));
          const reapply = buildCommandsForPolicy(pushView(mergePolicies(afterSet)));
          for (const cmd of [...unblock, ...reapply]) {
            await sendCommandToDevice(device, cmd.type, req.user.id, cmd.extra || {});
          }
          devicesUpdated++;
        } catch (e) {
          console.error(`Policy ${status}: failed to update device ${device.device_uid}:`, e.message);
        }
      }
    }

    await logAudit({ userId: req.user.id, organizationId: result.rows[0].organization_id, action: `policy_${status}`, status: "success", req, details: devicesUpdated ? `${devicesUpdated} device(s) updated` : undefined });
    res.json({
      message: devicesUpdated ? `Policy ${status} - ${devicesUpdated} device(s) updated` : `Policy ${status}`,
      policy: result.rows[0],
      devices_updated: devicesUpdated,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/policies/:id/unassign   (removes this policy's device assignments)
// Genuinely reverses the policy on each device — sends the matching
// unblock_* commands — then clears the assignment record.
router.delete("/:id/unassign", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const policyResult = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    const policy = policyResult.rows[0];
    if (!policy) return res.status(404).json({ error: "Policy not found" });

    const assignedDevices = await pool.query(
      `SELECT DISTINCT dv.* FROM devices dv JOIN device_policies dp ON dp.device_id = dv.id WHERE dp.policy_id = $1`,
      [id]
    );

    // Only undo what no OTHER policy on the same device still needs, then
    // re-apply whatever the remaining policies require.
    let notified = 0;
    for (const device of assignedDevices.rows) {
      if (device.fcm_token) {
        const all = await getDevicePolicies(pool, device.id);
        const remaining = all.filter((p) => String(p.id) !== String(policy.id));
        const unblockCommands = buildUnblockDiff(mergePolicies(all), mergePolicies(remaining));
        const reapplyCommands = buildCommandsForPolicy(pushView(mergePolicies(remaining)));
        for (const cmd of [...unblockCommands, ...reapplyCommands]) {
          await sendCommandToDevice(device, cmd.type, req.user.id, cmd.extra || {});
        }
        notified++;
      }
    }

    await pool.query("DELETE FROM device_policies WHERE policy_id = $1", [id]);
    await pool.query("UPDATE departments SET default_policy_id = NULL WHERE default_policy_id = $1", [id]);

    await logAudit({ userId: req.user.id, organizationId: policy.organization_id, action: "policy_unassigned_all", status: "success", req, details: `${assignedDevices.rows.length} device(s), ${notified} notified` });
    res.json({ message: `Reversed and unassigned from ${assignedDevices.rows.length} device(s)`, count: assignedDevices.rows.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/policies/:id   (SRS-009 BR-05)
router.delete("/:id", requireAuth, blockSuperAdmin, async (req, res) => {
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

    // Clear any enrollment profile using this as its default policy first,
    // so the foreign key doesn't block the delete.
    await pool.query("UPDATE enrollment_profiles SET default_policy_id = NULL WHERE default_policy_id = $1", [id]);
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

// POST /api/policies/:id/assign   (SRS-009 FR-04) — assign to one device
router.post("/:id/assign", requireAuth, requireRole("OrganizationAdmin", "DepartmentManager"), async (req, res) => {
  try {
    const { id } = req.params;
    const { device_uid } = req.body;
    if (!device_uid) return res.status(400).json({ error: "Select at least one device or department" });

    const policyResult = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    const policy = policyResult.rows[0];
    if (!policy) return res.status(404).json({ error: "Policy not found" });
    if (!isActive(policy)) return res.status(400).json({ error: "This policy is disabled. Enable it before assigning." });

    const deviceResult = await pool.query(
      `SELECT dv.*, e.department_id AS employee_department_id, e.role AS employee_role FROM devices dv
       LEFT JOIN employees e ON e.device_id = dv.id
       WHERE dv.device_uid = $1 AND dv.organization_id = $2`,
      [device_uid, policy.organization_id]
    );
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Selected device does not exist" });
    if (!device.fcm_token) return res.status(400).json({ error: "This device has no FCM token yet" });

    // Department Managers can only apply policies to devices held by
    // an employee in the department they manage.
    if (req.user.role === "DepartmentManager") {
      const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
      if (!managedDeptId || device.employee_department_id !== managedDeptId) {
        return res.status(403).json({ error: "You can only manage devices in your own department" });
      }
      if (device.employee_role === "DepartmentManager") {
        return res.status(403).json({ error: "This device can only be managed by the Organization Admin" });
      }
    }

    // A device can hold several policies at once: build the commands from
    // ALL of them merged, so this assignment never cancels an earlier one.
    const existing = (await getDevicePolicies(pool, device.id)).filter((p) => String(p.id) !== String(policy.id));
    const commands = buildCommandsForPolicy(pushView(mergePolicies([...existing, policy])));
    for (const cmd of commands) {
      await sendCommandToDevice(device, cmd.type, req.user.id, cmd.extra || {});
    }

    await pool.query(`DELETE FROM device_policies WHERE device_id = $1 AND policy_id = $2`, [device.id, policy.id]);
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
router.post("/:id/assign-department", requireAuth, requireRole("OrganizationAdmin", "DepartmentManager"), async (req, res) => {
  try {
    const { id } = req.params;
    const { department_id } = req.body;
    if (!department_id) return res.status(400).json({ error: "Select at least one device or department" });

    if (req.user.role === "DepartmentManager") {
      const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
      if (!managedDeptId || Number(department_id) !== managedDeptId) {
        return res.status(403).json({ error: "You can only manage your own department" });
      }
    }

    const policyResult = await pool.query("SELECT * FROM policies WHERE id = $1", [id]);
    const policy = policyResult.rows[0];
    if (!policy) return res.status(404).json({ error: "Policy not found" });
    if (!isActive(policy)) return res.status(400).json({ error: "This policy is disabled. Enable it before assigning." });

    const devicesResult = await pool.query(
      `SELECT dv.* FROM devices dv JOIN employees e ON e.device_id = dv.id
       WHERE e.department_id = $1 AND dv.fcm_token IS NOT NULL`,
      [department_id]
    );

    let count = 0;
    for (const device of devicesResult.rows) {
      const existing = (await getDevicePolicies(pool, device.id)).filter((p) => String(p.id) !== String(policy.id));
      const commands = buildCommandsForPolicy(pushView(mergePolicies([...existing, policy])));
      for (const cmd of commands) {
        await sendCommandToDevice(device, cmd.type, req.user.id, cmd.extra || {});
      }
      await pool.query(`DELETE FROM device_policies WHERE device_id = $1 AND policy_id = $2`, [device.id, policy.id]);
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
