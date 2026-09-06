const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

// POST /api/enrollment/profiles   (SRS-013 FR-01)
router.post("/profiles", requireAuth, async (req, res) => {
  try {
    const { name, default_policy_id, default_department_id, token_expiry_hours, organization_id } = req.body;
    const orgId = req.user.is_super_admin ? (organization_id || req.user.organization_id) : req.user.organization_id;

    if (!name || !name.trim()) return res.status(400).json({ error: "Profile name is required" });

    const result = await pool.query(
      `INSERT INTO enrollment_profiles (organization_id, name, default_policy_id, default_department_id, token_expiry_hours)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [orgId, name.trim(), default_policy_id || null, default_department_id || null, token_expiry_hours || 24]
    );

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "enrollment_profile_created", status: "success", req, details: name });
    res.status(201).json({ message: "Enrollment profile created", profile: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/enrollment/profiles
router.get("/profiles", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? req.query.organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const result = await pool.query(
      `SELECT ep.*, p.name AS policy_name, d.name AS department_name
       FROM enrollment_profiles ep
       LEFT JOIN policies p ON ep.default_policy_id = p.id
       LEFT JOIN departments d ON ep.default_department_id = d.id
       WHERE ep.organization_id = $1 ORDER BY ep.created_at DESC`,
      [orgId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/enrollment/profiles/:id
router.delete("/profiles/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("UPDATE devices SET enrollment_profile_id = NULL WHERE enrollment_profile_id = $1", [id]);
    const result = await pool.query("DELETE FROM enrollment_profiles WHERE id = $1 RETURNING *", [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Profile not found" });
    res.json({ message: "Enrollment profile deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/enrollment/history   (SRS-013) — enrollment table (device/org/employee/method/status/dates)
router.get("/history", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? req.query.organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const result = await pool.query(
      `SELECT dv.id, dv.device_uid, dv.model, dv.status, dv.enrollment_method, dv.enrolled_at, dv.last_seen,
              dv.token_expires_at, e.name AS assigned_employee_name, dv.employee_name, ep.name AS profile_name
       FROM devices dv
       LEFT JOIN employees e ON e.device_id = dv.id
       LEFT JOIN enrollment_profiles ep ON dv.enrollment_profile_id = ep.id
       WHERE dv.organization_id = $1
       ORDER BY dv.enrolled_at DESC
       LIMIT 200`,
      [orgId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/enrollment/validate/:device_uid   (Called by the Android agent, no login yet)
// SRS-A02 — runs BEFORE /api/devices/confirm. Read-only: lets the agent
// show a confirmation summary (org, policy, profile) and catch an
// expired/invalid/already-used code without side effects, so the user
// can back out before anything is actually registered.
router.get("/validate/:device_uid", async (req, res) => {
  const { device_uid } = req.params;
  try {
    const result = await pool.query(
      `SELECT dv.device_uid, dv.status, dv.fcm_token, dv.token_expires_at, dv.enrollment_method,
              org.name AS organization_name,
              ep.name AS enrollment_profile_name,
              p.name AS policy_name
       FROM devices dv
       LEFT JOIN organizations org ON dv.organization_id = org.id
       LEFT JOIN enrollment_profiles ep ON dv.enrollment_profile_id = ep.id
       LEFT JOIN policies p ON ep.default_policy_id = p.id
       WHERE dv.device_uid = $1`,
      [device_uid]
    );
    const device = result.rows[0];

    if (!device) {
      await logAudit({ action: "device_enrollment_validate", status: "failed", req, details: `${device_uid} — not found` });
      return res.status(404).json({ error: "Invalid enrollment code" });
    }
    if (device.token_expires_at && new Date(device.token_expires_at) < new Date()) {
      await logAudit({ action: "device_enrollment_validate", status: "failed", req, details: `${device_uid} — token expired` });
      return res.status(410).json({ error: "Enrollment token has expired" });
    }
    // FR-10 / BR-03: a device that already completed /confirm (has an
    // FCM token from a previous run) is already managed — block re-use
    // of the same code rather than silently re-registering it.
    if (device.fcm_token) {
      await logAudit({ action: "device_enrollment_validate", status: "failed", req, details: `${device_uid} — already enrolled` });
      return res.status(409).json({ error: "This device is already managed" });
    }

    await logAudit({ action: "device_enrollment_validate", status: "success", req, details: device_uid });
    res.json({
      valid: true,
      organization_name: device.organization_name || "Unknown Organization",
      enrollment_profile_name: device.enrollment_profile_name || null,
      policy_name: device.policy_name || null,
      enrollment_method: device.enrollment_method || "QR Code",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
