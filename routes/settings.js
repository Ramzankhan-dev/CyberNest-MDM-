const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

// Ensures a settings row exists (auto-created with defaults on first read)
async function ensureSettings(organizationId) {
  const existing = await pool.query("SELECT * FROM organization_settings WHERE organization_id = $1", [organizationId]);
  if (existing.rows.length > 0) return existing.rows[0];
  const created = await pool.query(
    "INSERT INTO organization_settings (organization_id) VALUES ($1) RETURNING *",
    [organizationId]
  );
  return created.rows[0];
}

// GET /api/settings   (SRS-017 FR-01/07)
router.get("/", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? req.query.organization_id || req.user.organization_id : req.user.organization_id;
    const settings = await ensureSettings(orgId);
    res.json(settings);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/settings   (SRS-017 FR-01/02/06) — BR-04: security-relevant changes are audited
router.put("/", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? req.query.organization_id || req.user.organization_id : req.user.organization_id;
    await ensureSettings(orgId);

    const {
      time_zone, date_format, max_failed_login_attempts, lockout_duration_minutes,
      session_timeout_minutes, default_qr_expiry_hours,
    } = req.body;

    // FR-02: basic validation on numeric ranges
    if (max_failed_login_attempts !== undefined && (max_failed_login_attempts < 3 || max_failed_login_attempts > 10)) {
      return res.status(400).json({ error: "Configuration value is invalid — max failed attempts must be 3-10" });
    }
    if (session_timeout_minutes !== undefined && (!Number.isInteger(session_timeout_minutes) || session_timeout_minutes < 5 || session_timeout_minutes > 43200)) {
      return res.status(400).json({ error: "Configuration value is invalid — session timeout must be between 5 minutes and 30 days" });
    }

    const result = await pool.query(
      `UPDATE organization_settings SET
        time_zone = COALESCE($1, time_zone), date_format = COALESCE($2, date_format),
        max_failed_login_attempts = COALESCE($3, max_failed_login_attempts),
        lockout_duration_minutes = COALESCE($4, lockout_duration_minutes),
        session_timeout_minutes = COALESCE($5, session_timeout_minutes),
        default_qr_expiry_hours = COALESCE($6, default_qr_expiry_hours),
        updated_at = NOW()
       WHERE organization_id = $7 RETURNING *`,
      [time_zone, date_format, max_failed_login_attempts, lockout_duration_minutes, session_timeout_minutes,
       default_qr_expiry_hours, orgId]
    );

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "settings_updated", status: "success", req, details: JSON.stringify(req.body) });
    res.json({ message: "Settings updated", settings: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/settings/reset   (SRS-017 FR-05) — restore defaults
router.post("/reset", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? req.query.organization_id || req.user.organization_id : req.user.organization_id;
    await pool.query("DELETE FROM organization_settings WHERE organization_id = $1", [orgId]);
    const fresh = await ensureSettings(orgId);

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "settings_reset", status: "success", req });
    res.json({ message: "Settings restored to defaults", settings: fresh });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/settings/health   (SRS-017 "System Health" enterprise addition)
router.get("/health", requireAuth, async (req, res) => {
  try {
    let dbStatus = "Healthy";
    try { await pool.query("SELECT 1"); } catch (e) { dbStatus = "Unhealthy"; }

    let firebaseStatus = "Connected";
    try { require("../config/firebase"); } catch (e) { firebaseStatus = "Not configured"; }

    res.json({
      database: dbStatus,
      api_server: "Running",
      notification_service: firebaseStatus,
      server_time: new Date().toISOString(),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
