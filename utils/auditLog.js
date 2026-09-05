const pool = require("../config/db");

// Reusable across every module — every SRS document asks for audit
// logging, so this one helper is called from many route files.
async function logAudit({ userId = null, organizationId = null, action, status, req, details = null }) {
  try {
    const ip = req?.headers?.["x-forwarded-for"] || req?.socket?.remoteAddress || null;
    const browser = req?.headers?.["user-agent"] || null;
    await pool.query(
      `INSERT INTO audit_logs (user_id, organization_id, action, status, ip_address, browser_info, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId, organizationId, action, status, ip, browser, details]
    );
  } catch (err) {
    // Audit logging should never break the actual request
    console.error("Audit log failed:", err.message);
  }
}

module.exports = logAudit;
