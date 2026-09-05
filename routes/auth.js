const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");
const { sendOtpEmail } = require("../config/mailer");

const router = express.Router();

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MINUTES = 15;
const OTP_EXPIRY_MINUTES = 5;
const MAX_OTP_ATTEMPTS = 5;
const MAX_OTP_RESENDS = 3;

const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many login attempts from this network. Please try again later." },
});

function passwordMeetsComplexity(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/.test(password);
}

// ===================== REGISTER =====================
router.post("/register", async (req, res) => {
  try {
    const { name, email, password, organization_name } = req.body;
    if (!name || !email || !password || !organization_name) {
      return res.status(400).json({ error: "name, email, password and organization_name are required" });
    }

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const orgResult = await pool.query(
      "INSERT INTO organizations (name) VALUES ($1) RETURNING id",
      [organization_name]
    );
    const organizationId = orgResult.rows[0].id;

    const roleResult = await pool.query("SELECT id FROM roles WHERE name = 'OrganizationAdmin'");
    const roleId = roleResult.rows[0]?.id || null;

    const password_hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, organization_id, role, role_id, status)
       VALUES ($1, $2, $3, $4, 'super_admin', $5, 'active')
       RETURNING id, name, email, organization_id`,
      [name, email, password_hash, organizationId, roleId]
    );

    res.status(201).json({ message: "Admin and organization created", user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===================== LOGIN (SRS-001) =====================
router.post("/login", loginRateLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email address" });
    }

    const result = await pool.query(
      `SELECT u.*, r.name AS role_name FROM users u
       LEFT JOIN roles r ON u.role_id = r.id
       WHERE u.email = $1`,
      [email]
    );
    const user = result.rows[0];

    if (!user) {
      await logAudit({ action: "login_failed", status: "failure", req, details: `No account for ${email}` });
      return res.status(401).json({ error: "Invalid email or password" });
    }

    if (user.status === "suspended") {
      await logAudit({ userId: user.id, organizationId: user.organization_id, action: "login_failed", status: "failure", req, details: "Account suspended" });
      return res.status(403).json({ error: "Your account has been disabled. Contact your administrator." });
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(429).json({ error: `Too many failed attempts. Try again after ${new Date(user.locked_until).toLocaleTimeString()}.` });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      const attempts = (user.failed_login_attempts || 0) + 1;
      const shouldLock = attempts >= MAX_FAILED_ATTEMPTS;
      await pool.query(
        `UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3`,
        [attempts, shouldLock ? new Date(Date.now() + LOCK_DURATION_MINUTES * 60 * 1000) : null, user.id]
      );
      await logAudit({ userId: user.id, organizationId: user.organization_id, action: "login_failed", status: "failure", req, details: "Wrong password" });
      return res.status(401).json({ error: "Invalid email or password" });
    }

    await pool.query("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1", [user.id]);

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role_name || user.role, organization_id: user.organization_id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    const refreshToken = crypto.randomBytes(40).toString("hex");
    await pool.query(
      `INSERT INTO sessions (user_id, refresh_token, ip_address, browser_info, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        user.id,
        refreshToken,
        req.headers["x-forwarded-for"] || req.socket.remoteAddress,
        req.headers["user-agent"],
        new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      ]
    );

    await logAudit({ userId: user.id, organizationId: user.organization_id, action: "login_success", status: "success", req });

    res.json({
      success: true,
      message: "Login successful",
      token,
      refreshToken,
      role: user.role_name || user.role,
      organizationId: user.organization_id,
      user: { id: user.id, name: user.name, email: user.email, role: user.role_name || user.role, organization_id: user.organization_id },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: "refreshToken is required" });
    }

    const result = await pool.query(
      `SELECT s.*, u.email, u.organization_id, r.name AS role_name FROM sessions s
       JOIN users u ON s.user_id = u.id
       LEFT JOIN roles r ON u.role_id = r.id
       WHERE s.refresh_token = $1 AND s.revoked = FALSE AND s.expires_at > NOW()`,
      [refreshToken]
    );
    const session = result.rows[0];
    if (!session) {
      return res.status(401).json({ error: "Invalid or expired refresh token" });
    }

    const token = jwt.sign(
      { id: session.user_id, email: session.email, role: session.role_name, organization_id: session.organization_id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===================== FORGOT PASSWORD (SRS-002) =====================

router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email address" });
    }

    const userResult = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];
    if (!user) {
      return res.json({ message: "If that email is registered, a verification code has been sent." });
    }

    const recentResends = await pool.query(
      `SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1 AND created_at > NOW() - INTERVAL '15 minutes'`,
      [user.id]
    );
    if (parseInt(recentResends.rows[0].count) >= MAX_OTP_RESENDS) {
      return res.status(429).json({ error: "Too many code requests. Please wait before requesting another." });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, otp_hash, expires_at) VALUES ($1, $2, $3)`,
      [user.id, otpHash, expiresAt]
    );

    await sendOtpEmail(email, otp);
    await logAudit({ userId: user.id, action: "password_reset_requested", status: "success", req, details: email });

    res.json({ message: "If that email is registered, a verification code has been sent." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "A valid 6-digit code is required" });
    }

    const userResult = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];
    if (!user) {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    const tokenResult = await pool.query(
      `SELECT * FROM password_reset_tokens
       WHERE user_id = $1 AND used = FALSE
       ORDER BY created_at DESC LIMIT 1`,
      [user.id]
    );
    const resetToken = tokenResult.rows[0];
    if (!resetToken) {
      return res.status(400).json({ error: "Invalid verification code" });
    }
    if (new Date(resetToken.expires_at) < new Date()) {
      return res.status(400).json({ error: "Verification code has expired" });
    }
    if (resetToken.attempts >= MAX_OTP_ATTEMPTS) {
      return res.status(429).json({ error: "Too many incorrect attempts. Please request a new code." });
    }

    const validOtp = await bcrypt.compare(otp, resetToken.otp_hash);
    if (!validOtp) {
      await pool.query("UPDATE password_reset_tokens SET attempts = attempts + 1 WHERE id = $1", [resetToken.id]);
      return res.status(400).json({ error: "Invalid verification code" });
    }

    await pool.query("UPDATE password_reset_tokens SET verified = TRUE WHERE id = $1", [resetToken.id]);
    res.json({ message: "Code verified" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, password } = req.body;
    if (!email || !otp || !password) {
      return res.status(400).json({ error: "email, otp and password are required" });
    }
    if (!passwordMeetsComplexity(password)) {
      return res.status(400).json({ error: "Password does not meet security requirements (8+ chars, upper, lower, number, symbol)" });
    }

    const userResult = await pool.query("SELECT id, organization_id FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];
    if (!user) {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    const tokenResult = await pool.query(
      `SELECT * FROM password_reset_tokens
       WHERE user_id = $1 AND verified = TRUE AND used = FALSE
       ORDER BY created_at DESC LIMIT 1`,
      [user.id]
    );
    const resetToken = tokenResult.rows[0];
    if (!resetToken) {
      return res.status(400).json({ error: "Please verify your code first" });
    }
    const validOtp = await bcrypt.compare(otp, resetToken.otp_hash);
    if (!validOtp || new Date(resetToken.expires_at) < new Date()) {
      return res.status(400).json({ error: "Verification code is invalid or expired" });
    }

    const newHash = await bcrypt.hash(password, 10);
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [newHash, user.id]);
    await pool.query("UPDATE password_reset_tokens SET used = TRUE WHERE id = $1", [resetToken.id]);

    await pool.query("UPDATE sessions SET revoked = TRUE WHERE user_id = $1", [user.id]);

    await logAudit({ userId: user.id, organizationId: user.organization_id, action: "password_reset_completed", status: "success", req });

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===================== PROFILE (existing) =====================

router.patch("/change-password", requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) {
      return res.status(400).json({ error: "current_password and new_password are required" });
    }
    if (!passwordMeetsComplexity(new_password)) {
      return res.status(400).json({ error: "Password does not meet security requirements (8+ chars, upper, lower, number, symbol)" });
    }

    const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const validPassword = await bcrypt.compare(current_password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    const newHash = await bcrypt.hash(new_password, 10);
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [newHash, req.user.id]);
    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "password_changed", status: "success", req });

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/api-keys", requireAuth, async (req, res) => {
  try {
    const rawKey = "cn_live_" + crypto.randomBytes(24).toString("hex");
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
    const keyPrefix = rawKey.slice(0, 14);

    await pool.query(
      "INSERT INTO api_keys (user_id, key_hash, key_prefix) VALUES ($1, $2, $3)",
      [req.user.id, keyHash, keyPrefix]
    );

    res.status(201).json({ message: "API key created", key: rawKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/api-keys", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, key_prefix, created_at FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
