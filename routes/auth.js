const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");

const router = express.Router();

// POST /api/auth/register  -> creates a new organization + its first admin
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

    // Every admin who signs up gets their own organization — their data
    // is scoped to it from here on, and they never see other orgs' data.
    const orgResult = await pool.query(
      "INSERT INTO organizations (name) VALUES ($1) RETURNING id",
      [organization_name]
    );
    const organizationId = orgResult.rows[0].id;

    const password_hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash, organization_id, role) VALUES ($1, $2, $3, $4, 'super_admin') RETURNING id, name, email, organization_id",
      [name, email, password_hash, organizationId]
    );

    res.status(201).json({ message: "Admin and organization created", user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/auth/login -> returns a JWT token
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, organization_id: user.organization_id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role, organization_id: user.organization_id },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/auth/change-password   (Requires login)
router.patch("/change-password", requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) {
      return res.status(400).json({ error: "current_password and new_password are required" });
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

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/auth/api-keys   (Requires login) — generates a new API key
router.post("/api-keys", requireAuth, async (req, res) => {
  try {
    const rawKey = "cn_live_" + crypto.randomBytes(24).toString("hex");
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
    const keyPrefix = rawKey.slice(0, 14); // shown in the list, e.g. "cn_live_82fa1c"

    await pool.query(
      "INSERT INTO api_keys (user_id, key_hash, key_prefix) VALUES ($1, $2, $3)",
      [req.user.id, keyHash, keyPrefix]
    );

    // The full key is only ever shown once, right here — the backend
    // only stores its hash, same practice as a real API key system.
    res.status(201).json({ message: "API key created", key: rawKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/auth/api-keys   (Requires login) — lists this admin's keys (masked)
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
