const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");

const router = express.Router();

// GET /api/organizations/me   (Admin only) — this admin's own organization + stats
router.get("/me", requireAuth, async (req, res) => {
  try {
    const orgResult = await pool.query("SELECT * FROM organizations WHERE id = $1", [req.user.organization_id]);
    const org = orgResult.rows[0];
    if (!org) {
      return res.status(404).json({ error: "Organization not found" });
    }

    const deptCount = await pool.query("SELECT COUNT(*) FROM departments WHERE organization_id = $1", [org.id]);
    const deviceCount = await pool.query("SELECT COUNT(*) FROM devices WHERE organization_id = $1", [org.id]);
    const adminCount = await pool.query("SELECT COUNT(*) FROM users WHERE organization_id = $1", [org.id]);

    res.json({
      ...org,
      department_count: parseInt(deptCount.rows[0].count),
      device_count: parseInt(deviceCount.rows[0].count),
      admin_count: parseInt(adminCount.rows[0].count),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/organizations/me   (Admin only) — rename own organization
router.patch("/me", requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: "name is required" });
    }
    const result = await pool.query(
      "UPDATE organizations SET name = $1 WHERE id = $2 RETURNING *",
      [name.trim(), req.user.organization_id]
    );
    res.json({ message: "Organization updated", organization: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
