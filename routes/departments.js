const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");

const router = express.Router();

// POST /api/departments   (Admin only)
router.post("/", requireAuth, async (req, res) => {
  try {
    const { name, default_policy_id } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: "name is required" });
    }
    const result = await pool.query(
      `INSERT INTO departments (organization_id, name, default_policy_id)
       VALUES ($1, $2, $3) RETURNING *`,
      [req.user.organization_id, name.trim(), default_policy_id || null]
    );
    res.status(201).json({ message: "Department created", department: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/departments   (Admin only) — this org's departments, with employee/device counts
router.get("/", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT d.*, p.name AS policy_name,
              (SELECT COUNT(*) FROM employees e WHERE e.department_id = d.id) AS employee_count,
              (SELECT COUNT(*) FROM employees e WHERE e.department_id = d.id AND e.device_id IS NOT NULL) AS device_count
       FROM departments d
       LEFT JOIN policies p ON d.default_policy_id = p.id
       WHERE d.organization_id = $1
       ORDER BY d.created_at DESC`,
      [req.user.organization_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
