const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");

const router = express.Router();

// Small helper — confirms a department belongs to the requesting admin's org,
// so one org's admin can never touch another org's departments/employees.
async function departmentBelongsToOrg(departmentId, organizationId) {
  const result = await pool.query(
    "SELECT id FROM departments WHERE id = $1 AND organization_id = $2",
    [departmentId, organizationId]
  );
  return result.rows.length > 0;
}

// POST /api/employees   (Admin only)
router.post("/", requireAuth, async (req, res) => {
  try {
    const { name, employee_code, department_id } = req.body;
    if (!name || !department_id) {
      return res.status(400).json({ error: "name and department_id are required" });
    }
    if (!(await departmentBelongsToOrg(department_id, req.user.organization_id))) {
      return res.status(404).json({ error: "Department not found" });
    }

    const result = await pool.query(
      `INSERT INTO employees (department_id, name, employee_code)
       VALUES ($1, $2, $3) RETURNING *`,
      [department_id, name, employee_code || null]
    );
    res.status(201).json({ message: "Employee added", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/employees   (Admin only) — every employee in this org, across all departments
router.get("/", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT e.*, d.name AS department_name, dev.device_uid, dev.model
       FROM employees e
       JOIN departments d ON e.department_id = d.id
       LEFT JOIN devices dev ON e.device_id = dev.id
       WHERE d.organization_id = $1
       ORDER BY e.created_at DESC`,
      [req.user.organization_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/assign-device   (Admin only)
router.patch("/:id/assign-device", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { device_uid } = req.body;
    if (!device_uid) {
      return res.status(400).json({ error: "device_uid is required" });
    }

    const deviceResult = await pool.query(
      "SELECT id FROM devices WHERE device_uid = $1 AND organization_id = $2",
      [device_uid, req.user.organization_id]
    );
    const device = deviceResult.rows[0];
    if (!device) {
      return res.status(404).json({ error: "Device not found in your organization" });
    }

    const result = await pool.query(
      `UPDATE employees e SET device_id = $1
       FROM departments d
       WHERE e.id = $2 AND e.department_id = d.id AND d.organization_id = $3
       RETURNING e.*`,
      [device.id, id, req.user.organization_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Employee not found" });
    }
    res.json({ message: "Device assigned", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/status   (Admin only) — suspend / reinstate
router.patch("/:id/status", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // "active" | "suspended"
    if (!["active", "suspended"].includes(status)) {
      return res.status(400).json({ error: "status must be 'active' or 'suspended'" });
    }

    const result = await pool.query(
      `UPDATE employees e SET status = $1
       FROM departments d
       WHERE e.id = $2 AND e.department_id = d.id AND d.organization_id = $3
       RETURNING e.*`,
      [status, id, req.user.organization_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Employee not found" });
    }
    res.json({ message: `Employee ${status}`, employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
