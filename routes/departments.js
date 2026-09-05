const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

function isValidCode(code) {
  return /^[A-Z0-9]{2,20}$/.test(code);
}

// POST /api/departments   (SRS-005)
router.post("/", requireAuth, async (req, res) => {
  try {
    const { name, code, manager_employee_id, description, default_policy_id, status, organization_id } = req.body;
    // Super Admin can create a department in ANY organization by passing
    // organization_id; a regular admin is always scoped to their own.
    const orgId = req.user.is_super_admin ? (organization_id || req.user.organization_id) : req.user.organization_id;

    if (!name || name.trim().length < 3 || name.trim().length > 100) {
      return res.status(400).json({ error: "Department name is required (3-100 characters)" });
    }
    if (!code || !isValidCode(code)) {
      return res.status(400).json({ error: "Department code must be 2-20 uppercase letters/numbers" });
    }

    const dupCode = await pool.query(
      "SELECT id FROM departments WHERE organization_id = $1 AND code = $2",
      [orgId, code]
    );
    if (dupCode.rows.length > 0) return res.status(409).json({ error: "Department code already exists" });

    const dupName = await pool.query(
      "SELECT id FROM departments WHERE organization_id = $1 AND LOWER(name) = LOWER($2)",
      [orgId, name.trim()]
    );
    if (dupName.rows.length > 0) return res.status(409).json({ error: "Department name already exists" });

    const result = await pool.query(
      `INSERT INTO departments (organization_id, name, code, manager_employee_id, description, default_policy_id, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [orgId, name.trim(), code, manager_employee_id || null, description || null, default_policy_id || null, status || "active"]
    );

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "department_created", status: "success", req, details: name });
    res.status(201).json({ message: "Department created", department: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/departments   (SRS-005) — search, sort, filter, pagination
// Super Admin must pass ?organization_id=X to view that org's departments;
// a regular admin always sees their own organization only.
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, status, sort, page = 1, limit = 20, organization_id } = req.query;

    const orgId = req.user.is_super_admin ? organization_id : req.user.organization_id;
    if (!orgId) {
      return res.status(400).json({ error: "organization_id is required" });
    }

    const conditions = ["d.organization_id = $1"];
    const params = [orgId];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(d.name ILIKE $${params.length} OR d.code ILIKE $${params.length} OR mgr.name ILIKE $${params.length})`);
    }
    if (status) {
      params.push(status);
      conditions.push(`d.status = $${params.length}`);
    }

    let orderBy = "d.created_at DESC";
    if (sort === "name") orderBy = "d.name ASC";
    else if (sort === "employee_count") orderBy = "employee_count DESC";
    else if (sort === "device_count") orderBy = "device_count DESC";

    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), offset);

    const result = await pool.query(
      `SELECT d.*, p.name AS policy_name, mgr.name AS manager_name,
              (SELECT COUNT(*) FROM employees e WHERE e.department_id = d.id) AS employee_count,
              (SELECT COUNT(*) FROM employees e WHERE e.department_id = d.id AND e.device_id IS NOT NULL) AS device_count,
              (SELECT COUNT(*) FROM employees e JOIN devices dv ON e.device_id = dv.id
                WHERE e.department_id = d.id AND dv.last_seen > NOW() - INTERVAL '90 seconds') AS online_count
       FROM departments d
       LEFT JOIN policies p ON d.default_policy_id = p.id
       LEFT JOIN employees mgr ON d.manager_employee_id = mgr.id
       WHERE ${conditions.join(" AND ")}
       ORDER BY ${orderBy}
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM departments d LEFT JOIN employees mgr ON d.manager_employee_id = mgr.id WHERE ${conditions.join(" AND ")}`,
      params.slice(0, conditions.length)
    );

    res.json({
      departments: result.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/departments/:id   (SRS-005)
router.put("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, default_policy_id, status } = req.body;

    // Confirm the department exists, and (for non-super-admins) belongs to their org
    const existing = await pool.query("SELECT * FROM departments WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Department not found" });
    const dept = existing.rows[0];
    if (!req.user.is_super_admin && dept.organization_id !== req.user.organization_id) {
      return res.status(404).json({ error: "Department not found" });
    }

    if (name) {
      const dupName = await pool.query(
        "SELECT id FROM departments WHERE organization_id = $1 AND LOWER(name) = LOWER($2) AND id != $3",
        [dept.organization_id, name.trim(), id]
      );
      if (dupName.rows.length > 0) return res.status(409).json({ error: "Department name already exists" });
    }

    const result = await pool.query(
      `UPDATE departments SET name = COALESCE($1, name), description = COALESCE($2, description),
        default_policy_id = COALESCE($3, default_policy_id), status = COALESCE($4, status)
       WHERE id = $5 RETURNING *`,
      [name, description, default_policy_id, status, id]
    );

    await logAudit({ userId: req.user.id, organizationId: dept.organization_id, action: "department_updated", status: "success", req });
    res.json({ message: "Department updated", department: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/departments/:id/manager   (SRS-005 FR-06)
router.patch("/:id/manager", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { manager_employee_id } = req.body;

    const existing = await pool.query("SELECT * FROM departments WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Department not found" });
    const dept = existing.rows[0];
    if (!req.user.is_super_admin && dept.organization_id !== req.user.organization_id) {
      return res.status(404).json({ error: "Department not found" });
    }

    if (manager_employee_id) {
      const emp = await pool.query(
        "SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.id = $1 AND d.organization_id = $2 AND e.status = 'active'",
        [manager_employee_id, dept.organization_id]
      );
      if (emp.rows.length === 0) return res.status(400).json({ error: "Selected manager is invalid" });
    }

    const result = await pool.query(
      "UPDATE departments SET manager_employee_id = $1 WHERE id = $2 RETURNING *",
      [manager_employee_id || null, id]
    );

    await logAudit({ userId: req.user.id, organizationId: dept.organization_id, action: "department_manager_assigned", status: "success", req });
    res.json({ message: "Manager assigned", department: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/departments/:id   (SRS-005 BR-05)
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const existing = await pool.query("SELECT * FROM departments WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Department not found" });
    const dept = existing.rows[0];
    if (!req.user.is_super_admin && dept.organization_id !== req.user.organization_id) {
      return res.status(404).json({ error: "Department not found" });
    }

    const empCount = await pool.query("SELECT COUNT(*) FROM employees WHERE department_id = $1", [id]);
    if (parseInt(empCount.rows[0].count) > 0) {
      return res.status(409).json({ error: "Cannot delete a department with employees assigned. Reassign or remove them first." });
    }

    const result = await pool.query("UPDATE departments SET status = 'disabled' WHERE id = $1 RETURNING *", [id]);

    await logAudit({ userId: req.user.id, organizationId: dept.organization_id, action: "department_deleted", status: "success", req });
    res.json({ message: "Department deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
