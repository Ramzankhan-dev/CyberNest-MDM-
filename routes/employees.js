const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

const ALLOWED_ROLES = ["OrganizationAdmin", "DepartmentManager", "Employee"];

async function departmentBelongsToOrg(departmentId, organizationId) {
  const result = await pool.query(
    "SELECT id, status FROM departments WHERE id = $1 AND organization_id = $2",
    [departmentId, organizationId]
  );
  return result.rows[0] || null;
}

// POST /api/employees   (SRS-006)
router.post("/", requireAuth, async (req, res) => {
  try {
    const { employee_code, first_name, last_name, email, phone_number, department_id, designation, role, status } = req.body;

    if (!employee_code || employee_code.length > 20) {
      return res.status(400).json({ error: "Employee ID is required (max 20 characters)" });
    }
    if (!first_name || !last_name) {
      return res.status(400).json({ error: "First name and last name are required" });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email address" });
    }
    if (!department_id) {
      return res.status(400).json({ error: "Department is required" });
    }
    const dept = await departmentBelongsToOrg(department_id, req.user.organization_id);
    if (!dept) return res.status(400).json({ error: "Department not found" });
    if (dept.status !== "active") return res.status(400).json({ error: "Department is not active" });

    if (role && !ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({ error: "Role must be OrganizationAdmin, DepartmentManager, or Employee" });
    }

    // Employee ID + email must be unique within the organization
    const dupCode = await pool.query(
      `SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id
       WHERE d.organization_id = $1 AND e.employee_code = $2`,
      [req.user.organization_id, employee_code]
    );
    if (dupCode.rows.length > 0) return res.status(409).json({ error: "Employee ID already exists" });

    const dupEmail = await pool.query(
      `SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id
       WHERE d.organization_id = $1 AND e.email = $2`,
      [req.user.organization_id, email]
    );
    if (dupEmail.rows.length > 0) return res.status(409).json({ error: "Email already exists" });

    const fullName = `${first_name} ${last_name}`.trim();
    const result = await pool.query(
      `INSERT INTO employees (department_id, name, employee_code, email, phone_number, designation, role, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [department_id, fullName, employee_code, email, phone_number || null, designation || null, role || "Employee", status || "active"]
    );

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "employee_created", status: "success", req, details: fullName });
    res.status(201).json({ message: "Employee added", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/employees   (SRS-006) — search, filter, sort, pagination
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, department_id, status, role, has_device, sort, page = 1, limit = 20 } = req.query;
    const conditions = ["d.organization_id = $1"];
    const params = [req.user.organization_id];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(e.name ILIKE $${params.length} OR e.employee_code ILIKE $${params.length} OR e.email ILIKE $${params.length} OR e.phone_number ILIKE $${params.length})`);
    }
    if (department_id) {
      params.push(department_id);
      conditions.push(`e.department_id = $${params.length}`);
    }
    if (status) {
      params.push(status);
      conditions.push(`e.status = $${params.length}`);
    }
    if (role) {
      params.push(role);
      conditions.push(`e.role = $${params.length}`);
    }
    if (has_device === "true") conditions.push("e.device_id IS NOT NULL");
    if (has_device === "false") conditions.push("e.device_id IS NULL");

    let orderBy = "e.created_at DESC";
    if (sort === "name") orderBy = "e.name ASC";
    else if (sort === "department") orderBy = "d.name ASC";

    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), offset);

    const result = await pool.query(
      `SELECT e.*, d.name AS department_name, dev.device_uid, dev.model, dev.status AS device_status
       FROM employees e
       JOIN departments d ON e.department_id = d.id
       LEFT JOIN devices dev ON e.device_id = dev.id
       WHERE ${conditions.join(" AND ")}
       ORDER BY ${orderBy}
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countResult = await pool.query(
      `SELECT COUNT(*) FROM employees e JOIN departments d ON e.department_id = d.id WHERE ${conditions.join(" AND ")}`,
      params.slice(0, conditions.length)
    );

    res.json({ employees: result.rows, total: parseInt(countResult.rows[0].count), page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/employees/:id   (SRS-006 FR-04)
router.put("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { first_name, last_name, email, phone_number, designation, status } = req.body;

    const existing = await pool.query(
      `SELECT e.* FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.id = $1 AND d.organization_id = $2`,
      [id, req.user.organization_id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Employee not found" });

    const name = first_name && last_name ? `${first_name} ${last_name}`.trim() : null;

    if (email) {
      const dupEmail = await pool.query(
        `SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id
         WHERE d.organization_id = $1 AND e.email = $2 AND e.id != $3`,
        [req.user.organization_id, email, id]
      );
      if (dupEmail.rows.length > 0) return res.status(409).json({ error: "Email already exists" });
    }

    const result = await pool.query(
      `UPDATE employees SET name = COALESCE($1, name), email = COALESCE($2, email),
        phone_number = COALESCE($3, phone_number), designation = COALESCE($4, designation), status = COALESCE($5, status)
       WHERE id = $6 RETURNING *`,
      [name, email, phone_number, designation, status, id]
    );

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "employee_updated", status: "success", req });
    res.json({ message: "Employee updated", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/department   (SRS-006 FR-07 — transfer)
router.patch("/:id/department", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { department_id } = req.body;

    const dept = await departmentBelongsToOrg(department_id, req.user.organization_id);
    if (!dept) return res.status(400).json({ error: "Department not found" });
    if (dept.status !== "active") return res.status(400).json({ error: "Department is not active" });

    const result = await pool.query(
      `UPDATE employees e SET department_id = $1
       FROM departments d WHERE e.id = $2 AND e.department_id = d.id AND d.organization_id = $3
       RETURNING e.*`,
      [department_id, id, req.user.organization_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Employee not found" });

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "employee_department_changed", status: "success", req });
    res.json({ message: "Department changed", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/role   (SRS-006 FR-08)
router.patch("/:id/role", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    if (!ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({ error: "Role must be OrganizationAdmin, DepartmentManager, or Employee" });
    }

    const result = await pool.query(
      `UPDATE employees e SET role = $1
       FROM departments d WHERE e.id = $2 AND e.department_id = d.id AND d.organization_id = $3
       RETURNING e.*`,
      [role, id, req.user.organization_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Employee not found" });

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "employee_role_changed", status: "success", req });
    res.json({ message: "Role updated", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/assign-device   (SRS-006 FR-06, BR-03/04/05)
router.patch("/:id/assign-device", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { device_uid } = req.body;
    if (!device_uid) {
      return res.status(400).json({ error: "device_uid is required" });
    }

    const empResult = await pool.query(
      `SELECT e.* FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.id = $1 AND d.organization_id = $2`,
      [id, req.user.organization_id]
    );
    const employee = empResult.rows[0];
    if (!employee) return res.status(404).json({ error: "Employee not found" });

    // BR-05: suspended employees cannot receive new device assignments
    if (employee.status === "suspended") {
      return res.status(409).json({ error: "Cannot assign a device to a suspended employee" });
    }

    const deviceResult = await pool.query(
      "SELECT id FROM devices WHERE device_uid = $1 AND organization_id = $2",
      [device_uid, req.user.organization_id]
    );
    const device = deviceResult.rows[0];
    if (!device) {
      return res.status(404).json({ error: "Device not found in your organization" });
    }

    // BR-04: one device can only be assigned to one employee at a time
    const alreadyAssigned = await pool.query("SELECT id FROM employees WHERE device_id = $1 AND id != $2", [device.id, id]);
    if (alreadyAssigned.rows.length > 0) {
      return res.status(409).json({ error: "Selected device is already assigned to another employee" });
    }

    const result = await pool.query(
      `UPDATE employees e SET device_id = $1
       FROM departments d
       WHERE e.id = $2 AND e.department_id = d.id AND d.organization_id = $3
       RETURNING e.*`,
      [device.id, id, req.user.organization_id]
    );

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "employee_device_assigned", status: "success", req });
    res.json({ message: "Device assigned", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/status   (SRS-006 FR-09) — suspend / reinstate
router.patch("/:id/status", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
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
    if (result.rows.length === 0) return res.status(404).json({ error: "Employee not found" });

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: `employee_${status}`, status: "success", req });
    res.json({ message: `Employee ${status}`, employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/employees/:id   (SRS-006)
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await pool.query(
      `SELECT e.* FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.id = $1 AND d.organization_id = $2`,
      [id, req.user.organization_id]
    );
    if (existing.rows.length === 0) return res.status(404).json({ error: "Employee not found" });

    // Clear any department that has this employee set as its manager first
    await pool.query("UPDATE departments SET manager_employee_id = NULL WHERE manager_employee_id = $1", [id]);
    await pool.query("DELETE FROM employees WHERE id = $1", [id]);

    await logAudit({ userId: req.user.id, organizationId: req.user.organization_id, action: "employee_deleted", status: "success", req });
    res.json({ message: "Employee deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
