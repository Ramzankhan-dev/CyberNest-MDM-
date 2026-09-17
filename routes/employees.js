const express = require("express");
const bcrypt = require("bcryptjs");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const requireRole = require("../middleware/roles");
const { getManagedDepartmentId } = require("../middleware/roles");
const requireEmployeeAuth = require("../middleware/employeeAuth");
const logAudit = require("../utils/auditLog");

const router = express.Router();

const ALLOWED_ROLES = ["OrganizationAdmin", "DepartmentManager", "Employee"];

// Creates (or re-suspends-then-reuses, if one already exists from a
// prior promotion) the dashboard-login "users" account for an
// employee being made a Department Manager, and points
// departments.manager_id / employees.linked_user_id at it. Enforces
// the 1:1 department<->manager constraint at the application level
// too (clearer error message than letting the DB UNIQUE constraint
// reject it).
async function createOrAttachManagerAccount(pool, { employeeId, departmentId, fullName, email, password, organizationId }) {
  const existingManager = await pool.query("SELECT manager_id FROM departments WHERE id = $1", [departmentId]);
  const currentManagerId = existingManager.rows[0]?.manager_id;

  const employeeRow = await pool.query("SELECT linked_user_id FROM employees WHERE id = $1", [employeeId]);
  const alreadyLinkedUserId = employeeRow.rows[0]?.linked_user_id;

  if (currentManagerId && currentManagerId !== alreadyLinkedUserId) {
    throw new Error("This department already has a Department Manager — remove them first");
  }

  const roleResult = await pool.query("SELECT id FROM roles WHERE name = 'DepartmentManager'");
  const roleId = roleResult.rows[0]?.id;
  if (!roleId) throw new Error("DepartmentManager role is not configured");

  let userId = alreadyLinkedUserId;
  if (userId) {
    // Re-activating a previously-demoted manager account.
    await pool.query("UPDATE users SET status = 'active', name = $1, role_id = $2 WHERE id = $3", [fullName, roleId, userId]);
  } else {
    if (!password || password.length < 8) throw new Error("A password (min 8 characters) is required to create a Department Manager account");
    const passwordHash = await bcrypt.hash(password, 10);
    const insertResult = await pool.query(
      `INSERT INTO users (name, email, password_hash, organization_id, role, role_id, status)
       VALUES ($1, $2, $3, $4, 'department_manager', $5, 'active') RETURNING id`,
      [fullName, email, passwordHash, organizationId, roleId]
    );
    userId = insertResult.rows[0].id;
  }

  await pool.query("UPDATE departments SET manager_id = $1 WHERE id = $2", [userId, departmentId]);
  await pool.query("UPDATE employees SET linked_user_id = $1 WHERE id = $2", [userId, employeeId]);
  return userId;
}

// Called when an employee is demoted away from DepartmentManager —
// detaches them from the department they managed and suspends their
// dashboard account (rather than deleting it, to keep audit_log /
// other references intact).
async function detachManagerAccount(pool, employeeId) {
  const employeeRow = await pool.query("SELECT linked_user_id FROM employees WHERE id = $1", [employeeId]);
  const linkedUserId = employeeRow.rows[0]?.linked_user_id;
  if (!linkedUserId) return;

  await pool.query("UPDATE departments SET manager_id = NULL WHERE manager_id = $1", [linkedUserId]);
  await pool.query("UPDATE users SET status = 'suspended' WHERE id = $1", [linkedUserId]);
}

// GET /api/employees/profile   (SRS-A04 FR-07/FR-08 — called by the
// Android agent right after employee-login, with the employee's own
// token). Placed before "/:id" routes so Express doesn't treat
// "profile" as an :id param.
router.get("/profile", requireEmployeeAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT e.*, d.name AS department_name, d.organization_id, o.name AS organization_name
       FROM employees e
       JOIN departments d ON e.department_id = d.id
       JOIN organizations o ON d.organization_id = o.id
       WHERE e.id = $1`,
      [req.employee.id]
    );
    const employee = result.rows[0];
    if (!employee) return res.status(404).json({ error: "Employee not found" });

    // Enterprise Enhancement (SRS-A04) — "Welcome Summary" wants
    // policies-loaded / apps-assigned counts for the employee's device.
    let policiesLoaded = 0;
    let applicationsAssigned = 0;
    if (employee.device_id) {
      const policyCount = await pool.query("SELECT COUNT(*) FROM device_policies WHERE device_id = $1", [employee.device_id]);
      const appCount = await pool.query("SELECT COUNT(*) FROM device_apps WHERE device_id = $1", [employee.device_id]);
      policiesLoaded = parseInt(policyCount.rows[0].count, 10);
      applicationsAssigned = parseInt(appCount.rows[0].count, 10);
    }

    res.json({
      id: employee.id,
      name: employee.name,
      employee_code: employee.employee_code,
      email: employee.email,
      designation: employee.designation,
      role: employee.role,
      department: employee.department_name,
      organization: employee.organization_name,
      policies_loaded: policiesLoaded,
      applications_assigned: applicationsAssigned,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

async function getDepartmentAnyOrg(departmentId) {
  const result = await pool.query("SELECT id, status, organization_id FROM departments WHERE id = $1", [departmentId]);
  return result.rows[0] || null;
}

async function getEmployeeOrgId(employeeId) {
  const result = await pool.query(
    `SELECT d.organization_id FROM employees e JOIN departments d ON e.department_id = d.id WHERE e.id = $1`,
    [employeeId]
  );
  return result.rows[0]?.organization_id || null;
}

// PATCH /api/employees/:id/set-password   (Admin only — employees don't
// self-register or reset their own password from this project's UI)
router.patch("/:id/set-password", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    if (!password || password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const orgId = await getEmployeeOrgId(id);
    if (!orgId) return res.status(404).json({ error: "Employee not found" });
    if (!req.user.is_super_admin && orgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query("UPDATE employees SET password_hash = $1 WHERE id = $2", [passwordHash, id]);

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "employee_password_set", status: "success", req, details: `employee #${id}` });
    res.json({ message: "Password set successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/employees   (SRS-006)
router.post("/", requireAuth, requireRole("OrganizationAdmin"), async (req, res) => {
  try {
    const { employee_code, first_name, last_name, email, phone_number, department_id, designation, role, status, password } = req.body;

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
    const dept = await getDepartmentAnyOrg(department_id);
    if (!dept) return res.status(400).json({ error: "Department not found" });
    // A regular admin can only add employees to their OWN organization's
    // departments; a Super Admin may add to any organization's department.
    if (!req.user.is_super_admin && dept.organization_id !== req.user.organization_id) {
      return res.status(400).json({ error: "Department not found" });
    }
    if (dept.status !== "active") return res.status(400).json({ error: "Department is not active" });

    const orgId = dept.organization_id;

    if (role && !ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({ error: "Role must be OrganizationAdmin, DepartmentManager, or Employee" });
    }

    // Employee ID + email must be unique within the organization
    const dupCode = await pool.query(
      `SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id
       WHERE d.organization_id = $1 AND e.employee_code = $2`,
      [orgId, employee_code]
    );
    if (dupCode.rows.length > 0) return res.status(409).json({ error: "Employee ID already exists" });

    const dupEmail = await pool.query(
      `SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id
       WHERE d.organization_id = $1 AND e.email = $2`,
      [orgId, email]
    );
    if (dupEmail.rows.length > 0) return res.status(409).json({ error: "Email already exists" });

    const fullName = `${first_name} ${last_name}`.trim();
    const result = await pool.query(
      `INSERT INTO employees (department_id, name, employee_code, email, phone_number, designation, role, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [department_id, fullName, employee_code, email, phone_number || null, designation || null, role || "Employee", status || "active"]
    );

    if (role === "DepartmentManager") {
      try {
        await createOrAttachManagerAccount(pool, {
          employeeId: result.rows[0].id,
          departmentId: department_id,
          fullName,
          email,
          password,
          organizationId: orgId,
        });
      } catch (managerErr) {
        // The employee row is already created — roll that back too,
        // rather than leaving an Employee record with a DepartmentManager
        // label but no working dashboard account behind it.
        await pool.query("DELETE FROM employees WHERE id = $1", [result.rows[0].id]);
        return res.status(400).json({ error: managerErr.message });
      }
    }

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "employee_created", status: "success", req, details: fullName });
    res.status(201).json({ message: "Employee added", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/employees   (SRS-006) — search, filter, sort, pagination
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, department_id, status, role, has_device, sort, page = 1, limit = 20, organization_id } = req.query;

    const orgId = req.user.is_super_admin ? organization_id : req.user.organization_id;
    if (!orgId) {
      return res.status(400).json({ error: "organization_id is required" });
    }

    const conditions = ["d.organization_id = $1"];
    const params = [orgId];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(e.name ILIKE $${params.length} OR e.employee_code ILIKE $${params.length} OR e.email ILIKE $${params.length} OR e.phone_number ILIKE $${params.length})`);
    }
    if (req.user.role === "DepartmentManager") {
      // Sees only employees in the department they manage — overrides
      // any department_id filter the request might ask for.
      const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
      params.push(managedDeptId || 0); // 0 never matches a real id — an unassigned manager sees an empty list
      conditions.push(`e.department_id = $${params.length}`);
    } else if (department_id) {
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

    const filterParamCount = params.length; // exact count of params actually used by `conditions` above
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
      params.slice(0, filterParamCount)
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

    const empOrgId = await getEmployeeOrgId(id);
    if (!empOrgId) return res.status(404).json({ error: "Employee not found" });
    if (!req.user.is_super_admin && empOrgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    const name = first_name && last_name ? `${first_name} ${last_name}`.trim() : null;

    if (email) {
      const dupEmail = await pool.query(
        `SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id
         WHERE d.organization_id = $1 AND e.email = $2 AND e.id != $3`,
        [empOrgId, email, id]
      );
      if (dupEmail.rows.length > 0) return res.status(409).json({ error: "Email already exists" });
    }

    const result = await pool.query(
      `UPDATE employees SET name = COALESCE($1, name), email = COALESCE($2, email),
        phone_number = COALESCE($3, phone_number), designation = COALESCE($4, designation), status = COALESCE($5, status)
       WHERE id = $6 RETURNING *`,
      [name, email, phone_number, designation, status, id]
    );

    await logAudit({ userId: req.user.id, organizationId: empOrgId, action: "employee_updated", status: "success", req });
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

    const empOrgId = await getEmployeeOrgId(id);
    if (!empOrgId) return res.status(404).json({ error: "Employee not found" });
    if (!req.user.is_super_admin && empOrgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    const dept = await getDepartmentAnyOrg(department_id);
    if (!dept || dept.organization_id !== empOrgId) return res.status(400).json({ error: "Department not found" });
    if (dept.status !== "active") return res.status(400).json({ error: "Department is not active" });

    const result = await pool.query("UPDATE employees SET department_id = $1 WHERE id = $2 RETURNING *", [department_id, id]);

    await logAudit({ userId: req.user.id, organizationId: empOrgId, action: "employee_department_changed", status: "success", req });
    res.json({ message: "Department changed", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/role   (SRS-006 FR-08)
router.patch("/:id/role", requireAuth, requireRole("OrganizationAdmin"), async (req, res) => {
  try {
    const { id } = req.params;
    const { role, password } = req.body;
    if (!ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({ error: "Role must be OrganizationAdmin, DepartmentManager, or Employee" });
    }

    const empOrgId = await getEmployeeOrgId(id);
    if (!empOrgId) return res.status(404).json({ error: "Employee not found" });
    if (!req.user.is_super_admin && empOrgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    const currentResult = await pool.query("SELECT * FROM employees WHERE id = $1", [id]);
    const current = currentResult.rows[0];

    if (current.role === "DepartmentManager" && role !== "DepartmentManager") {
      await detachManagerAccount(pool, id);
    }
    if (role === "DepartmentManager" && current.role !== "DepartmentManager") {
      try {
        await createOrAttachManagerAccount(pool, {
          employeeId: id,
          departmentId: current.department_id,
          fullName: current.name,
          email: current.email,
          password,
          organizationId: empOrgId,
        });
      } catch (managerErr) {
        return res.status(400).json({ error: managerErr.message });
      }
    }

    const result = await pool.query("UPDATE employees SET role = $1 WHERE id = $2 RETURNING *", [role, id]);

    await logAudit({ userId: req.user.id, organizationId: empOrgId, action: "employee_role_changed", status: "success", req });
    res.json({ message: "Role updated", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/assign-device   (SRS-006 FR-06, BR-03/04/05)
router.patch("/:id/assign-device", requireAuth, requireRole("OrganizationAdmin", "DepartmentManager"), async (req, res) => {
  try {
    const { id } = req.params;
    const { device_uid } = req.body;
    if (!device_uid) {
      return res.status(400).json({ error: "device_uid is required" });
    }

    const empOrgId = await getEmployeeOrgId(id);
    if (!empOrgId) return res.status(404).json({ error: "Employee not found" });
    if (!req.user.is_super_admin && empOrgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    const empResult = await pool.query("SELECT * FROM employees WHERE id = $1", [id]);
    const employee = empResult.rows[0];

    if (req.user.role === "DepartmentManager") {
      const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
      if (!managedDeptId || employee.department_id !== managedDeptId) {
        return res.status(403).json({ error: "You can only assign devices to employees in your own department" });
      }
    }

    // BR-05: suspended employees cannot receive new device assignments
    if (employee.status === "suspended") {
      return res.status(409).json({ error: "Cannot assign a device to a suspended employee" });
    }

    const deviceResult = await pool.query(
      "SELECT id FROM devices WHERE device_uid = $1 AND organization_id = $2",
      [device_uid, empOrgId]
    );
    const device = deviceResult.rows[0];
    if (!device) {
      return res.status(404).json({ error: "Device not found in this organization" });
    }

    // BR-04: one device can only be assigned to one employee at a time
    const alreadyAssigned = await pool.query("SELECT id FROM employees WHERE device_id = $1 AND id != $2", [device.id, id]);
    if (alreadyAssigned.rows.length > 0) {
      return res.status(409).json({ error: "Selected device is already assigned to another employee" });
    }

    const result = await pool.query("UPDATE employees SET device_id = $1 WHERE id = $2 RETURNING *", [device.id, id]);

    await logAudit({ userId: req.user.id, organizationId: empOrgId, action: "employee_device_assigned", status: "success", req });
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

    const empOrgId = await getEmployeeOrgId(id);
    if (!empOrgId) return res.status(404).json({ error: "Employee not found" });
    if (!req.user.is_super_admin && empOrgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    const result = await pool.query("UPDATE employees SET status = $1 WHERE id = $2 RETURNING *", [status, id]);

    await logAudit({ userId: req.user.id, organizationId: empOrgId, action: `employee_${status}`, status: "success", req });
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
    const empOrgId = await getEmployeeOrgId(id);
    if (!empOrgId) return res.status(404).json({ error: "Employee not found" });
    if (!req.user.is_super_admin && empOrgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    // Clear any department that has this employee set as its manager first
    await pool.query("UPDATE departments SET manager_employee_id = NULL WHERE manager_employee_id = $1", [id]);
    await pool.query("DELETE FROM employees WHERE id = $1", [id]);

    await logAudit({ userId: req.user.id, organizationId: empOrgId, action: "employee_deleted", status: "success", req });
    res.json({ message: "Employee deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
