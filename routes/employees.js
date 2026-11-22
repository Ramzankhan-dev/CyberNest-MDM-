const express = require("express");
const bcrypt = require("bcryptjs");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const requireRole = require("../middleware/roles");
const { getManagedDepartmentId, blockSuperAdmin } = require("../middleware/roles");
const requireEmployeeAuth = require("../middleware/employeeAuth");
const logAudit = require("../utils/auditLog");
const { passwordRuleError } = require("../utils/passwordRules");

const router = express.Router();

const ALLOWED_ROLES = ["OrganizationAdmin", "DepartmentManager", "Employee"];

// Errors meant for the user (shown as-is). Anything else is logged and returned as a generic server error,
// so raw database messages never reach the dashboard.
class UserFacingError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}
const EMAIL_IN_USE_MESSAGE = "This email is already used by another dashboard account. Use a different email for this employee.";

// Maps an error from the manager-account helper to { status, message }, or null if it is not a user-facing error.
function managerErrorResponse(err) {
  if (err instanceof UserFacingError) return { status: err.status, message: err.message };
  if (err && err.code === "23505") return { status: 409, message: EMAIL_IN_USE_MESSAGE }; // unique violation (e.g. users_email_key)
  return null;
}

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
    throw new UserFacingError("This department already has a Department Manager — remove them first", 409);
  }

  const roleResult = await pool.query("SELECT id FROM roles WHERE name = 'DepartmentManager'");
  const roleId = roleResult.rows[0]?.id;
  if (!roleId) throw new UserFacingError("DepartmentManager role is not configured", 500);

  const ruleError = password ? passwordRuleError(password) : null;
  if (ruleError) throw new UserFacingError(ruleError);
  const passwordHash = password ? await bcrypt.hash(password, 10) : null;

  let userId = alreadyLinkedUserId;
  if (userId) {
    // Re-activating the manager account already linked to this employee (new password only if one was given).
    await pool.query(
      "UPDATE users SET status = 'active', name = $1, role = 'department_manager', role_id = $2, password_hash = COALESCE($3, password_hash) WHERE id = $4",
      [fullName, roleId, passwordHash, userId]
    );
  } else {
    // users.email is unique across the whole system, so look for an existing account with this email first.
    const existingUser = await pool.query(
      `SELECT u.id, u.organization_id, COALESCE(r.name, u.role) AS role_name,
              (SELECT e.id FROM employees e WHERE e.linked_user_id = u.id LIMIT 1) AS linked_employee_id
       FROM users u LEFT JOIN roles r ON u.role_id = r.id
       WHERE LOWER(u.email) = LOWER($1)
       ORDER BY (u.email = $1) DESC LIMIT 1`,
      [email]
    );
    const found = existingUser.rows[0];
    if (found) {
      const sameOrg = Number(found.organization_id) === Number(organizationId);
      const isManagerAccount = ["DepartmentManager", "department_manager"].includes(found.role_name);
      const linkedToOther = found.linked_employee_id && String(found.linked_employee_id) !== String(employeeId);
      // Only a leftover manager account of this same organization (e.g. from a deleted/demoted employee) may be reused.
      if (!sameOrg || !isManagerAccount || linkedToOther) throw new UserFacingError(EMAIL_IN_USE_MESSAGE, 409);
      await pool.query(
        "UPDATE users SET status = 'active', name = $1, role = 'department_manager', role_id = $2, organization_id = $3, password_hash = COALESCE($4, password_hash) WHERE id = $5",
        [fullName, roleId, organizationId, passwordHash, found.id]
      );
      userId = found.id;
    } else {
      if (!password) throw new UserFacingError("A password (min 8 characters, letters and numbers) is required to create a Department Manager account");
      const insertResult = await pool.query(
        `INSERT INTO users (name, email, password_hash, organization_id, role, role_id, status)
         VALUES ($1, $2, $3, $4, 'department_manager', $5, 'active') RETURNING id`,
        [fullName, email, passwordHash, organizationId, roleId]
      );
      userId = insertResult.rows[0].id;
    }
  }

  await pool.query("UPDATE departments SET manager_id = $1 WHERE id = $2", [userId, departmentId]);
  await pool.query("UPDATE employees SET linked_user_id = $1 WHERE id = $2", [userId, employeeId]);
  // Keeps the pre-existing manager_employee_id label field (set via
  // the Departments module's own "Set Manager" UI) pointed at the
  // same person, so the two "who manages this department" fields
  // don't quietly diverge.
  await pool.query("UPDATE departments SET manager_employee_id = $1 WHERE id = $2", [employeeId, departmentId]);
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
  await pool.query("UPDATE departments SET manager_employee_id = NULL WHERE manager_employee_id = $1", [employeeId]);
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
router.patch("/:id/set-password", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    const ruleError = passwordRuleError(password);
    if (ruleError) return res.status(400).json({ error: ruleError });

    const orgId = await getEmployeeOrgId(id);
    if (!orgId) return res.status(404).json({ error: "Employee not found" });
    if (orgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    // A Department Manager also has a dashboard login (users table) — keep both passwords in sync.
    const empRow = await pool.query("SELECT role, linked_user_id FROM employees WHERE id = $1", [id]);
    const linkedUserId = empRow.rows[0]?.role === "DepartmentManager" ? empRow.rows[0].linked_user_id : null;
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query("UPDATE employees SET password_hash = $1 WHERE id = $2", [passwordHash, id]);
    if (linkedUserId) await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, linkedUserId]);

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
        const friendly = managerErrorResponse(managerErr);
        if (!friendly) throw managerErr;
        return res.status(friendly.status).json({ error: friendly.message });
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
      // any department_id filter the request might ask for. Also
      // excludes their own linked employee row — a manager viewing
      // "their team" shouldn't see themselves listed as one of their
      // own reports.
      const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
      params.push(managedDeptId || 0); // 0 never matches a real id — an unassigned manager sees an empty list
      conditions.push(`e.department_id = $${params.length}`);
      params.push(req.user.id);
      conditions.push(`(e.linked_user_id IS NULL OR e.linked_user_id != $${params.length})`);
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
// PUT /api/employees/:id   (Organization Admin) — edit name, phone, designation, email, status and (optionally) password.
// Keeps everything that mirrors the employee in step: the linked dashboard login (users), and the assigned device's name.
router.put("/:id", requireAuth, requireRole("OrganizationAdmin"), blockSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { first_name, last_name, status, password } = req.body;
    const has = (field) => req.body[field] !== undefined;

    const empOrgId = await getEmployeeOrgId(id);
    if (!empOrgId || empOrgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }
    const current = (await pool.query("SELECT * FROM employees WHERE id = $1", [id])).rows[0];

    // Validate every field that was sent before changing anything
    let name = null;
    if (has("name") || (first_name && last_name)) {
      name = (has("name") ? String(req.body.name) : `${first_name} ${last_name}`).trim();
      if (!name) return res.status(400).json({ error: "Name cannot be empty" });
    }

    let email = null;
    if (has("email")) {
      email = String(req.body.email).trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address" });
      if (email.toLowerCase() !== String(current.email || "").toLowerCase()) {
        const dupEmployee = await pool.query(
          `SELECT e.id FROM employees e JOIN departments d ON e.department_id = d.id
           WHERE d.organization_id = $1 AND LOWER(e.email) = LOWER($2) AND e.id != $3`,
          [empOrgId, email, id]
        );
        if (dupEmployee.rows.length > 0) return res.status(409).json({ error: "Another employee already uses this email" });
      }
      // users.email is unique system-wide (dashboard logins), so check it too — except this employee's own linked login
      const dupUser = await pool.query(
        "SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND id IS DISTINCT FROM $2",
        [email, current.linked_user_id]
      );
      if (dupUser.rows.length > 0) return res.status(409).json({ error: "This email is already used by another account" });
    }

    let phone;
    if (has("phone_number")) {
      phone = String(req.body.phone_number || "").trim();
      if (phone && !/^[0-9+()\-\s]{7,20}$/.test(phone)) return res.status(400).json({ error: "Enter a valid phone number" });
    }
    if (status !== undefined && !["active", "suspended"].includes(status)) {
      return res.status(400).json({ error: "status must be 'active' or 'suspended'" });
    }
    let passwordHash = null;
    if (password) {
      const ruleError = passwordRuleError(password);
      if (ruleError) return res.status(400).json({ error: ruleError });
      passwordHash = await bcrypt.hash(password, 10);
    }

    const client = await pool.connect();
    let updated;
    try {
      await client.query("BEGIN");
      updated = (await client.query(
        `UPDATE employees SET
           name = COALESCE($1, name),
           email = COALESCE($2, email),
           phone_number = CASE WHEN $3::boolean THEN $4 ELSE phone_number END,
           designation = CASE WHEN $5::boolean THEN $6 ELSE designation END,
           status = COALESCE($7, status),
           password_hash = COALESCE($8, password_hash)
         WHERE id = $9 RETURNING *`,
        [name, email, has("phone_number"), phone || null, has("designation"), has("designation") ? (String(req.body.designation || "").trim() || null) : null, status || null, passwordHash, id]
      )).rows[0];

      // Linked dashboard login (Department Manager): same name, email and password
      if (current.linked_user_id) {
        await client.query(
          "UPDATE users SET name = COALESCE($1, name), email = COALESCE($2, email), password_hash = COALESCE($3, password_hash) WHERE id = $4",
          [name, email, passwordHash, current.linked_user_id]
        );
      }
      // Assigned device shows the employee's current name
      if (name && current.device_id) {
        await client.query("UPDATE devices SET employee_name = $1 WHERE id = $2", [name, current.device_id]);
      }
      await client.query("COMMIT");
    } catch (txErr) {
      await client.query("ROLLBACK");
      if (txErr.code === "23505") return res.status(409).json({ error: "This email is already used by another account" });
      throw txErr;
    } finally {
      client.release();
    }

    await logAudit({ userId: req.user.id, organizationId: empOrgId, action: "employee_updated", status: "success", req, details: `employee #${id}${passwordHash ? " (password changed)" : ""}` });
    res.json({ message: "Employee updated", employee: { ...updated, password_hash: undefined } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/department   (SRS-006 FR-07 — transfer)
router.patch("/:id/department", requireAuth, blockSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { department_id } = req.body;

    const empOrgId = await getEmployeeOrgId(id);
    if (!empOrgId) return res.status(404).json({ error: "Employee not found" });
    if (empOrgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    const dept = await getDepartmentAnyOrg(department_id);
    if (!dept || dept.organization_id !== empOrgId) return res.status(400).json({ error: "Department not found" });
    if (dept.status !== "active") return res.status(400).json({ error: "Department is not active" });

    // A Department Manager stays in the department they manage — change their role first to move them.
    const empRow = (await pool.query("SELECT role, department_id FROM employees WHERE id = $1", [id])).rows[0];
    if (empRow && empRow.role === "DepartmentManager" && String(empRow.department_id) !== String(department_id)) {
      return res.status(409).json({ error: "This employee is a Department Manager — change their role first before moving them to another department" });
    }

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
        const friendly = managerErrorResponse(managerErr);
        if (!friendly) throw managerErr;
        return res.status(friendly.status).json({ error: friendly.message });
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
    await pool.query("UPDATE devices SET department_id = $1, employee_name = $2 WHERE id = $3", [employee.department_id, employee.name, device.id]);

    await logAudit({ userId: req.user.id, organizationId: empOrgId, action: "employee_device_assigned", status: "success", req });
    res.json({ message: "Device assigned", employee: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/unassign-device — frees the employee's current device so it can be given to someone else
// (the device keeps its department, so it shows up as a "department unassigned device").
router.patch("/:id/unassign-device", requireAuth, requireRole("OrganizationAdmin", "DepartmentManager"), async (req, res) => {
  try {
    const { id } = req.params;
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
        return res.status(403).json({ error: "You can only manage devices of employees in your own department" });
      }
    }
    if (!employee.device_id) return res.status(409).json({ error: "This employee has no device assigned" });

    await pool.query("UPDATE devices SET employee_name = NULL WHERE id = $1", [employee.device_id]);
    await pool.query("UPDATE employees SET device_id = NULL WHERE id = $1", [id]);

    await logAudit({ userId: req.user.id, organizationId: empOrgId, action: "employee_device_unassigned", status: "success", req, details: `employee #${id}` });
    res.json({ message: "Device unassigned" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/employees/:id/status   (SRS-006 FR-09) — suspend / reinstate
router.patch("/:id/status", requireAuth, requireRole("OrganizationAdmin", "DepartmentManager"), async (req, res) => {
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

    if (req.user.role === "DepartmentManager") {
      const empResult = await pool.query("SELECT department_id FROM employees WHERE id = $1", [id]);
      const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
      if (!managedDeptId || empResult.rows[0]?.department_id !== managedDeptId) {
        return res.status(403).json({ error: "You can only manage employees in your own department" });
      }
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
router.delete("/:id", requireAuth, requireRole("OrganizationAdmin"), async (req, res) => {
  try {
    const { id } = req.params;
    const empOrgId = await getEmployeeOrgId(id);
    if (!empOrgId) return res.status(404).json({ error: "Employee not found" });
    if (!req.user.is_super_admin && empOrgId !== req.user.organization_id) {
      return res.status(404).json({ error: "Employee not found" });
    }

    const holding = await pool.query("SELECT device_id FROM employees WHERE id = $1", [id]);
    if (holding.rows[0]?.device_id) {
      return res.status(409).json({ error: "Please unassign the employee's device before deleting this employee." });
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
