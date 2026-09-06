const express = require("express");
const pool = require("../config/db");
const bcrypt = require("bcryptjs");
const requireAuth = require("../middleware/auth");
const requireSuperAdmin = require("../middleware/superAdmin");
const logAudit = require("../utils/auditLog");

const router = express.Router();

function isValidCode(code) {
  return /^[A-Z0-9]{3,20}$/.test(code);
}
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ===================== SUPER ADMIN: manage ALL organizations =====================

// GET /api/organizations  (Super Admin only)
// Supports: ?search=, ?status=active|suspended|inactive, ?sort=name|created_at|device_count, ?page=, ?limit=
router.get("/", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { search, status, sort, page = 1, limit = 20 } = req.query;
    const conditions = [];
    const params = [];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(o.name ILIKE $${params.length} OR o.code ILIKE $${params.length} OR o.email ILIKE $${params.length} OR o.industry ILIKE $${params.length})`);
    }
    if (status) {
      params.push(status);
      conditions.push(`o.status = $${params.length}`);
    }
    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    let orderBy = "o.created_at DESC";
    if (sort === "name") orderBy = "o.name ASC";
    else if (sort === "device_count") orderBy = "device_count DESC";
    else if (sort === "status") orderBy = "o.status ASC";

    const filterParamCount = params.length;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), offset);

    const result = await pool.query(
      `SELECT o.*,
              (SELECT COUNT(*) FROM departments d WHERE d.organization_id = o.id) AS department_count,
              (SELECT COUNT(*) FROM employees e JOIN departments d ON e.department_id = d.id WHERE d.organization_id = o.id) AS employee_count,
              (SELECT COUNT(*) FROM devices dv WHERE dv.organization_id = o.id) AS device_count,
              (SELECT u.name FROM users u WHERE u.organization_id = o.id AND u.is_super_admin = FALSE ORDER BY u.id LIMIT 1) AS admin_name
       FROM organizations o
       ${whereClause}
       ORDER BY ${orderBy}
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countResult = await pool.query(`SELECT COUNT(*) FROM organizations o ${whereClause}`, params.slice(0, filterParamCount));

    res.json({
      organizations: result.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/organizations  (Super Admin only) — create a new organization
// Optionally also creates its first Organization Admin in the same call.
router.post("/", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { name, code, industry, email, contact_number, country, city, address, status, admin_name, admin_email, admin_password } = req.body;

    if (!name || name.trim().length < 3 || name.trim().length > 100) {
      return res.status(400).json({ error: "Organization name is required" });
    }
    if (!code || !isValidCode(code)) {
      return res.status(400).json({ error: "Organization code must be 3-20 uppercase letters/numbers" });
    }
    if (!industry) return res.status(400).json({ error: "Industry is required" });
    if (!email || !isValidEmail(email)) return res.status(400).json({ error: "Enter a valid email address" });
    if (!country) return res.status(400).json({ error: "Country is required" });

    const dupName = await pool.query("SELECT id FROM organizations WHERE LOWER(name) = LOWER($1)", [name.trim()]);
    if (dupName.rows.length > 0) return res.status(409).json({ error: "Organization name already exists" });

    const dupCode = await pool.query("SELECT id FROM organizations WHERE code = $1", [code]);
    if (dupCode.rows.length > 0) return res.status(409).json({ error: "Organization code already exists" });

    const orgResult = await pool.query(
      `INSERT INTO organizations (name, code, industry, email, contact_number, country, city, address, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [name.trim(), code, industry, email, contact_number || null, country, city || null, address || null, status || "active"]
    );
    const org = orgResult.rows[0];

    // BR-02: every organization must have at least one Organization Admin —
    // create one now if credentials were supplied for it.
    if (admin_name && admin_email && admin_password) {
      const existingAdmin = await pool.query("SELECT id FROM users WHERE email = $1", [admin_email]);
      if (existingAdmin.rows.length === 0) {
        const roleResult = await pool.query("SELECT id FROM roles WHERE name = 'OrganizationAdmin'");
        const hash = await bcrypt.hash(admin_password, 10);
        await pool.query(
          `INSERT INTO users (name, email, password_hash, organization_id, role, role_id, status)
           VALUES ($1, $2, $3, $4, 'super_admin', $5, 'active')`,
          [admin_name, admin_email, hash, org.id, roleResult.rows[0]?.id || null]
        );
      }
    }

    await logAudit({ userId: req.user.id, organizationId: org.id, action: "organization_created", status: "success", req, details: org.name });

    res.status(201).json({ message: "Organization created", organization: org });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/organizations/:id  (Super Admin only)
router.put("/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, industry, email, contact_number, country, city, address } = req.body;

    if (name) {
      const dupName = await pool.query("SELECT id FROM organizations WHERE LOWER(name) = LOWER($1) AND id != $2", [name.trim(), id]);
      if (dupName.rows.length > 0) return res.status(409).json({ error: "Organization name already exists" });
    }
    if (email && !isValidEmail(email)) return res.status(400).json({ error: "Enter a valid email address" });

    const result = await pool.query(
      `UPDATE organizations SET
        name = COALESCE($1, name), industry = COALESCE($2, industry), email = COALESCE($3, email),
        contact_number = COALESCE($4, contact_number), country = COALESCE($5, country),
        city = COALESCE($6, city), address = COALESCE($7, address)
       WHERE id = $8 RETURNING *`,
      [name, industry, email, contact_number, country, city, address, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Organization not found" });

    await logAudit({ userId: req.user.id, organizationId: id, action: "organization_updated", status: "success", req });
    res.json({ message: "Organization updated", organization: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/organizations/:id/status  (Super Admin only) — suspend/activate
router.patch("/:id/status", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!["active", "suspended", "inactive"].includes(status)) {
      return res.status(400).json({ error: "status must be active, suspended, or inactive" });
    }

    const result = await pool.query("UPDATE organizations SET status = $1 WHERE id = $2 RETURNING *", [status, id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Organization not found" });

    await logAudit({ userId: req.user.id, organizationId: id, action: `organization_${status}`, status: "success", req });
    res.json({ message: `Organization ${status}`, organization: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/organizations/:id  (Super Admin only)
// BR-04: cannot delete an organization that still has enrolled devices.
router.delete("/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const deviceCount = await pool.query("SELECT COUNT(*) FROM devices WHERE organization_id = $1", [id]);
    if (parseInt(deviceCount.rows[0].count) > 0) {
      return res.status(409).json({ error: "Cannot delete an organization with enrolled devices. Remove its devices first." });
    }

    // BR-05: soft delete — mark inactive rather than hard-deleting
    const result = await pool.query("UPDATE organizations SET status = 'inactive' WHERE id = $1 RETURNING *", [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Organization not found" });

    await logAudit({ userId: req.user.id, organizationId: id, action: "organization_deleted", status: "success", req });
    res.json({ message: "Organization deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/organizations/:id/stats  (Super Admin only) — FR-09
router.get("/:id/stats", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const departments = await pool.query("SELECT COUNT(*) FROM departments WHERE organization_id = $1", [id]);
    const employees = await pool.query("SELECT COUNT(*) FROM employees e JOIN departments d ON e.department_id = d.id WHERE d.organization_id = $1", [id]);
    const devices = await pool.query("SELECT COUNT(*) FROM devices WHERE organization_id = $1", [id]);
    const policies = await pool.query("SELECT COUNT(*) FROM policies WHERE organization_id = $1", [id]);

    res.json({
      departments: parseInt(departments.rows[0].count),
      employees: parseInt(employees.rows[0].count),
      devices: parseInt(devices.rows[0].count),
      policies: parseInt(policies.rows[0].count),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===================== ORGANIZATION ADMIN: their own organization =====================

// GET /api/organizations/me   (Any admin) — this admin's own organization + stats
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

// PATCH /api/organizations/me   (Any admin) — rename own organization
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
