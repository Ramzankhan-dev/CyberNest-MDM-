// Role-authorization middleware, layered on top of requireAuth (which
// only checks "is this a valid token"). This checks "is this specific
// role allowed to do this specific thing" — used to enforce the
// 3-tier hierarchy:
//   SuperAdmin       — organizations only (create/edit/suspend), and
//                       read-only visibility everywhere else. NOT
//                       included by default in requireRole() calls
//                       below, since SuperAdmin is deliberately
//                       excluded from org-level write actions
//                       (departments/employees/policies/devices) —
//                       that's the whole point of the split.
//   OrganizationAdmin — full operational control within their org.
//   DepartmentManager — scoped operational control within their own
//                       department only (the route handler itself is
//                       responsible for the department-level scoping;
//                       this middleware only checks the role name).
//
// Usage: router.post("/", requireAuth, requireRole("OrganizationAdmin"), handler)
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ error: "You don't have permission to perform this action" });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: "You don't have permission to perform this action" });
    }
    next();
  };
}

// Looks up which department (if any) this user manages —
// departments.manager_id is unique, so a user manages at most one.
// Used to scope a Department Manager's actions/visibility to their
// own department wherever the route handler needs it.
async function getManagedDepartmentId(pool, userId) {
  const result = await pool.query("SELECT id FROM departments WHERE manager_id = $1", [userId]);
  return result.rows[0]?.id || null;
}

// Explicit write-block for Super Admin. SuperAdmin has read-only
// visibility into every organization's Departments, Employees,
// Policies, and Devices — they can view everything but must never be
// able to create/edit/suspend/delete/command anything at the
// organization level (that's OrganizationAdmin's and, scoped to their
// own department, DepartmentManager's job). Apply this to every
// POST/PUT/PATCH/DELETE route in those four modules that isn't
// already restricted to a specific non-SuperAdmin role via
// requireRole(). Must run after requireAuth.
function blockSuperAdmin(req, res, next) {
  if (req.user && req.user.is_super_admin) {
    return res.status(403).json({ error: "Super Admin has read-only access to this module" });
  }
  next();
}

module.exports = requireRole;
module.exports.getManagedDepartmentId = getManagedDepartmentId;
module.exports.blockSuperAdmin = blockSuperAdmin;
