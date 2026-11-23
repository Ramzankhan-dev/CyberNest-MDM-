const jwt = require("jsonwebtoken");
const pool = require("../config/db");

// Protects admin-only routes. Checks for a valid token in the
// Authorization header: "Bearer <token>"
// Also rejects tokens belonging to an organization that has been deleted
// (status 'inactive'), so deleting an organization cuts off its dashboard
// users immediately instead of waiting for their JWT to expire.
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  if (!decoded.is_super_admin && decoded.organization_id) {
    try {
      const org = await pool.query("SELECT status FROM organizations WHERE id = $1", [decoded.organization_id]);
      // No row = organization was permanently deleted.
      if (!org.rows[0] || org.rows[0].status === "inactive") {
        return res.status(403).json({ error: "This organization has been deleted. Dashboard access is no longer available." });
      }
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Server error" });
    }
  }

  // A Department Manager loses dashboard access as soon as their department is disabled.
  if (decoded.role === "DepartmentManager") {
    try {
      const dept = await pool.query("SELECT status FROM departments WHERE manager_id = $1", [decoded.id]);
      if (dept.rows[0] && dept.rows[0].status !== "active") {
        return res.status(403).json({ error: "This department is disabled. Contact your Organization Admin." });
      }
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "Server error" });
    }
  }

  req.user = decoded; // { id, email, role }
  next();
}

module.exports = requireAuth;
