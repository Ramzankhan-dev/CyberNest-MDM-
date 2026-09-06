const jwt = require("jsonwebtoken");

// Protects employee-facing routes (SRS-A04). Employee tokens carry
// { type: "employee", ... } so they're rejected here even if somehow
// presented where an admin token was expected, and vice versa — the
// two token spaces don't overlap.
function requireEmployeeAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.type !== "employee") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    req.employee = decoded; // { id, employee_code, department_id, organization_id, type }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

module.exports = requireEmployeeAuth;
