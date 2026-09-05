// Guards routes that only the platform Super Admin can use (SRS-004).
// Must run AFTER requireAuth, since it reads req.user set by it.
function requireSuperAdmin(req, res, next) {
  if (!req.user || !req.user.is_super_admin) {
    return res.status(403).json({ error: "Access denied — Super Admin only" });
  }
  next();
}

module.exports = requireSuperAdmin;
