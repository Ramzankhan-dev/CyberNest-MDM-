const express = require("express");
const requireAuth = require("../middleware/auth");
const { sendCode, confirmCode, VerificationError } = require("../utils/emailVerification");

const router = express.Router();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Only the people who add emails to the system: Super Admin (organizations)
// and Organization Admin (employees / managers).
function canVerify(req, res, next) {
  if (req.user?.is_super_admin || req.user?.role === "OrganizationAdmin") return next();
  return res.status(403).json({ error: "You don't have permission to perform this action" });
}

function handle(err, res) {
  if (err instanceof VerificationError) return res.status(err.status).json({ error: err.message });
  console.error(err);
  return res.status(500).json({ error: "Server error" });
}

// POST /api/email-verification/send   { email }
router.post("/send", requireAuth, canVerify, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim();
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "Enter a valid email address" });
    const result = await sendCode(email, req.user.id);
    res.json({ message: `Code sent to ${email}`, expires_in_minutes: result.expiresInMinutes });
  } catch (err) {
    handle(err, res);
  }
});

// POST /api/email-verification/confirm   { email, otp }
router.post("/confirm", requireAuth, canVerify, async (req, res) => {
  try {
    await confirmCode(req.body.email, req.body.otp, req.user.id);
    res.json({ message: "Email verified", verified: true });
  } catch (err) {
    handle(err, res);
  }
});

module.exports = router;
