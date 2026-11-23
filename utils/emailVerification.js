// Email OTP verification — proves an email inbox really exists (and is
// reachable) before it is saved for an Organization, Org Admin,
// Department Manager or Employee.
//
// Flow: dashboard calls /api/email-verification/send -> a 6-digit code is
// emailed (EmailJS "verify" template) -> dashboard calls /confirm with the
// code -> the create/update route checks isEmailVerified() and, once the
// record is saved, consumeVerification() so the same proof can't be reused.

const bcrypt = require("bcryptjs");
const pool = require("../config/db");
const { sendVerificationEmail } = require("../config/mailer");

const CODE_EXPIRY_MINUTES = 10;   // code must be entered within this time
const VERIFIED_VALID_MINUTES = 30; // after verifying, the form must be saved within this time
const MAX_ATTEMPTS = 5;           // wrong codes before a new one is needed
const RESEND_COOLDOWN_SECONDS = 60;

class VerificationError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const normalize = (email) => String(email || "").trim().toLowerCase();

async function sendCode(email, userId) {
  const e = normalize(email);

  const recent = await pool.query(
    `SELECT created_at FROM email_verifications
      WHERE email = $1 AND requested_by = $2 AND created_at > NOW() - make_interval(secs => $3)
      ORDER BY created_at DESC LIMIT 1`,
    [e, userId, RESEND_COOLDOWN_SECONDS]
  );
  if (recent.rows.length > 0) {
    throw new VerificationError(`Please wait ${RESEND_COOLDOWN_SECONDS} seconds before requesting a new code`, 429);
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const otpHash = await bcrypt.hash(otp, 10);

  // Older unused codes for this email (from this admin) stop working
  await pool.query(
    "UPDATE email_verifications SET used = TRUE WHERE email = $1 AND requested_by = $2 AND used = FALSE",
    [e, userId]
  );
  const row = await pool.query(
    `INSERT INTO email_verifications (email, otp_hash, expires_at, requested_by)
     VALUES ($1, $2, NOW() + make_interval(mins => $3), $4) RETURNING id`,
    [e, otpHash, CODE_EXPIRY_MINUTES, userId]
  );

  try {
    await sendVerificationEmail(e, otp);
  } catch (err) {
    await pool.query("DELETE FROM email_verifications WHERE id = $1", [row.rows[0].id]);
    console.error("Verification email failed:", err.message);
    throw new VerificationError("Could not send the verification email. Check the address and try again.", 502);
  }
  return { expiresInMinutes: CODE_EXPIRY_MINUTES };
}

async function confirmCode(email, otp, userId) {
  const e = normalize(email);
  if (!/^\d{6}$/.test(String(otp || ""))) throw new VerificationError("Enter the 6-digit code");

  const result = await pool.query(
    `SELECT * FROM email_verifications
      WHERE email = $1 AND requested_by = $2 AND used = FALSE
      ORDER BY created_at DESC LIMIT 1`,
    [e, userId]
  );
  const row = result.rows[0];
  if (!row) throw new VerificationError("No code was sent to this email — click Send Code first");
  if (row.verified) return { verified: true };
  if (new Date(row.expires_at) < new Date()) throw new VerificationError("This code has expired — send a new one");
  if (row.attempts >= MAX_ATTEMPTS) throw new VerificationError("Too many wrong attempts — send a new code", 429);

  const ok = await bcrypt.compare(String(otp), row.otp_hash);
  if (!ok) {
    await pool.query("UPDATE email_verifications SET attempts = attempts + 1 WHERE id = $1", [row.id]);
    const left = MAX_ATTEMPTS - row.attempts - 1;
    throw new VerificationError(left > 0 ? `Incorrect code — ${left} attempt(s) left` : "Too many wrong attempts — send a new code");
  }
  await pool.query("UPDATE email_verifications SET verified = TRUE, verified_at = NOW() WHERE id = $1", [row.id]);
  return { verified: true };
}

async function isEmailVerified(email, userId) {
  const result = await pool.query(
    `SELECT id FROM email_verifications
      WHERE email = $1 AND requested_by = $2 AND verified = TRUE AND used = FALSE
        AND verified_at > NOW() - make_interval(mins => $3)
      LIMIT 1`,
    [normalize(email), userId, VERIFIED_VALID_MINUTES]
  );
  return result.rows.length > 0;
}

async function consumeVerification(email, userId) {
  await pool.query(
    "UPDATE email_verifications SET used = TRUE WHERE email = $1 AND requested_by = $2 AND verified = TRUE AND used = FALSE",
    [normalize(email), userId]
  );
}

const NOT_VERIFIED_MESSAGE = "Please verify this email first (Send Code, then enter the code sent to it)";

module.exports = { sendCode, confirmCode, isEmailVerified, consumeVerification, VerificationError, NOT_VERIFIED_MESSAGE };
