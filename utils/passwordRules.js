// Password rule for employee / manager passwords: at least 8 characters, containing both letters and numbers.
// Returns a user-friendly message, or null when the password is acceptable.
// (Keep in sync with dashboard src/utils/passwordRules.js.)

function passwordRuleError(password) {
  if (typeof password !== "string" || password.length < 8) return "Password must be at least 8 characters";
  if (!/[A-Za-z]/.test(password)) return "Password must include at least one letter (A-Z)";
  if (!/\d/.test(password)) return "Password must include at least one number (0-9)";
  return null;
}

module.exports = { passwordRuleError };
