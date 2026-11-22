// IMEI helpers. The Android agent sends text like "Not available" or
// "Permission not granted" when it can't read the IMEI, so only a real
// 15-digit IMEI (passes the Luhn check, not all zeros) counts as an IMEI.

function luhnValid(digits) {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let n = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

// Returns the IMEI as a 15-digit string, or null when it isn't a usable IMEI.
function cleanImei(value) {
  if (value === null || value === undefined) return null;
  const s = String(value).trim();
  if (!/^\d{15}$/.test(s)) return null;
  if (/^0+$/.test(s)) return null;
  return luhnValid(s) ? s : null;
}

module.exports = { cleanImei };
