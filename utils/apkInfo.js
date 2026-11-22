// Reads the real package name / version out of an .apk file's binary
// AndroidManifest.xml, so uploads can be verified instead of trusting
// whatever the admin typed.
const ApkReader = require("adbkit-apkreader");

async function readApkInfo(filePath) {
  const reader = await ApkReader.open(filePath);
  const manifest = await reader.readManifest();
  const pkg = manifest && manifest.package ? String(manifest.package).trim() : "";
  const versionName = manifest && manifest.versionName != null ? String(manifest.versionName).trim() : "";
  const versionCode = manifest && manifest.versionCode != null ? String(manifest.versionCode) : "";
  return { packageName: pkg, versionName: versionName || versionCode || null };
}

module.exports = { readApkInfo };
