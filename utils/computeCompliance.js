// Works out a device's compliance status from what we actually know:
// its latest policy assignment, whether it's synced since, whether any
// recent commands for it failed, and whether it's online right now.
// Shared by routes/compliance.js (SRS-011, admin-facing) and
// routes/agent.js (SRS-A05, agent-facing) so the two never disagree.
function computeComplianceStatus(device, latestFailed) {
  if (!device.policy_id) return "Unknown";
  if (latestFailed) return "Policy Failed";
  if (!device.last_seen || new Date(device.last_seen) < new Date(device.assigned_at)) return "Pending Sync";
  const isOnline = new Date(device.last_seen).getTime() > Date.now() - 90000;
  return isOnline ? "Compliant" : "Non-Compliant";
}

module.exports = computeComplianceStatus;
