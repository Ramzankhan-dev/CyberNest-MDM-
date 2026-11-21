// Multi-policy support: a device can have several policies assigned at the
// same time. This file turns that list into ONE effective policy, and builds
// the FCM commands for it, so a newly assigned policy never cancels an older one.
//
// Merge rules (most restrictive wins):
//   - every restriction flag (camera, bluetooth, wifi, usb, ...) = ON if ANY policy sets it
//   - password min length = highest; max failed attempts and auto-lock = lowest
//   - blocked apps = union of all policies
//   - policies WITHOUT working hours apply all the time ("always")
//   - policies WITH working hours apply only inside the window ("scheduled").
//     One schedule is used for all scheduled rules: the kiosk policy's window
//     has the highest priority, otherwise the most recently assigned one.

const BOOLEAN_FLAGS = [
  "camera_blocked", "bluetooth_blocked", "wifi_restricted", "usb_transfer_blocked",
  "screenshot_blocked", "usb_debugging_blocked", "mobile_hotspot_blocked",
  "airplane_mode_blocked", "location_services_blocked", "factory_reset_blocked",
  "password_required", "prevent_unknown_sources", "prevent_play_store",
  "vpn_required", "mobile_data_restricted", "developer_options_disabled",
  "kiosk_mode",
];

const hasSchedule = (p) => !!(p.working_hours_start && p.working_hours_end);

// Higher = wins when two policies compete for the same single setting
// (which kiosk app / which working-hours window).
function priority(p) {
  if (p.kiosk_mode && hasSchedule(p)) return 3;
  if (p.kiosk_mode) return 2;
  if (hasSchedule(p)) return 1;
  return 0;
}

function splitApps(value) {
  return String(value || "").split(",").map((s) => s.trim()).filter(Boolean);
}

// `policies` must be ordered oldest -> newest assignment.
function mergePolicies(policies) {
  if (!policies || policies.length === 0) return null;

  const byPriority = policies
    .map((p, i) => ({ p, i }))
    .sort((a, b) => priority(a.p) - priority(b.p) || a.i - b.i)
    .map((x) => x.p);

  const merged = { ...policies[policies.length - 1] }; // identity (id, name, ...) of the latest one
  merged.merged_policy_names = policies.map((p) => p.name);

  for (const flag of BOOLEAN_FLAGS) merged[flag] = policies.some((p) => !!p[flag]);

  const nums = (key) => policies.map((p) => Number(p[key])).filter((n) => Number.isFinite(n) && n > 0);
  merged.password_min_length = nums("password_min_length").length ? Math.max(...nums("password_min_length")) : null;
  merged.max_failed_attempts = nums("max_failed_attempts").length ? Math.min(...nums("max_failed_attempts")) : null;
  merged.auto_lock_timeout_minutes = nums("auto_lock_timeout_minutes").length ? Math.min(...nums("auto_lock_timeout_minutes")) : null;

  merged.blocked_apps = [...new Set(policies.flatMap((p) => splitApps(p.blocked_apps)))].join(",") || null;

  const always = policies.filter((p) => !hasSchedule(p));
  const scheduled = policies.filter(hasSchedule);
  const lastKiosk = (list) => [...list].reverse().find((p) => p.kiosk_mode);

  merged.camera_always = always.some((p) => p.camera_blocked);
  merged.camera_scheduled = scheduled.some((p) => p.camera_blocked);
  merged.bluetooth_always = always.some((p) => p.bluetooth_blocked);
  merged.bluetooth_scheduled = scheduled.some((p) => p.bluetooth_blocked);
  merged.kiosk_always = always.some((p) => p.kiosk_mode);
  merged.kiosk_scheduled = scheduled.some((p) => p.kiosk_mode);
  merged.kiosk_always_package = lastKiosk(always)?.kiosk_package || null;
  merged.kiosk_scheduled_package = lastKiosk(scheduled)?.kiosk_package || null;
  merged.kiosk_package = merged.kiosk_scheduled_package || merged.kiosk_always_package || null;

  const scheduleOwner = byPriority.filter(hasSchedule).pop();
  merged.working_hours_start = scheduleOwner ? scheduleOwner.working_hours_start : null;
  merged.working_hours_end = scheduleOwner ? scheduleOwner.working_hours_end : null;

  return merged;
}

const isActive = (p) => (p.status || "active") === "active";

// Every policy assigned to a device (active AND disabled), oldest first, one row per policy.
async function getAssignedPolicies(db, deviceId) {
  const result = await db.query(
    `SELECT p.*, dp.assigned_at AS assigned_at
     FROM device_policies dp JOIN policies p ON dp.policy_id = p.id
     WHERE dp.device_id = $1 ORDER BY dp.assigned_at ASC`,
    [deviceId]
  );
  const seen = new Map();
  for (const row of result.rows) seen.set(String(row.id), row); // a re-assigned policy keeps its newest position
  return [...seen.values()];
}

// Only the ACTIVE policies assigned to a device. A disabled policy stays assigned
// (so enabling it again re-applies it) but has no effect while disabled.
async function getDevicePolicies(db, deviceId) {
  return (await getAssignedPolicies(db, deviceId)).filter(isActive);
}

// Same, looked up by device_uid (used by the Android agent, which has no device id).
async function getEffectivePolicyByUid(db, deviceUid) {
  const device = await db.query("SELECT id FROM devices WHERE device_uid = $1", [deviceUid]);
  if (!device.rows[0]) return null;
  return mergePolicies(await getDevicePolicies(db, device.rows[0].id));
}

// What gets pushed right away over FCM: only rules that are active all the
// time. Scheduled camera/bluetooth/kiosk are switched by the device's own
// working-hours check, so pushing them here would ignore the schedule.
function pushView(merged) {
  if (!merged) return null;
  return {
    ...merged,
    camera_blocked: merged.camera_always,
    bluetooth_blocked: merged.bluetooth_always,
    kiosk_mode: merged.kiosk_always,
    kiosk_package: merged.kiosk_always_package,
    working_hours_start: null,
    working_hours_end: null,
  };
}

function buildCommandsForPolicy(policy) {
  const commands = [];
  if (!policy) return commands;

  // camera_blocked, bluetooth_blocked and kiosk_mode are the three
  // restrictions the dashboard labels "Working hours (kiosk/camera/
  // bluetooth auto-toggle)" — when a schedule is set, only the
  // on-device 30s check (HomeActivity.checkWorkingHoursAndEnforce,
  // which uses the device's own local time) should ever turn them on
  // or off. Pushing them immediately here too — regardless of the
  // schedule — used to cause a visible flicker: kiosk would engage
  // for a few seconds right on assignment, then the on-device check
  // would notice it's outside the window and undo it a moment later.
  const schedule = hasSchedule(policy);

  if (policy.camera_blocked && !schedule) commands.push({ type: "block_camera" });
  if (policy.bluetooth_blocked && !schedule) commands.push({ type: "block_bluetooth" });
  if (policy.wifi_restricted) commands.push({ type: "block_wifi" });
  if (policy.usb_transfer_blocked) commands.push({ type: "block_usb" });
  if (policy.screenshot_blocked) commands.push({ type: "block_screenshot" });
  if (policy.usb_debugging_blocked) commands.push({ type: "block_usb_debugging" });
  if (policy.mobile_hotspot_blocked) commands.push({ type: "block_hotspot" });
  if (policy.airplane_mode_blocked) commands.push({ type: "block_airplane_mode" });
  if (policy.location_services_blocked) commands.push({ type: "block_location" });
  if (policy.factory_reset_blocked) commands.push({ type: "block_factory_reset" });
  if (policy.prevent_unknown_sources) commands.push({ type: "block_unknown_sources" });
  if (policy.prevent_play_store) commands.push({ type: "block_play_store" });
  if (policy.auto_lock_timeout_minutes) commands.push({ type: "set_auto_lock", extra: { minutes: String(policy.auto_lock_timeout_minutes) } });
  if (policy.password_required && policy.password_min_length) {
    commands.push({ type: "set_password_policy", extra: { min_length: String(policy.password_min_length), max_failed: String(policy.max_failed_attempts || 5) } });
  }
  splitApps(policy.blocked_apps).forEach((pkg) => {
    commands.push({ type: "block_app", extra: { package_name: pkg } });
  });
  if (policy.kiosk_mode && !schedule) commands.push({ type: "enable_kiosk", extra: policy.kiosk_package ? { package_name: policy.kiosk_package } : {} });
  return commands;
}

// Mirrors buildCommandsForPolicy — sends the opposite (unblock_*) commands
// so unassigning a policy genuinely reverses it on the device, not just
// clears the database record.
function buildUnblockCommandsForPolicy(policy) {
  const commands = [];
  if (!policy) return commands;
  if (policy.camera_blocked) commands.push({ type: "unblock_camera" });
  if (policy.bluetooth_blocked) commands.push({ type: "unblock_bluetooth" });
  if (policy.wifi_restricted) commands.push({ type: "unblock_wifi" });
  if (policy.usb_transfer_blocked) commands.push({ type: "unblock_usb" });
  if (policy.screenshot_blocked) commands.push({ type: "unblock_screenshot" });
  if (policy.usb_debugging_blocked) commands.push({ type: "unblock_usb_debugging" });
  if (policy.mobile_hotspot_blocked) commands.push({ type: "unblock_hotspot" });
  if (policy.airplane_mode_blocked) commands.push({ type: "unblock_airplane_mode" });
  if (policy.location_services_blocked) commands.push({ type: "unblock_location" });
  if (policy.factory_reset_blocked) commands.push({ type: "unblock_factory_reset" });
  if (policy.prevent_unknown_sources) commands.push({ type: "unblock_unknown_sources" });
  if (policy.prevent_play_store) commands.push({ type: "unblock_play_store" });
  splitApps(policy.blocked_apps).forEach((pkg) => {
    commands.push({ type: "unblock_app", extra: { package_name: pkg } });
  });
  if (policy.kiosk_mode) commands.push({ type: "disable_kiosk" });
  return commands;
}

// When policies are removed from a device, only undo what NO remaining policy
// still needs. `before` and `after` are merged policies (after may be null).
function buildUnblockDiff(before, after) {
  if (!before) return [];
  const diff = {};
  for (const flag of BOOLEAN_FLAGS) diff[flag] = !!before[flag] && !(after && after[flag]);
  const stillBlocked = new Set(splitApps(after && after.blocked_apps));
  diff.blocked_apps = splitApps(before.blocked_apps).filter((pkg) => !stillBlocked.has(pkg)).join(",");
  return buildUnblockCommandsForPolicy(diff);
}

module.exports = {
  mergePolicies,
  getDevicePolicies,
  getAssignedPolicies,
  isActive,
  getEffectivePolicyByUid,
  pushView,
  buildCommandsForPolicy,
  buildUnblockCommandsForPolicy,
  buildUnblockDiff,
};
