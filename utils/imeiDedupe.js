// Stops the same phone (same IMEI) from showing up twice.
//
// The IMEI reaches the backend with the agent's first heartbeat (not at
// enrollment time), so this runs when a device reports an IMEI that is not
// stored on it yet. Outcomes:
//   set      - no other device has this IMEI: store it.
//   merged   - same organization, the other row is stale (e.g. the phone was
//              wiped and enrolled again): the old row takes over the new
//              enrollment (new device_uid, FCM token, ...) and the new
//              duplicate row is deleted, so history/employee/policies stay.
//   conflict - another organization, or the other row is online right now, or
//              two different employees are involved: the IMEI is NOT stored
//              on this device and the admin is told through the audit log.

const ACTIVE_WINDOW_MS = 2 * 60 * 1000; // heartbeats arrive every 30s

const isActiveNow = (d) =>
  d.status === "online" && d.last_seen && Date.now() - new Date(d.last_seen).getTime() < ACTIVE_WINDOW_MS;

async function mergeIntoExisting(pool, keep, dupe, imei) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const dupeEmp = (await client.query("SELECT id FROM employees WHERE device_id = $1", [dupe.id])).rows;
    const keepEmp = (await client.query("SELECT id FROM employees WHERE device_id = $1", [keep.id])).rows;
    if (dupeEmp.length && keepEmp.length) {
      await client.query("ROLLBACK");
      return { action: "conflict", message: "The existing device and this new enrollment are assigned to different employees. Unassign one of them first." };
    }

    if (dupeEmp.length) await client.query("UPDATE employees SET device_id = $1 WHERE device_id = $2", [keep.id, dupe.id]);
    await client.query(
      `DELETE FROM device_policies WHERE device_id = $1 AND policy_id IN (SELECT policy_id FROM device_policies WHERE device_id = $2)`,
      [dupe.id, keep.id]
    );
    await client.query("UPDATE device_policies SET device_id = $1 WHERE device_id = $2", [keep.id, dupe.id]);
    await client.query("UPDATE commands SET device_id = $1 WHERE device_id = $2", [keep.id, dupe.id]);
    await client.query("DELETE FROM device_apps WHERE device_id = $1", [dupe.id]);
    await client.query("DELETE FROM devices WHERE id = $1", [dupe.id]);

    const employeeName = dupeEmp.length ? (dupe.employee_name || keep.employee_name) : (keep.employee_name || dupe.employee_name);
    const updated = await client.query(
      `UPDATE devices SET
         device_uid = $1,
         fcm_token = COALESCE($2, fcm_token),
         model = COALESCE($3, model),
         android_version = COALESCE($4, android_version),
         enrollment_profile_id = COALESCE($5, enrollment_profile_id),
         department_id = COALESCE(department_id, $6),
         employee_name = $7,
         imei = $8,
         status = 'online',
         last_seen = NOW()
       WHERE id = $9 RETURNING *`,
      [dupe.device_uid, dupe.fcm_token, dupe.model, dupe.android_version, dupe.enrollment_profile_id, dupe.department_id, employeeName || null, imei, keep.id]
    );
    await client.query("COMMIT");
    return { action: "merged", device: updated.rows[0], previousUid: keep.device_uid };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// `device` = the row that just reported `imei` (a valid, cleaned IMEI).
async function resolveImeiForDevice(pool, device, imei) {
  const others = (await pool.query(
    "SELECT * FROM devices WHERE imei = $1 AND id <> $2 ORDER BY last_seen DESC NULLS LAST, id DESC",
    [imei, device.id]
  )).rows;
  if (others.length === 0) return { action: "set" };

  const sameOrg = others.filter((o) => String(o.organization_id) === String(device.organization_id));
  if (sameOrg.length < others.length) {
    return { action: "conflict", message: "This IMEI is already registered in another organization." };
  }
  if (sameOrg.some(isActiveNow)) {
    return { action: "conflict", message: "A device with this IMEI is already enrolled and active in this organization." };
  }
  return mergeIntoExisting(pool, sameOrg[0], device, imei);
}

module.exports = { resolveImeiForDevice };
