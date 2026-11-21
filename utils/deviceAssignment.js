// Links a device to the employee who just logged in on it (called from POST /api/auth/employee-login).
//   - the device becomes that employee's device (employees.device_id) and shows their name
//   - a device enrolled from an "Unassigned" QR profile (no department) moves into the employee's department
//   - a device already held by another employee, or from another organization, is refused with a clear message

class AssignmentError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

// `employee` is the row returned by employee-login (employees.* plus the department's organization_id).
async function assignDeviceToLoggedInEmployee(pool, employee, deviceUid) {
  const deviceResult = await pool.query(
    "SELECT id, organization_id, department_id FROM devices WHERE device_uid = $1",
    [deviceUid]
  );
  const device = deviceResult.rows[0];
  if (!device) return null; // unknown uid — nothing to link, the login itself is still valid

  if (Number(device.organization_id) !== Number(employee.organization_id)) {
    throw new AssignmentError("This device belongs to a different organization", 403);
  }

  const holder = await pool.query("SELECT id, name FROM employees WHERE device_id = $1 AND id <> $2", [device.id, employee.id]);
  if (holder.rows.length > 0) {
    throw new AssignmentError(`This device is already assigned to ${holder.rows[0].name}. Ask your administrator to unassign it first.`, 409);
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // If the employee was holding a different device, it is released (one device per employee).
    if (employee.device_id && Number(employee.device_id) !== Number(device.id)) {
      await client.query("UPDATE devices SET employee_name = NULL WHERE id = $1 AND employee_name = $2", [employee.device_id, employee.name]);
    }
    await client.query("UPDATE employees SET device_id = $1 WHERE id = $2", [device.id, employee.id]);
    await client.query(
      "UPDATE devices SET employee_name = $1, department_id = COALESCE(department_id, $2) WHERE id = $3",
      [employee.name, employee.department_id, device.id]
    );
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }

  return { device_id: device.id, moved_to_department: device.department_id == null };
}

module.exports = { assignDeviceToLoggedInEmployee, AssignmentError };
