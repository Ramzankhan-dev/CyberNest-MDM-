const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const requireRole = require("../middleware/roles");
const { getManagedDepartmentId } = require("../middleware/roles");

const router = express.Router();

// Custom report builder for Organization Admin (whole organization) and Department Manager
// (own department only, never including the manager's own device). Column keys, SQL expressions
// and filter fields come from the whitelist below; user input only PICKS from it or is a bound parameter.
router.use(requireAuth, requireRole("OrganizationAdmin", "DepartmentManager"));

const MAX_ROWS = 5000;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const validDate = (v) => (typeof v === "string" && DATE_RE.test(v) ? v : null);
function clampLimit(value, fallback = 1000) {
  const n = parseInt(value, 10);
  if (!Number.isInteger(n) || n < 1) return fallback;
  return Math.min(n, MAX_ROWS);
}

// Bound parameters: Organization Admin -> [orgId]; Department Manager -> [deptId, orgId].
// Every entity gives one scope per role, written against those parameter numbers.
const MGR_DEVICE_SCOPE = `dv.organization_id = $2 AND COALESCE(dv.department_id, e.department_id) = $1
  AND NOT EXISTS (SELECT 1 FROM employees mgr_e WHERE mgr_e.device_id = dv.id AND mgr_e.role = 'DepartmentManager')`;
const ONLINE = "(dv.last_seen IS NOT NULL AND dv.last_seen > NOW() - INTERVAL '90 seconds')";
const CONNECTIVITY = `CASE WHEN dv.status = 'pending' THEN 'pending' WHEN ${ONLINE} THEN 'online' ELSE 'offline' END`;
const DEVICE_DEPT_JOIN = "LEFT JOIN departments dep ON dep.id = COALESCE(dv.department_id, e.department_id)";

const ENTITIES = {
  devices: {
    label: "Devices",
    roles: ["OrganizationAdmin", "DepartmentManager"],
    from: `devices dv LEFT JOIN employees e ON e.device_id = dv.id ${DEVICE_DEPT_JOIN}`,
    scope: { OrganizationAdmin: "dv.organization_id = $1", DepartmentManager: MGR_DEVICE_SCOPE },
    dateExpr: "dv.enrolled_at",
    dateLabel: "Enrolled date",
    orderBy: "dv.device_uid",
    columns: {
      employee_name: ["Employee", "COALESCE(e.name, dv.employee_name)"],
      department: ["Department", "dep.name"],
      device_uid: ["Device UID", "dv.device_uid"],
      model: ["Model", "dv.model"],
      manufacturer: ["Manufacturer", "dv.manufacturer"],
      android_version: ["Android", "dv.android_version"],
      imei: ["IMEI", "dv.imei"],
      enrollment_status: ["Enrollment status", "dv.status"],
      connectivity: ["Online/Offline", CONNECTIVITY],
      is_rooted: ["Rooted", "dv.is_rooted"],
      is_locked: ["Locked", "dv.is_locked"],
      battery_level: ["Battery %", "dv.battery_level"],
      storage_used_gb: ["Used GB", "dv.storage_used_gb"],
      storage_total_gb: ["Total GB", "dv.storage_total_gb"],
      last_seen: ["Last seen", "dv.last_seen"],
      enrolled_at: ["Enrolled", "dv.enrolled_at"],
    },
    defaultColumns: ["employee_name", "department", "device_uid", "model", "connectivity", "battery_level", "last_seen"],
    filters: {
      connectivity: { label: "Online/Offline", expr: CONNECTIVITY, options: ["online", "offline", "pending"] },
      is_rooted: { label: "Rooted", expr: "COALESCE(dv.is_rooted, FALSE)", options: ["true", "false"] },
    },
  },

  employees: {
    label: "Employees",
    roles: ["OrganizationAdmin", "DepartmentManager"],
    from: "employees e JOIN departments dep ON dep.id = e.department_id LEFT JOIN devices dv ON dv.id = e.device_id",
    scope: {
      OrganizationAdmin: "dep.organization_id = $1",
      DepartmentManager: "e.department_id = $1 AND dep.organization_id = $2 AND e.role <> 'DepartmentManager'",
    },
    dateExpr: "e.created_at",
    dateLabel: "Added date",
    orderBy: "e.name",
    columns: {
      name: ["Name", "e.name"],
      employee_code: ["Code", "e.employee_code"],
      department: ["Department", "dep.name"],
      role: ["Role", "e.role"],
      email: ["Email", "e.email"],
      phone_number: ["Phone", "e.phone_number"],
      designation: ["Designation", "e.designation"],
      status: ["Status", "e.status"],
      device: ["Device", "COALESCE(dv.model, dv.device_uid, 'Unassigned')"],
      created_at: ["Added", "e.created_at"],
    },
    defaultColumns: ["name", "employee_code", "department", "email", "status", "device"],
    filters: {
      status: { label: "Status contains", expr: "e.status" },
      has_device: { label: "Has device", expr: "(e.device_id IS NOT NULL)", options: ["true", "false"] },
    },
  },

  commands: {
    label: "Commands / Activity",
    roles: ["OrganizationAdmin", "DepartmentManager"],
    from: `commands c JOIN devices dv ON c.device_id = dv.id
           LEFT JOIN employees e ON e.device_id = dv.id
           LEFT JOIN users u ON u.id = c.issued_by`,
    scope: { OrganizationAdmin: "dv.organization_id = $1", DepartmentManager: MGR_DEVICE_SCOPE },
    dateExpr: "c.issued_at",
    dateLabel: "Issued date",
    orderBy: "c.issued_at DESC",
    columns: {
      issued_at: ["Time", "c.issued_at"],
      issued_by: ["Issued by", "u.name"],
      command_type: ["Command", "c.command_type"],
      device: ["Device", "COALESCE(e.name, dv.employee_name, dv.device_uid)"],
      status: ["Status", "c.status"],
      error_message: ["Error", "c.error_message"],
    },
    defaultColumns: ["issued_at", "issued_by", "command_type", "device", "status"],
    filters: {
      status: { label: "Status", expr: "c.status", options: ["pending", "sent", "executed", "failed", "cancelled"] },
      command_type: { label: "Command contains", expr: "c.command_type" },
    },
  },

  departments: {
    label: "Departments",
    roles: ["OrganizationAdmin"],
    from: "departments dep LEFT JOIN policies p ON p.id = dep.default_policy_id",
    scope: { OrganizationAdmin: "dep.organization_id = $1" },
    dateExpr: "dep.created_at",
    dateLabel: "Created date",
    orderBy: "dep.name",
    columns: {
      name: ["Department", "dep.name"],
      code: ["Code", "dep.code"],
      status: ["Status", "dep.status"],
      manager: ["Manager", "(SELECT m.name FROM employees m WHERE m.linked_user_id = dep.manager_id LIMIT 1)"],
      default_policy: ["Default policy", "p.name"],
      employees: ["Employees", "(SELECT COUNT(*) FROM employees x WHERE x.department_id = dep.id)::int"],
      devices: ["Devices", "(SELECT COUNT(DISTINCT dv2.id) FROM devices dv2 LEFT JOIN employees e2 ON e2.device_id = dv2.id WHERE COALESCE(dv2.department_id, e2.department_id) = dep.id)::int"],
      created_at: ["Created", "dep.created_at"],
    },
    defaultColumns: ["name", "code", "manager", "default_policy", "employees", "devices", "status"],
    filters: {
      status: { label: "Status", expr: "dep.status", options: ["active", "disabled"] },
    },
  },

  policies: {
    label: "Policies",
    roles: ["OrganizationAdmin"],
    from: "policies p",
    scope: { OrganizationAdmin: "p.organization_id = $1" },
    dateExpr: "p.created_at",
    dateLabel: "Created date",
    orderBy: "p.name",
    columns: {
      name: ["Policy", "p.name"],
      status: ["Status", "COALESCE(p.status, 'active')"],
      camera_blocked: ["Camera blocked", "p.camera_blocked"],
      bluetooth_blocked: ["Bluetooth blocked", "p.bluetooth_blocked"],
      wifi_restricted: ["Wi-Fi restricted", "p.wifi_restricted"],
      usb_transfer_blocked: ["USB blocked", "p.usb_transfer_blocked"],
      kiosk_mode: ["Kiosk", "p.kiosk_mode"],
      working_hours_start: ["Hours from", "p.working_hours_start"],
      working_hours_end: ["Hours to", "p.working_hours_end"],
      assigned_devices: ["Assigned devices", "(SELECT COUNT(*) FROM device_policies dp WHERE dp.policy_id = p.id)::int"],
      created_at: ["Created", "p.created_at"],
    },
    defaultColumns: ["name", "status", "camera_blocked", "bluetooth_blocked", "kiosk_mode", "assigned_devices"],
    filters: {
      status: { label: "Status", expr: "COALESCE(p.status, 'active')", options: ["active", "disabled"] },
    },
  },

  applications: {
    label: "Applications",
    roles: ["OrganizationAdmin"],
    from: "applications a",
    scope: { OrganizationAdmin: "a.organization_id = $1" },
    dateExpr: "a.created_at",
    dateLabel: "Created date",
    orderBy: "a.name",
    columns: {
      name: ["Application", "a.name"],
      package_name: ["Package", "a.package_name"],
      version: ["Version", "a.version"],
      category: ["Category", "a.category"],
      install_type: ["Install type", "a.install_type"],
      status: ["Status", "a.status"],
      assigned_devices: ["Assigned devices", "(SELECT COUNT(*) FROM application_assignments aa WHERE aa.application_id = a.id)::int"],
      created_at: ["Created", "a.created_at"],
    },
    defaultColumns: ["name", "package_name", "category", "install_type", "status", "assigned_devices"],
    filters: {
      status: { label: "Status", expr: "a.status", options: ["active", "blocked"] },
      category: { label: "Category", expr: "a.category", options: ["Enterprise", "Public"] },
      install_type: { label: "Install type", expr: "a.install_type", options: ["Required", "Optional", "Locked"] },
    },
  },

  audit_logs: {
    label: "Audit Logs",
    roles: ["OrganizationAdmin"],
    from: `audit_logs al
           LEFT JOIN users u ON u.id = al.user_id
           LEFT JOIN roles r ON r.id = u.role_id`,
    scope: { OrganizationAdmin: "al.organization_id = $1" },
    dateExpr: "al.created_at",
    dateLabel: "Event date",
    orderBy: "al.created_at DESC",
    columns: {
      created_at: ["Time", "al.created_at"],
      user_name: ["User", "u.name"],
      user_email: ["User email", "u.email"],
      role: ["Role", "COALESCE(r.name, u.role)"],
      action: ["Action", "al.action"],
      status: ["Status", "al.status"],
      details: ["Details", "al.details"],
      ip_address: ["IP address", "al.ip_address"],
    },
    defaultColumns: ["created_at", "user_name", "role", "action", "status"],
    filters: {
      action: { label: "Action contains", expr: "al.action" },
      status: { label: "Status", expr: "al.status", options: ["success", "failure", "failed"] },
    },
  },
};

const entitiesFor = (role) => Object.entries(ENTITIES).filter(([, def]) => def.roles.includes(role));

// GET /api/manager-reports/custom/meta
router.get("/custom/meta", (req, res) => {
  const entities = entitiesFor(req.user.role).map(([key, def]) => ({
    key,
    label: def.label,
    dateLabel: def.dateLabel,
    columns: Object.entries(def.columns).map(([ckey, [label]]) => ({ key: ckey, label })),
    defaultColumns: def.defaultColumns,
    filters: Object.entries(def.filters).map(([fkey, f]) => ({ key: fkey, label: f.label, options: f.options || null })),
  }));
  res.json({ entities, max_rows: MAX_ROWS });
});

// POST /api/manager-reports/custom   Body: { entity, columns[], filters{}, date_from, date_to, limit }
router.post("/custom", async (req, res) => {
  try {
    const role = req.user.role;
    const { entity, columns, filters } = req.body || {};
    const def = Object.prototype.hasOwnProperty.call(ENTITIES, entity) && ENTITIES[entity].roles.includes(role) ? ENTITIES[entity] : null;
    if (!def) return res.status(400).json({ error: "Unknown data source" });

    let params;
    if (role === "DepartmentManager") {
      const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
      if (!managedDeptId) return res.status(403).json({ error: "You are not managing a department" });
      params = [managedDeptId, req.user.organization_id];
    } else {
      params = [req.user.organization_id];
    }

    const requested = Array.isArray(columns) && columns.length > 0 ? columns : def.defaultColumns;
    const keys = [...new Set(requested)].filter((k) => Object.prototype.hasOwnProperty.call(def.columns, k));
    if (keys.length === 0) return res.status(400).json({ error: "Select at least one valid column" });

    const conditions = [def.scope[role]];

    const dateFrom = validDate(req.body.date_from);
    const dateTo = validDate(req.body.date_to);
    if (dateFrom) { params.push(dateFrom); conditions.push(`${def.dateExpr} >= $${params.length}::date`); }
    if (dateTo) { params.push(dateTo); conditions.push(`${def.dateExpr} < $${params.length}::date + 1`); }

    if (filters && typeof filters === "object") {
      for (const [fkey, value] of Object.entries(filters)) {
        const f = Object.prototype.hasOwnProperty.call(def.filters, fkey) ? def.filters[fkey] : null;
        if (!f || value === "" || value === null || value === undefined) continue;
        const str = String(value).slice(0, 100);
        if (f.options) {
          if (!f.options.includes(str)) return res.status(400).json({ error: `Invalid value for ${f.label}` });
          params.push(str);
          conditions.push(`(${f.expr})::text = $${params.length}`);
        } else {
          params.push(`%${str}%`);
          conditions.push(`(${f.expr}) ILIKE $${params.length}`);
        }
      }
    }

    const limit = clampLimit(req.body.limit, 1000);
    const select = keys.map((k) => `${def.columns[k][1]} AS "${k}"`).join(", ");
    const result = await pool.query(
      `SELECT ${select} FROM ${def.from} WHERE ${conditions.join(" AND ")} ORDER BY ${def.orderBy} LIMIT ${limit + 1}`,
      params
    );
    res.json({
      columns: keys.map((k) => ({ key: k, label: def.columns[k][0] })),
      rows: result.rows.slice(0, limit),
      truncated: result.rows.length > limit,
      limit,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
