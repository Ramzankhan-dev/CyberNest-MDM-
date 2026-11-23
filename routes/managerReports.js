const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const requireRole = require("../middleware/roles");
const { getManagedDepartmentId } = require("../middleware/roles");

const router = express.Router();

// Department Manager custom report builder. Everything is limited to the manager's own
// department (and never includes the manager's own device). Column keys, SQL expressions and
// filter fields come from the whitelist below; user input only PICKS from it or is a bound parameter.
router.use(requireAuth, requireRole("DepartmentManager"));

const MAX_ROWS = 5000;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const validDate = (v) => (typeof v === "string" && DATE_RE.test(v) ? v : null);
function clampLimit(value, fallback = 1000) {
  const n = parseInt(value, 10);
  if (!Number.isInteger(n) || n < 1) return fallback;
  return Math.min(n, MAX_ROWS);
}

// $1 = managed department id, $2 = organization id (always the first two bound parameters).
const DEVICE_SCOPE = `dv.organization_id = $2 AND COALESCE(dv.department_id, e.department_id) = $1
  AND NOT EXISTS (SELECT 1 FROM employees mgr_e WHERE mgr_e.device_id = dv.id AND mgr_e.role = 'DepartmentManager')`;
const ONLINE = "(dv.last_seen IS NOT NULL AND dv.last_seen > NOW() - INTERVAL '90 seconds')";
const CONNECTIVITY = `CASE WHEN dv.status = 'pending' THEN 'pending' WHEN ${ONLINE} THEN 'online' ELSE 'offline' END`;

const ENTITIES = {
  devices: {
    label: "Devices",
    from: "devices dv LEFT JOIN employees e ON e.device_id = dv.id",
    scope: DEVICE_SCOPE,
    dateExpr: "dv.enrolled_at",
    dateLabel: "Enrolled date",
    orderBy: "dv.device_uid",
    columns: {
      employee_name: ["Employee", "COALESCE(e.name, dv.employee_name)"],
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
    defaultColumns: ["employee_name", "device_uid", "model", "connectivity", "battery_level", "last_seen"],
    filters: {
      connectivity: { label: "Online/Offline", expr: CONNECTIVITY, options: ["online", "offline", "pending"] },
      is_rooted: { label: "Rooted", expr: "COALESCE(dv.is_rooted, FALSE)", options: ["true", "false"] },
    },
  },

  employees: {
    label: "Employees",
    from: "employees e LEFT JOIN devices dv ON dv.id = e.device_id",
    scope: "e.department_id = $1 AND EXISTS (SELECT 1 FROM departments dd WHERE dd.id = e.department_id AND dd.organization_id = $2) AND e.role <> 'DepartmentManager'",
    dateExpr: "e.created_at",
    dateLabel: "Added date",
    orderBy: "e.name",
    columns: {
      name: ["Name", "e.name"],
      employee_code: ["Code", "e.employee_code"],
      email: ["Email", "e.email"],
      phone_number: ["Phone", "e.phone_number"],
      designation: ["Designation", "e.designation"],
      status: ["Status", "e.status"],
      device: ["Device", "COALESCE(dv.model, dv.device_uid, 'Unassigned')"],
      created_at: ["Added", "e.created_at"],
    },
    defaultColumns: ["name", "employee_code", "email", "status", "device"],
    filters: {
      status: { label: "Status contains", expr: "e.status" },
      has_device: { label: "Has device", expr: "(e.device_id IS NOT NULL)", options: ["true", "false"] },
    },
  },

  commands: {
    label: "Commands / Activity",
    from: `commands c JOIN devices dv ON c.device_id = dv.id
           LEFT JOIN employees e ON e.device_id = dv.id
           LEFT JOIN users u ON u.id = c.issued_by`,
    scope: DEVICE_SCOPE,
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
};

// GET /api/manager-reports/custom/meta
router.get("/custom/meta", (req, res) => {
  const entities = Object.entries(ENTITIES).map(([key, def]) => ({
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
    const managedDeptId = await getManagedDepartmentId(pool, req.user.id);
    if (!managedDeptId) return res.status(403).json({ error: "You are not managing a department" });

    const { entity, columns, filters } = req.body || {};
    const def = Object.prototype.hasOwnProperty.call(ENTITIES, entity) ? ENTITIES[entity] : null;
    if (!def) return res.status(400).json({ error: "Unknown data source" });

    const requested = Array.isArray(columns) && columns.length > 0 ? columns : def.defaultColumns;
    const keys = [...new Set(requested)].filter((k) => Object.prototype.hasOwnProperty.call(def.columns, k));
    if (keys.length === 0) return res.status(400).json({ error: "Select at least one valid column" });

    const params = [managedDeptId, req.user.organization_id];
    const conditions = [def.scope];

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
