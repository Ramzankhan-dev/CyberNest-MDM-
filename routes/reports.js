const express = require("express");
const pool = require("../config/db");
const requireAuth = require("../middleware/auth");
const requireSuperAdmin = require("../middleware/superAdmin");
const { criticalActionsSql, categorySql } = require("../utils/criticalActions");

const router = express.Router();

// Platform-wide reports — Super Admin only. Everything here is read-only and
// computed in SQL (no per-device queries), so it stays fast as the fleet grows.
router.use(requireAuth, requireSuperAdmin);

const MAX_ROWS = 5000;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

// One row per device with its latest policy assignment and a compliance
// status computed with the same rules as utils/computeCompliance.js:
//   no policy -> Unknown, failed command since assignment -> Policy Failed,
//   not synced since assignment -> Pending Sync, online -> Compliant,
//   otherwise Non-Compliant. Online = heartbeat within 90 seconds.
// Only explicitly named columns are ever returned (never fcm_token etc.).
const DEVICE_CTE = `
  dev AS (
    SELECT x.*,
      CASE
        WHEN x.policy_id IS NULL THEN 'Unknown'
        WHEN EXISTS (
          SELECT 1 FROM commands c
          WHERE c.device_id = x.id AND c.status = 'failed'
            AND c.issued_at > COALESCE(x.assigned_at, TIMESTAMP 'epoch')
            AND NOT EXISTS (SELECT 1 FROM commands c2 WHERE c2.device_id = c.device_id AND c2.command_type = c.command_type AND c2.status = 'executed' AND c2.issued_at > c.issued_at)
        ) THEN 'Policy Failed'
        WHEN x.last_seen IS NULL OR x.last_seen < x.assigned_at THEN 'Pending Sync'
        WHEN x.last_seen > NOW() - INTERVAL '90 seconds' THEN 'Compliant'
        ELSE 'Non-Compliant'
      END AS compliance_status,
      (x.last_seen IS NOT NULL AND x.last_seen > NOW() - INTERVAL '90 seconds') AS is_online
    FROM (
      SELECT DISTINCT ON (dv.id) dv.*, dp.policy_id, dp.assigned_at
      FROM devices dv
      LEFT JOIN device_policies dp ON dp.device_id = dv.id
      ORDER BY dv.id, dp.assigned_at DESC
    ) x
  )`;

function validDate(value) {
  return typeof value === "string" && DATE_RE.test(value) ? value : null;
}

function clampLimit(value, fallback = 1000) {
  const n = parseInt(value, 10);
  if (!Number.isInteger(n) || n < 1) return fallback;
  return Math.min(n, MAX_ROWS);
}

function fail(res, err) {
  console.error(err);
  res.status(500).json({ error: "Server error" });
}

// ===================== Organizations Overview / Compliance =====================

const ORG_OVERVIEW_SQL = `
  WITH ${DEVICE_CTE}
  SELECT o.id, o.name, o.code, o.status, o.country, o.created_at,
         COUNT(d.id)::int AS total_devices,
         COUNT(d.id) FILTER (WHERE d.compliance_status = 'Compliant')::int AS compliant,
         COUNT(d.id) FILTER (WHERE d.compliance_status = 'Non-Compliant')::int AS non_compliant,
         COUNT(d.id) FILTER (WHERE d.compliance_status = 'Pending Sync')::int AS pending_sync,
         COUNT(d.id) FILTER (WHERE d.compliance_status = 'Policy Failed')::int AS policy_failed,
         COUNT(d.id) FILTER (WHERE d.compliance_status = 'Unknown')::int AS unknown,
         (SELECT COUNT(*) FROM employees e JOIN departments dp ON e.department_id = dp.id
           WHERE dp.organization_id = o.id AND e.role = 'Employee')::int AS employees,
         (SELECT COUNT(*) FROM employees e JOIN departments dp ON e.department_id = dp.id
           WHERE dp.organization_id = o.id AND e.role = 'DepartmentManager')::int AS managers
  FROM organizations o
  LEFT JOIN dev d ON d.organization_id = o.id
  GROUP BY o.id
  ORDER BY o.name`;

async function orgOverviewRows() {
  const result = await pool.query(ORG_OVERVIEW_SQL);
  return result.rows.map((r) => ({
    ...r,
    compliance_percentage: r.total_devices > 0 ? Math.round((r.compliant / r.total_devices) * 100) : 0,
  }));
}

// GET /api/reports/organizations-overview
router.get("/organizations-overview", async (req, res) => {
  try {
    res.json({ rows: await orgOverviewRows() });
  } catch (err) { fail(res, err); }
});

// GET /api/reports/compliance — compliance status/percentage per organization
router.get("/compliance", async (req, res) => {
  try {
    res.json({ rows: await orgOverviewRows() });
  } catch (err) { fail(res, err); }
});

// ===================== Device Inventory =====================

// GET /api/reports/inventory — device status breakdown per organization
router.get("/inventory", async (req, res) => {
  try {
    const result = await pool.query(
      `WITH ${DEVICE_CTE}
       SELECT o.id, o.name, o.status,
              COUNT(d.id)::int AS total,
              COUNT(d.id) FILTER (WHERE d.status = 'pending')::int AS pending,
              COUNT(d.id) FILTER (WHERE d.status <> 'pending' AND d.is_online)::int AS online,
              COUNT(d.id) FILTER (WHERE d.status <> 'pending' AND NOT d.is_online)::int AS offline,
              COUNT(d.id) FILTER (WHERE d.is_rooted = TRUE)::int AS rooted,
              COUNT(d.id) FILTER (WHERE d.is_locked = TRUE)::int AS locked
       FROM organizations o
       LEFT JOIN dev d ON d.organization_id = o.id
       GROUP BY o.id
       ORDER BY o.name`
    );
    res.json({ rows: result.rows });
  } catch (err) { fail(res, err); }
});

// ===================== Security (risky devices) =====================

// GET /api/reports/security — rooted, policy-failed or non-compliant devices
router.get("/security", async (req, res) => {
  try {
    const result = await pool.query(
      `WITH ${DEVICE_CTE}
       SELECT o.name AS organization, d.device_uid, d.model, d.employee_name,
              d.is_rooted, d.compliance_status, d.battery_level, d.last_seen
       FROM dev d
       JOIN organizations o ON o.id = d.organization_id
       WHERE d.is_rooted = TRUE OR d.compliance_status IN ('Policy Failed', 'Non-Compliant')
       ORDER BY d.is_rooted DESC NULLS LAST, o.name, d.device_uid
       LIMIT ${MAX_ROWS}`
    );
    res.json({ rows: result.rows });
  } catch (err) { fail(res, err); }
});

// ===================== Activity (audit-based) =====================

// GET /api/reports/activity?date_from=&date_to=&organization_id=&limit=
router.get("/activity", async (req, res) => {
  try {
    const { organization_id } = req.query;
    const dateFrom = validDate(req.query.date_from);
    const dateTo = validDate(req.query.date_to);
    const conditions = [];
    const params = [];
    if (dateFrom) { params.push(dateFrom); conditions.push(`al.created_at >= $${params.length}::date`); }
    if (dateTo) { params.push(dateTo); conditions.push(`al.created_at < $${params.length}::date + 1`); }
    if (organization_id && Number.isInteger(Number(organization_id))) {
      params.push(Number(organization_id));
      conditions.push(`al.organization_id = $${params.length}`);
    }
    const result = await pool.query(
      `SELECT al.id, al.created_at, o.name AS organization, u.name AS user_name, u.email AS user_email,
              COALESCE(r.name, u.role) AS role, al.action, al.status, al.details, al.ip_address
       FROM audit_logs al
       LEFT JOIN organizations o ON o.id = al.organization_id
       LEFT JOIN users u ON u.id = al.user_id
       LEFT JOIN roles r ON r.id = u.role_id
       ${conditions.length ? `WHERE ${conditions.join(" AND ")}` : ""}
       ORDER BY al.created_at DESC
       LIMIT ${clampLimit(req.query.limit, 1000)}`,
      params
    );
    res.json({ rows: result.rows });
  } catch (err) { fail(res, err); }
});

// ===================== Applications =====================

// GET /api/reports/applications — blocked / allowed apps and APK installs per organization
router.get("/applications", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.id, o.name, o.status,
              (SELECT COUNT(*) FROM applications a WHERE a.organization_id = o.id)::int AS total_apps,
              (SELECT COUNT(*) FROM applications a WHERE a.organization_id = o.id AND a.status = 'blocked')::int AS blocked_apps,
              (SELECT COUNT(*) FROM applications a WHERE a.organization_id = o.id AND a.status = 'active')::int AS allowed_apps,
              (SELECT COUNT(*) FROM app_packages p WHERE p.organization_id = o.id)::int AS apk_packages,
              (SELECT COUNT(*) FROM app_installs i WHERE i.organization_id = o.id)::int AS installs
       FROM organizations o
       ORDER BY o.name`
    );
    res.json({ rows: result.rows });
  } catch (err) { fail(res, err); }
});

// ===================== Platform Growth =====================

// GET /api/reports/growth?interval=day|week|month&date_from=&date_to=
// New organizations and device enrollments per period (default: last 12 months).
router.get("/growth", async (req, res) => {
  try {
    const interval = ["day", "week", "month"].includes(req.query.interval) ? req.query.interval : "month";
    const now = new Date();
    const defaultFrom = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const dateFrom = validDate(req.query.date_from) || defaultFrom;
    const dateTo = validDate(req.query.date_to) || now.toISOString().slice(0, 10);

    const orgs = await pool.query(
      `SELECT to_char(date_trunc($1::text, created_at), 'YYYY-MM-DD') AS period, COUNT(*)::int AS count
       FROM organizations
       WHERE created_at >= $2::date AND created_at < $3::date + 1
       GROUP BY 1`,
      [interval, dateFrom, dateTo]
    );
    const devices = await pool.query(
      `SELECT to_char(date_trunc($1::text, enrolled_at), 'YYYY-MM-DD') AS period, COUNT(*)::int AS count
       FROM devices
       WHERE enrolled_at IS NOT NULL AND enrolled_at >= $2::date AND enrolled_at < $3::date + 1
       GROUP BY 1`,
      [interval, dateFrom, dateTo]
    );

    const byPeriod = new Map();
    const key = (d) => d;
    orgs.rows.forEach((r) => byPeriod.set(key(r.period), { period: key(r.period), new_organizations: r.count, device_enrollments: 0 }));
    devices.rows.forEach((r) => {
      const k = key(r.period);
      const row = byPeriod.get(k) || { period: k, new_organizations: 0, device_enrollments: 0 };
      row.device_enrollments = r.count;
      byPeriod.set(k, row);
    });
    const rows = [...byPeriod.values()].sort((a, b) => a.period.localeCompare(b.period));
    res.json({ interval, rows });
  } catch (err) { fail(res, err); }
});

// ===================== Cross-Org Security Events =====================

// GET /api/reports/security-events?date_from=&date_to=&organization_id=&limit=
// Failed logins, remote wipe/lock commands, org suspensions/deletions, device
// removals etc. across every organization (see utils/criticalActions.js).
router.get("/security-events", async (req, res) => {
  try {
    const { organization_id } = req.query;
    const dateFrom = validDate(req.query.date_from);
    const dateTo = validDate(req.query.date_to);
    const conditions = [`al.action IN (${criticalActionsSql()})`];
    const params = [];
    if (dateFrom) { params.push(dateFrom); conditions.push(`al.created_at >= $${params.length}::date`); }
    if (dateTo) { params.push(dateTo); conditions.push(`al.created_at < $${params.length}::date + 1`); }
    if (organization_id && Number.isInteger(Number(organization_id))) {
      params.push(Number(organization_id));
      conditions.push(`al.organization_id = $${params.length}`);
    }

    const events = await pool.query(
      `SELECT al.id, al.created_at, o.name AS organization, u.name AS user_name, u.email AS user_email,
              al.action, ${categorySql("al")} AS category, al.status, al.details, al.ip_address
       FROM audit_logs al
       LEFT JOIN organizations o ON o.id = al.organization_id
       LEFT JOIN users u ON u.id = al.user_id
       WHERE ${conditions.join(" AND ")}
       ORDER BY al.created_at DESC
       LIMIT ${clampLimit(req.query.limit, 1000)}`,
      params
    );
    const suspended = await pool.query(
      "SELECT id, name, code FROM organizations WHERE status = 'suspended' ORDER BY name"
    );
    res.json({ rows: events.rows, suspended_organizations: suspended.rows });
  } catch (err) { fail(res, err); }
});

// ===================== Inactive Devices / Organizations =====================

// GET /api/reports/inactive?days=N — no heartbeat for N days (default 7)
router.get("/inactive", async (req, res) => {
  try {
    let days = parseInt(req.query.days, 10);
    if (!Number.isInteger(days) || days < 1) days = 7;
    days = Math.min(days, 365);

    const devices = await pool.query(
      `SELECT o.name AS organization, dv.device_uid, dv.model, dv.employee_name, dv.last_seen,
              CASE WHEN dv.last_seen IS NULL THEN NULL
                   ELSE FLOOR(EXTRACT(EPOCH FROM (NOW() - dv.last_seen)) / 86400)::int END AS days_inactive
       FROM devices dv
       JOIN organizations o ON o.id = dv.organization_id
       WHERE dv.status <> 'pending'
         AND (dv.last_seen IS NULL OR dv.last_seen < NOW() - make_interval(days => $1))
       ORDER BY dv.last_seen ASC NULLS FIRST
       LIMIT ${MAX_ROWS}`,
      [days]
    );
    const organizations = await pool.query(
      `SELECT o.id, o.name, o.status, COUNT(dv.id)::int AS devices, MAX(dv.last_seen) AS last_heartbeat
       FROM organizations o
       LEFT JOIN devices dv ON dv.organization_id = o.id AND dv.status <> 'pending'
       GROUP BY o.id
       HAVING MAX(dv.last_seen) IS NULL OR MAX(dv.last_seen) < NOW() - make_interval(days => $1)
       ORDER BY o.name`,
      [days]
    );
    res.json({ days, devices: devices.rows, organizations: organizations.rows });
  } catch (err) { fail(res, err); }
});

// ===================== Custom Report Builder =====================

// Everything the builder can query is whitelisted below. Column keys, SQL
// expressions and filter fields come from this file only; user input is only
// ever used to PICK from these lists or passed as a bound parameter.
const ORG_COUNT = (table, extra = "") =>
  `(SELECT COUNT(*) FROM ${table} WHERE ${extra})::int`;

const ENTITIES = {
  organizations: {
    label: "Organizations",
    from: "organizations o",
    orgExpr: "o.id",
    dateExpr: "o.created_at",
    dateLabel: "Created date",
    orderBy: "o.name",
    columns: {
      name: ["Name", "o.name"],
      code: ["Code", "o.code"],
      industry: ["Industry", "o.industry"],
      country: ["Country", "o.country"],
      city: ["City", "o.city"],
      email: ["Email", "o.email"],
      status: ["Status", "o.status"],
      created_at: ["Created", "o.created_at"],
      devices: ["Devices", ORG_COUNT("devices dv", "dv.organization_id = o.id")],
      employees: ["Employees", ORG_COUNT("employees e JOIN departments dp ON e.department_id = dp.id", "dp.organization_id = o.id AND e.role = 'Employee'")],
      managers: ["Managers", ORG_COUNT("employees e JOIN departments dp ON e.department_id = dp.id", "dp.organization_id = o.id AND e.role = 'DepartmentManager'")],
      policies: ["Policies", ORG_COUNT("policies p", "p.organization_id = o.id")],
    },
    defaultColumns: ["name", "code", "status", "country", "devices", "employees", "created_at"],
    filters: {
      status: { label: "Status", expr: "o.status", options: ["active", "suspended", "inactive"] },
      country: { label: "Country contains", expr: "o.country" },
    },
  },

  devices: {
    label: "Devices",
    with: DEVICE_CTE,
    from: "dev d JOIN organizations o ON o.id = d.organization_id",
    orgExpr: "d.organization_id",
    dateExpr: "d.enrolled_at",
    dateLabel: "Enrolled date",
    orderBy: "o.name, d.device_uid",
    columns: {
      organization: ["Organization", "o.name"],
      device_uid: ["Device UID", "d.device_uid"],
      model: ["Model", "d.model"],
      manufacturer: ["Manufacturer", "d.manufacturer"],
      android_version: ["Android", "d.android_version"],
      employee_name: ["Employee", "d.employee_name"],
      enrollment_status: ["Enrollment status", "d.status"],
      connectivity: ["Online/Offline", "CASE WHEN d.status = 'pending' THEN 'pending' WHEN d.is_online THEN 'online' ELSE 'offline' END"],
      compliance_status: ["Compliance", "d.compliance_status"],
      is_rooted: ["Rooted", "d.is_rooted"],
      is_locked: ["Locked", "d.is_locked"],
      battery_level: ["Battery %", "d.battery_level"],
      last_seen: ["Last seen", "d.last_seen"],
      enrolled_at: ["Enrolled", "d.enrolled_at"],
    },
    defaultColumns: ["organization", "device_uid", "model", "connectivity", "compliance_status", "last_seen"],
    filters: {
      connectivity: { label: "Online/Offline", expr: "CASE WHEN d.status = 'pending' THEN 'pending' WHEN d.is_online THEN 'online' ELSE 'offline' END", options: ["online", "offline", "pending"] },
      compliance_status: { label: "Compliance", expr: "d.compliance_status", options: ["Compliant", "Non-Compliant", "Pending Sync", "Policy Failed", "Unknown"] },
      is_rooted: { label: "Rooted", expr: "d.is_rooted", options: ["true", "false"] },
    },
  },

  security_events: {
    label: "Security Events",
    from: `audit_logs al
           LEFT JOIN organizations o ON o.id = al.organization_id
           LEFT JOIN users u ON u.id = al.user_id
           LEFT JOIN roles r ON r.id = u.role_id`,
    baseWhere: `al.action IN (${criticalActionsSql()})`,
    orgExpr: "al.organization_id",
    dateExpr: "al.created_at",
    dateLabel: "Event date",
    orderBy: "al.created_at DESC",
    columns: {
      created_at: ["Time", "al.created_at"],
      organization: ["Organization", "o.name"],
      user_name: ["User", "u.name"],
      user_email: ["User email", "u.email"],
      role: ["Role", "COALESCE(r.name, u.role)"],
      action: ["Action", "al.action"],
      category: ["Category", categorySql("al")],
      status: ["Status", "al.status"],
      details: ["Details", "al.details"],
      ip_address: ["IP address", "al.ip_address"],
    },
    defaultColumns: ["created_at", "organization", "user_name", "category", "action", "status", "details"],
    filters: {
      category: { label: "Category", expr: categorySql("al"), options: ["Failed Login", "Remote Wipe / Lock", "Organization", "Device", "Policy / Employee"] },
      status: { label: "Status", expr: "al.status", options: ["success", "failure", "failed"] },
    },
  },

  audit_logs: {
    label: "Activity / Audit Logs",
    from: `audit_logs al
           LEFT JOIN organizations o ON o.id = al.organization_id
           LEFT JOIN users u ON u.id = al.user_id
           LEFT JOIN roles r ON r.id = u.role_id`,
    orgExpr: "al.organization_id",
    dateExpr: "al.created_at",
    dateLabel: "Event date",
    orderBy: "al.created_at DESC",
    columns: {
      created_at: ["Time", "al.created_at"],
      organization: ["Organization", "o.name"],
      user_name: ["User", "u.name"],
      user_email: ["User email", "u.email"],
      role: ["Role", "COALESCE(r.name, u.role)"],
      action: ["Action", "al.action"],
      status: ["Status", "al.status"],
      details: ["Details", "al.details"],
      ip_address: ["IP address", "al.ip_address"],
    },
    defaultColumns: ["created_at", "organization", "user_name", "role", "action", "status"],
    filters: {
      action: { label: "Action contains", expr: "al.action" },
      status: { label: "Status", expr: "al.status", options: ["success", "failure", "failed"] },
    },
  },

  applications: {
    label: "Applications",
    from: "applications a JOIN organizations o ON o.id = a.organization_id",
    orgExpr: "a.organization_id",
    dateExpr: "a.created_at",
    dateLabel: "Created date",
    orderBy: "o.name, a.name",
    columns: {
      organization: ["Organization", "o.name"],
      name: ["Application", "a.name"],
      package_name: ["Package", "a.package_name"],
      version: ["Version", "a.version"],
      category: ["Category", "a.category"],
      install_type: ["Install type", "a.install_type"],
      status: ["Status", "a.status"],
      assigned_devices: ["Assigned devices", "(SELECT COUNT(*) FROM application_assignments aa WHERE aa.application_id = a.id)::int"],
      created_at: ["Created", "a.created_at"],
    },
    defaultColumns: ["organization", "name", "package_name", "category", "status", "assigned_devices"],
    filters: {
      status: { label: "Status", expr: "a.status", options: ["active", "blocked"] },
      category: { label: "Category", expr: "a.category", options: ["Enterprise", "Public"] },
    },
  },
};

// GET /api/reports/custom/meta — what the builder UI can offer
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

// POST /api/reports/custom
// Body: { entity, columns[], filters{}, organization_ids[], date_from, date_to, limit }
router.post("/custom", async (req, res) => {
  try {
    const { entity, columns, filters, organization_ids } = req.body || {};
    const def = ENTITIES[entity];
    if (!def) return res.status(400).json({ error: "Unknown data source" });

    const requested = Array.isArray(columns) && columns.length > 0 ? columns : def.defaultColumns;
    const keys = [...new Set(requested)].filter((k) => Object.prototype.hasOwnProperty.call(def.columns, k));
    if (keys.length === 0) return res.status(400).json({ error: "Select at least one valid column" });

    const params = [];
    const conditions = [];
    if (def.baseWhere) conditions.push(def.baseWhere);

    // Scope: all organizations (no ids) or a selected set
    if (Array.isArray(organization_ids) && organization_ids.length > 0) {
      const ids = organization_ids.slice(0, 500).map(Number).filter((n) => Number.isInteger(n));
      if (ids.length === 0) return res.status(400).json({ error: "Invalid organization selection" });
      params.push(ids);
      conditions.push(`${def.orgExpr} = ANY($${params.length}::int[])`);
    }

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
    const sql = `${def.with ? `WITH ${def.with}` : ""}
      SELECT ${select}
      FROM ${def.from}
      ${conditions.length ? `WHERE ${conditions.join(" AND ")}` : ""}
      ORDER BY ${def.orderBy}
      LIMIT ${limit + 1}`;

    const result = await pool.query(sql, params);
    const truncated = result.rows.length > limit;
    res.json({
      columns: keys.map((k) => ({ key: k, label: def.columns[k][0] })),
      rows: result.rows.slice(0, limit),
      truncated,
      limit,
    });
  } catch (err) { fail(res, err); }
});

module.exports = router;
