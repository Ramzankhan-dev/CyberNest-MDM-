const express = require("express");
const fs = require("fs");
const os = require("os");
const multer = require("multer");
const pool = require("../config/db");
const admin = require("../config/firebase");
const requireAuth = require("../middleware/auth");
const logAudit = require("../utils/auditLog");
const { readApkInfo } = require("../utils/apkInfo");

const router = express.Router();
// The uploaded APK is written to a temporary file first so its manifest
// can be inspected, then stored in app_packages.apk_data (Render's disk is
// ephemeral, so the DB is the real storage). The temp file is always
// removed afterwards, whether the upload succeeded or was rejected.
// 150MB covers real-world APK sizes with headroom.
const upload = multer({ dest: os.tmpdir(), limits: { fileSize: 150 * 1024 * 1024 } });

function removeTempFile(file) {
  if (file && file.path) fs.promises.unlink(file.path).catch(() => {});
}

function isValidPackage(pkg) {
  return /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/.test(pkg);
}

// POST /api/applications   (multipart: apk file + name, package_name?, version?, category, install_type)
// One flow for adding an application: the APK is required, its real package
// name is read from the APK manifest, and the record + APK are saved together.
router.post("/", requireAuth, upload.single("apk"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "APK file is required" });

    const { name, package_name, version, category, install_type, organization_id } = req.body;
    const orgId = req.user.is_super_admin ? (organization_id || req.user.organization_id) : req.user.organization_id;

    if (!name || !name.trim()) return res.status(400).json({ error: "Application name is required" });
    const entered = (package_name || "").trim();
    if (entered && !isValidPackage(entered)) return res.status(400).json({ error: "Package name is invalid" });

    let info;
    try {
      info = await readApkInfo(req.file.path);
    } catch (err) {
      return res.status(400).json({ error: "Could not read this file — please upload a valid .apk" });
    }
    if (!info.packageName || !isValidPackage(info.packageName)) {
      return res.status(400).json({ error: "Could not read a package name from this APK" });
    }
    if (entered && entered !== info.packageName) {
      return res.status(400).json({ error: `Package name mismatch: the uploaded APK belongs to '${info.packageName}', not '${entered}'` });
    }
    const pkgName = info.packageName;

    const dup = await pool.query(
      `SELECT 1 FROM applications WHERE organization_id = $1 AND package_name = $2
       UNION ALL
       SELECT 1 FROM app_packages WHERE organization_id = $1 AND package_name = $2`,
      [orgId, pkgName]
    );
    if (dup.rows.length > 0) return res.status(409).json({ error: "This package already exists" });

    const versionToStore = (version && version.trim()) || info.versionName || null;
    const apkData = await fs.promises.readFile(req.file.path);

    const client = await pool.connect();
    let application;
    try {
      await client.query("BEGIN");
      await client.query(
        `INSERT INTO app_packages (organization_id, app_name, package_name, version_name, file_size_bytes, apk_data)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [orgId, name.trim(), pkgName, versionToStore, req.file.size, apkData]
      );
      const result = await client.query(
        `INSERT INTO applications (organization_id, name, package_name, version, category, install_type)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [orgId, name.trim(), pkgName, versionToStore, category || "Public", install_type || "Optional"]
      );
      await client.query("COMMIT");
      application = result.rows[0];
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }

    await logAudit({ userId: req.user.id, organizationId: orgId, action: "application_registered", status: "success", req, details: pkgName });
    res.status(201).json({ message: "Application added", application });
  } catch (err) {
    console.error(err);
    if (err.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: "APK is too large (max 150MB)" });
    res.status(500).json({ error: "Server error" });
  } finally {
    removeTempFile(req.file);
  }
});

// GET /api/applications   (SRS-012) — search, filter, pagination
router.get("/", requireAuth, async (req, res) => {
  try {
    const { search, category, status, installed, page = 1, limit = 50, organization_id } = req.query;
    const orgId = req.user.is_super_admin ? organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const conditions = ["a.organization_id = $1"];
    const params = [orgId];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(a.name ILIKE $${params.length} OR a.package_name ILIKE $${params.length})`);
    }
    if (category) {
      params.push(category);
      conditions.push(`a.category = $${params.length}`);
    }
    if (status) {
      params.push(status);
      conditions.push(`a.status = $${params.length}`);
    }

    const filterParamCount = params.length;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), offset);

    const result = await pool.query(
      `SELECT a.*,
              (SELECT COUNT(DISTINCT device_id) FROM application_assignments aa WHERE aa.application_id = a.id) AS assigned_devices_count,
              (SELECT COUNT(DISTINCT da.device_id) FROM device_apps da JOIN devices dv ON da.device_id = dv.id
                WHERE da.package_name = a.package_name AND dv.organization_id = a.organization_id) AS installed_count,
              pk.id AS package_id, pk.file_size_bytes, pk.uploaded_at AS apk_uploaded_at
       FROM applications a
       LEFT JOIN LATERAL (
         SELECT p.id, p.file_size_bytes, p.uploaded_at FROM app_packages p
         WHERE p.organization_id = a.organization_id AND p.package_name = a.package_name
         ORDER BY p.uploaded_at DESC LIMIT 1
       ) pk ON TRUE
       WHERE ${conditions.join(" AND ")}
       ORDER BY a.created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countResult = await pool.query(`SELECT COUNT(*) FROM applications a WHERE ${conditions.join(" AND ")}`, params.slice(0, filterParamCount));

    res.json({ applications: result.rows, total: parseInt(countResult.rows[0].count), page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/applications/stats   (SRS-012) — the 6 dashboard cards
router.get("/stats", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? req.query.organization_id : req.user.organization_id;
    if (!orgId) return res.status(400).json({ error: "organization_id is required" });

    const total = await pool.query("SELECT COUNT(*) FROM applications WHERE organization_id = $1", [orgId]);
    const enterprise = await pool.query("SELECT COUNT(*) FROM applications WHERE organization_id = $1 AND category = 'Enterprise'", [orgId]);
    const publicApps = await pool.query("SELECT COUNT(*) FROM applications WHERE organization_id = $1 AND category = 'Public'", [orgId]);
    const blocked = await pool.query("SELECT COUNT(*) FROM applications WHERE organization_id = $1 AND status = 'blocked'", [orgId]);
    const installed = await pool.query(
      `SELECT COUNT(DISTINCT da.package_name) FROM device_apps da JOIN devices dv ON da.device_id = dv.id
       JOIN applications a ON a.package_name = da.package_name AND a.organization_id = dv.organization_id
       WHERE dv.organization_id = $1`,
      [orgId]
    );
    const pending = await pool.query(
      `SELECT COUNT(*) FROM commands c JOIN devices d ON c.device_id = d.id
       WHERE d.organization_id = $1 AND c.command_type IN ('block_app', 'unblock_app', 'install_app') AND c.status IN ('pending', 'sent')`,
      [orgId]
    );

    res.json({
      total_applications: parseInt(total.rows[0].count),
      enterprise_apps: parseInt(enterprise.rows[0].count),
      public_apps: parseInt(publicApps.rows[0].count),
      blocked_apps: parseInt(blocked.rows[0].count),
      installed_applications: parseInt(installed.rows[0].count),
      pending_installations: parseInt(pending.rows[0].count),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PUT /api/applications/:id   (multipart, optional apk — attaches / replaces the APK)
router.put("/:id", requireAuth, upload.single("apk"), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, version, category, install_type } = req.body;

    const existing = await pool.query("SELECT * FROM applications WHERE id = $1", [id]);
    const current = existing.rows[0];
    if (!current) return res.status(404).json({ error: "Application not found" });

    let info = null;
    if (req.file) {
      try {
        info = await readApkInfo(req.file.path);
      } catch (err) {
        return res.status(400).json({ error: "Could not read this file — please upload a valid .apk" });
      }
      if (info.packageName !== current.package_name) {
        return res.status(400).json({ error: `Package name mismatch: the uploaded APK belongs to '${info.packageName}', not '${current.package_name}'` });
      }
    }

    const versionToStore = (version && version.trim()) || (info && info.versionName) || null;
    const result = await pool.query(
      `UPDATE applications SET name = COALESCE($1, name), version = COALESCE($2, version),
        category = COALESCE($3, category), install_type = COALESCE($4, install_type), updated_at = NOW()
       WHERE id = $5 RETURNING *`,
      [name && name.trim() ? name.trim() : null, versionToStore, category, install_type, id]
    );
    const app = result.rows[0];

    if (req.file) {
      const apkData = await fs.promises.readFile(req.file.path);
      // Update the stored APK in place so install history stays attached to it.
      const upd = await pool.query(
        `UPDATE app_packages SET app_name = $1, version_name = $2, file_size_bytes = $3, apk_data = $4, uploaded_at = NOW()
         WHERE id = (SELECT id FROM app_packages WHERE organization_id = $5 AND package_name = $6 ORDER BY uploaded_at DESC LIMIT 1)`,
        [app.name, app.version, req.file.size, apkData, app.organization_id, app.package_name]
      );
      if (upd.rowCount === 0) {
        await pool.query(
          `INSERT INTO app_packages (organization_id, app_name, package_name, version_name, file_size_bytes, apk_data)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [app.organization_id, app.name, app.package_name, app.version, req.file.size, apkData]
        );
      }
    }

    await logAudit({ userId: req.user.id, organizationId: app.organization_id, action: "application_updated", status: "success", req });
    res.json({ message: "Application updated", application: app });
  } catch (err) {
    console.error(err);
    if (err.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: "APK is too large (max 150MB)" });
    res.status(500).json({ error: "Server error" });
  } finally {
    removeTempFile(req.file);
  }
});

// Shared helper — sends block_app / unblock_app / uninstall_app to a device via FCM.
// Returns true if the push was accepted, false if it could not be delivered
// (the command row is then marked failed with the reason).
async function sendAppCommand(device, commandType, packageName, issuedBy, req) {
  const commandLog = await pool.query(
    `INSERT INTO commands (device_id, command_type, issued_by, status) VALUES ($1, $2, $3, 'pending') RETURNING *`,
    [device.id, commandType, issuedBy]
  );
  try {
    await admin.messaging().send({ token: device.fcm_token, data: { command: commandType, command_id: String(commandLog.rows[0].id), package_name: packageName } });
    await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1", [commandLog.rows[0].id]);
    return true;
  } catch (err) {
    await pool.query("UPDATE commands SET status = 'failed', error_message = $1 WHERE id = $2", [err.message, commandLog.rows[0].id]);
    return false;
  }
}

// Devices of an organization that currently have this package installed
// (as last reported by the agent) and can receive a push.
async function devicesWithAppInstalled(orgId, packageName) {
  const r = await pool.query(
    `SELECT DISTINCT dv.* FROM devices dv JOIN device_apps da ON da.device_id = dv.id
     WHERE dv.organization_id = $1 AND da.package_name = $2 AND dv.fcm_token IS NOT NULL`,
    [orgId, packageName]
  );
  return r.rows;
}

// Records that an application is assigned to a device (once per device).
async function recordAssignment(applicationId, deviceId, userId) {
  await pool.query(
    `INSERT INTO application_assignments (application_id, device_id, assigned_by)
     SELECT $1, $2, $3 WHERE NOT EXISTS (
       SELECT 1 FROM application_assignments WHERE application_id = $1 AND device_id = $2)`,
    [applicationId, deviceId, userId]
  );
}

// Pushes the silent APK install to one device.
// Returns { ok: true, command_id } or { ok: false, code, error }.
async function pushInstall(application, pkg, device, userId, req) {
  if (!device.fcm_token) return { ok: false, code: 409, error: "Device is not enrolled yet" };

  const alreadyInstalled = await pool.query(
    `SELECT 1 FROM app_installs WHERE app_package_id = $1 AND device_id = $2
     UNION ALL SELECT 1 FROM device_apps WHERE device_id = $2 AND package_name = $3`,
    [pkg.id, device.id, pkg.package_name]
  );
  if (alreadyInstalled.rows.length > 0) {
    return { ok: false, code: 409, already: true, error: `"${pkg.app_name}" is already installed on this device` };
  }

  const inProgress = await pool.query(
    `SELECT 1 FROM commands WHERE device_id = $1 AND package_id = $2 AND command_type = 'install_app'
       AND status IN ('pending', 'sent') AND issued_at > NOW() - INTERVAL '10 minutes'`,
    [device.id, pkg.id]
  );
  if (inProgress.rows.length > 0) {
    return { ok: false, code: 409, already: true, error: `"${pkg.app_name}" is already being installed on this device` };
  }

  const commandLog = await pool.query(
    `INSERT INTO commands (device_id, command_type, issued_by, status, package_id) VALUES ($1, 'install_app', $2, 'pending', $3) RETURNING id`,
    [device.id, userId, pkg.id]
  );
  try {
    await admin.messaging().send({
      token: device.fcm_token,
      data: {
        command: "install_app",
        command_id: String(commandLog.rows[0].id),
        package_id: String(pkg.id),
        package_name: pkg.package_name,
        app_name: pkg.app_name,
        version_name: pkg.version_name || "",
      },
    });
    await pool.query("UPDATE commands SET status = 'sent' WHERE id = $1", [commandLog.rows[0].id]);
    await recordAssignment(application.id, device.id, userId);
    await logAudit({ userId, organizationId: pkg.organization_id, action: "app_install_pushed", status: "success", req, details: `${pkg.app_name} -> ${device.device_uid}` });
    return { ok: true, command_id: commandLog.rows[0].id };
  } catch (err) {
    await pool.query("UPDATE commands SET status = 'failed', error_message = $1 WHERE id = $2", [err.message, commandLog.rows[0].id]);
    return { ok: false, code: 502, error: "Failed to reach device" };
  }
}

async function latestPackage(application) {
  const r = await pool.query(
    "SELECT * FROM app_packages WHERE organization_id = $1 AND package_name = $2 ORDER BY uploaded_at DESC LIMIT 1",
    [application.organization_id, application.package_name]
  );
  return r.rows[0] || null;
}

// POST /api/applications/:id/assign   (body: { device_uid } or { department_id })
// Records the assignment for every target device and then acts on it:
//  - Restricted apps are blocked on the target device(s) that have them installed.
//  - Any other app gets its APK pushed (silent install) to each target device
//    that doesn't have it yet. A department resolves to every device whose
//    employee belongs to that department.
router.post("/:id/assign", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { device_uid, department_id } = req.body;
    if (!device_uid && !department_id) return res.status(400).json({ error: "Select at least one device or department" });

    const appResult = await pool.query("SELECT * FROM applications WHERE id = $1", [id]);
    const app = appResult.rows[0];
    if (!app || (!req.user.is_super_admin && app.organization_id !== req.user.organization_id)) {
      return res.status(404).json({ error: "Application not found" });
    }
    if (app.status === "blocked") return res.status(409).json({ error: "This application is blocked — unblock it before assigning" });

    let targetDevices = [];
    if (device_uid) {
      const d = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, app.organization_id]);
      targetDevices = d.rows;
    } else {
      const d = await pool.query(
        `SELECT DISTINCT dv.* FROM devices dv JOIN employees e ON e.device_id = dv.id
         WHERE e.department_id = $1 AND dv.organization_id = $2`,
        [department_id, app.organization_id]
      );
      targetDevices = d.rows;
    }
    if (targetDevices.length === 0) return res.status(404).json({ error: "No matching devices found" });

    const pkg = app.category === "Restricted" ? null : await latestPackage(app);
    const summary = { installs_sent: 0, already_installed: 0, blocked: 0, unreachable: 0 };

    for (const device of targetDevices) {
      await recordAssignment(app.id, device.id, req.user.id);

      if (app.category === "Restricted") {
        const installed = await pool.query("SELECT 1 FROM device_apps WHERE device_id = $1 AND package_name = $2", [device.id, app.package_name]);
        if (installed.rows.length > 0 && device.fcm_token) {
          (await sendAppCommand(device, "block_app", app.package_name, req.user.id, req)) ? summary.blocked++ : summary.unreachable++;
        }
      } else if (pkg) {
        const r = await pushInstall(app, pkg, device, req.user.id, req);
        if (r.ok) summary.installs_sent++;
        else if (r.already) summary.already_installed++;
        else summary.unreachable++;
      }
    }

    await logAudit({ userId: req.user.id, organizationId: app.organization_id, action: "application_assigned", status: "success", req, details: `${app.name} -> ${targetDevices.length} device(s)` });

    const parts = [`Assigned to ${targetDevices.length} device(s)`];
    if (app.category === "Restricted") {
      parts.push(`block sent to ${summary.blocked}`);
    } else if (!pkg) {
      parts.push("no APK stored for this application, so nothing was installed");
    } else {
      parts.push(`install sent to ${summary.installs_sent}`);
      if (summary.already_installed) parts.push(`already installed / in progress on ${summary.already_installed}`);
    }
    if (summary.unreachable) parts.push(`${summary.unreachable} could not be reached`);
    res.json({ message: parts.join(" — "), enforced: app.category === "Restricted", ...summary });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/applications/:id/block   (SRS-012 FR-04)
// Marks the app Blocked and hides it on every device that has it installed.
router.patch("/:id/block", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const appResult = await pool.query("UPDATE applications SET status = 'blocked', updated_at = NOW() WHERE id = $1 RETURNING *", [id]);
    const app = appResult.rows[0];
    if (!app) return res.status(404).json({ error: "Application not found" });

    const devices = await devicesWithAppInstalled(app.organization_id, app.package_name);
    let notified = 0;
    for (const device of devices) {
      if (await sendAppCommand(device, "block_app", app.package_name, req.user.id, req)) notified++;
    }

    await logAudit({ userId: req.user.id, organizationId: app.organization_id, action: "application_blocked", status: "success", req, details: app.package_name });
    res.json({ message: "Application blocked", devices_notified: notified });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// PATCH /api/applications/:id/allow   (SRS-012 FR-05) — unhides it again everywhere
router.patch("/:id/allow", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const appResult = await pool.query("UPDATE applications SET status = 'active', updated_at = NOW() WHERE id = $1 RETURNING *", [id]);
    const app = appResult.rows[0];
    if (!app) return res.status(404).json({ error: "Application not found" });

    const devices = await devicesWithAppInstalled(app.organization_id, app.package_name);
    let notified = 0;
    for (const device of devices) {
      if (await sendAppCommand(device, "unblock_app", app.package_name, req.user.id, req)) notified++;
    }

    await logAudit({ userId: req.user.id, organizationId: app.organization_id, action: "application_allowed", status: "success", req, details: app.package_name });
    res.json({ message: "Application allowed", devices_notified: notified });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/applications/:id
// First sends an uninstall command to every device that has the app installed,
// then removes the application record and its stored APK.
router.delete("/:id", requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const existing = await client.query("SELECT * FROM applications WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).json({ error: "Application not found" });
    const app = existing.rows[0];

    const devices = await devicesWithAppInstalled(app.organization_id, app.package_name);
    let uninstallsSent = 0;
    for (const device of devices) {
      if (await sendAppCommand(device, "uninstall_app", app.package_name, req.user.id, req)) uninstallsSent++;
    }

    await client.query("BEGIN");
    await client.query("DELETE FROM application_assignments WHERE application_id = $1", [id]);
    await client.query(
      `UPDATE commands SET package_id = NULL
       WHERE package_id IN (SELECT id FROM app_packages WHERE organization_id = $1 AND package_name = $2)`,
      [app.organization_id, app.package_name]
    );
    await client.query("DELETE FROM app_packages WHERE organization_id = $1 AND package_name = $2", [app.organization_id, app.package_name]);
    await client.query("DELETE FROM applications WHERE id = $1", [id]);
    await client.query("COMMIT");

    await logAudit({ userId: req.user.id, organizationId: app.organization_id, action: "application_deleted", status: "success", req, details: `${app.package_name} — uninstall sent to ${uninstallsSent}/${devices.length} device(s)` });
    res.json({
      message: devices.length === 0
        ? "Application deleted"
        : `Application deleted — uninstall sent to ${uninstallsSent} of ${devices.length} device(s)`,
      uninstall_sent: uninstallsSent,
      devices_with_app: devices.length,
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(err);
    res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

// ===================== DIRECT APK INSTALL =====================
// Upload an APK once, then push a silent install to any device — the
// piece that was previously deferred (that gap was Managed Google Play
// / package-name installs from the Play Store, which need a Google
// Cloud enterprise account; this instead ships the APK bytes directly
// and installs via the Device Owner's PackageInstaller API, which
// needs nothing beyond what's already set up).

// POST /api/applications/:id/install   (body: { device_uid })
// :id is the application's id. Sends an "install_app" FCM command — the
// device fetches the APK from GET /api/agent/apps/packages/:id/download
// (agent-facing, in routes/agent.js) and installs it silently via
// PackageInstaller, which Device Owner apps can do without a user
// confirmation dialog.
router.post("/:id/install", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { device_uid } = req.body;
    if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

    const appResult = await pool.query("SELECT * FROM applications WHERE id = $1", [id]);
    const application = appResult.rows[0];
    if (!application || (!req.user.is_super_admin && application.organization_id !== req.user.organization_id)) {
      return res.status(404).json({ error: "Application not found" });
    }
    if (application.status === "blocked") {
      return res.status(409).json({ error: "This application is blocked — allow it before installing" });
    }

    const pkg = await latestPackage(application);
    if (!pkg) return res.status(409).json({ error: "No APK is stored for this application — edit it and upload an APK first" });

    const deviceResult = await pool.query("SELECT * FROM devices WHERE device_uid = $1 AND organization_id = $2", [device_uid, application.organization_id]);
    const device = deviceResult.rows[0];
    if (!device) return res.status(404).json({ error: "Device not found" });

    const result = await pushInstall(application, pkg, device, req.user.id, req);
    if (!result.ok) return res.status(result.code).json({ error: result.error });
    res.json({ message: `Install command sent to ${device.model || device.device_uid}`, command_id: result.command_id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/applications/packages/installs   — full install history:
// which APK, which device, which admin pushed it, and when.
router.get("/packages/installs", requireAuth, async (req, res) => {
  try {
    const orgId = req.user.is_super_admin ? (req.query.organization_id || req.user.organization_id) : req.user.organization_id;
    const result = await pool.query(
      `SELECT ai.id, ai.installed_at,
              ap.app_name, ap.package_name, ap.version_name,
              dv.device_uid, dv.model AS device_model,
              u.name AS installed_by_name
       FROM app_installs ai
       JOIN app_packages ap ON ai.app_package_id = ap.id
       JOIN devices dv ON ai.device_id = dv.id
       LEFT JOIN users u ON ai.installed_by = u.id
       WHERE ai.organization_id = $1
       ORDER BY ai.installed_at DESC
       LIMIT 200`,
      [orgId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
