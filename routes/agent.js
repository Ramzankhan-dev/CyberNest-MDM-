const express = require("express");
const pool = require("../config/db");
const logAudit = require("../utils/auditLog");

const router = express.Router();

// This file holds agent-facing endpoints (no dashboard login — the
// Android agent authenticates itself by device_uid, same pattern as
// the existing /api/devices/confirm and /api/devices/:uid/heartbeat
// routes). SRS-A03 is the first screen to need this namespace; later
// screens (A05 Device Status, A06 Sync, etc.) will add routes here
// too rather than starting yet another top-level router.

// POST /api/agent/provisioning/verify   (SRS-A03 FR-01..FR-03)
// Confirms the device is a real enrolled device (completed
// /api/devices/confirm already) before the agent proceeds with
// Device Owner provisioning checks. Read-only.
router.post("/provisioning/verify", async (req, res) => {
  const { device_uid } = req.body;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const result = await pool.query(
      `SELECT dv.device_uid, dv.model, dv.fcm_token, dv.enrolled_at,
              org.name AS organization_name,
              ep.name AS enrollment_profile_name
       FROM devices dv
       LEFT JOIN organizations org ON dv.organization_id = org.id
       LEFT JOIN enrollment_profiles ep ON dv.enrollment_profile_id = ep.id
       WHERE dv.device_uid = $1`,
      [device_uid]
    );
    const device = result.rows[0];

    if (!device) {
      return res.status(404).json({ error: "Device not found — complete enrollment first" });
    }
    if (!device.fcm_token || !device.enrolled_at) {
      return res.status(409).json({ error: "Device has not completed enrollment yet" });
    }

    res.json({
      verified: true,
      organization_name: device.organization_name || "Unknown Organization",
      device_name: device.model || "Unknown Device",
      enrollment_profile_name: device.enrollment_profile_name || null,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/agent/provisioning/complete   (SRS-A03 FR-11/FR-12)
// Called once the agent has confirmed Device Owner mode is active
// locally (dpm.isDeviceOwnerApp() == true) — records that the device
// finished the SRS-A03 checklist, separate from the earlier
// enrollment-confirm timestamp.
router.post("/provisioning/complete", async (req, res) => {
  const { device_uid } = req.body;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const result = await pool.query(
      `UPDATE devices SET device_owner_confirmed_at = NOW()
       WHERE device_uid = $1 RETURNING organization_id`,
      [device_uid]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Device not found" });
    }

    await logAudit({
      organizationId: result.rows[0].organization_id,
      action: "device_owner_provisioning_complete",
      status: "success",
      req,
      details: device_uid,
    });

    res.json({ message: "Provisioning marked complete" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/agent/policies/default   (SRS-A03 FR-08 — "Download Initial Policies")
// Same underlying data as /api/devices/:uid/current-policy — kept as
// its own route here because SRS-A03 names it separately and later
// agent screens will expect everything agent-facing under /api/agent.
router.get("/policies/default", async (req, res) => {
  const { device_uid } = req.query;
  if (!device_uid) return res.status(400).json({ error: "device_uid is required" });

  try {
    const result = await pool.query(
      `SELECT p.* FROM device_policies dp
       JOIN devices d ON dp.device_id = d.id
       JOIN policies p ON dp.policy_id = p.id
       WHERE d.device_uid = $1
       ORDER BY dp.assigned_at DESC LIMIT 1`,
      [device_uid]
    );
    res.json({ policy: result.rows[0] || null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
