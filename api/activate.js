// Device check-in for Notepad licences. Called by each app's licence gate.
//
//   POST /api/activate  { token, device }
//     200 { ok: true, devices, limit }
//     403 { ok: false, reason: "revoked" | "limit", devices?, limit? }
//     400 bad input; 5xx -> app treats as offline and stays open.
//
// Counting is always on; blocking at the device limit only when the admin
// switch site:lic:enforce = "on" (toggle on /api/license). Revoked licences
// are always refused.

import { DEVICE_LIMITS, metaCommand, verifyLicenseToken } from "./_lib/license.js";
import { rateLimit, redisPipeline, tooMany } from "./_lib/security.js";

const ORIGIN_OK = /^https:\/\/[a-z0-9-]+\.vercel\.app$/;
const DEVICE_RE = /^[A-Za-z0-9_-]{16,64}$/;

function cors(req, res) {
  const o = String(req.headers.origin || "");
  if (ORIGIN_OK.test(o)) {
    res.setHeader("Access-Control-Allow-Origin", o);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Max-Age", "86400");
  }
}

function body(req) {
  let b = req.body;
  if (typeof b === "string") {
    try { b = JSON.parse(b); } catch { b = {}; }
  }
  return b && typeof b === "object" ? b : {};
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  cors(req, res);
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }

  const { token, device } = body(req);
  const payload = verifyLicenseToken(token);
  if (!payload || !DEVICE_RE.test(String(device || ""))) {
    res.status(400).json({ ok: false, reason: "invalid" });
    return;
  }

  const rl = await rateLimit(req, { bucket: "activate", limit: 120, windowSec: 3600, failOpen: true });
  if (!rl.ok) {
    tooMany(res, rl);
    return;
  }

  const lid = payload.lid;
  const DEV = `site:lic:dev:${lid}`;
  const limit = DEVICE_LIMITS[payload.tier] || DEVICE_LIMITS.individual;
  try {
    const [revoked, enforce, known, count, meta] = await redisPipeline([
      ["SISMEMBER", "site:lic:revoked", lid],
      ["GET", "site:lic:enforce"],
      ["HEXISTS", DEV, device],
      ["HLEN", DEV],
      ["HEXISTS", "site:lic:meta", lid],
    ]);
    if (revoked) {
      res.status(403).json({ ok: false, reason: "revoked" });
      return;
    }
    if (!known && enforce === "on" && count >= limit) {
      res.status(403).json({ ok: false, reason: "limit", devices: count, limit });
      return;
    }
    const cmds = [["HSET", DEV, device, new Date().toISOString()]];
    if (!meta) cmds.push(metaCommand(payload, payload.ref)); // licences issued before tracking
    await redisPipeline(cmds);
    res.status(200).json({ ok: true, devices: known ? count : count + 1, limit });
  } catch (e) {
    console.error("activate failed", e && e.message);
    res.status(503).json({ ok: false, reason: "unavailable" });
  }
}
