// Shared security helpers for the /api routes. Files under api/_lib are not
// deployed as routes (Vercel skips paths that start with "_").
//
// Everything here runs on the existing Upstash Redis store; no extra service.

import crypto from "node:crypto";

function redisCreds() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error("NOT_CONFIGURED");
  return { url, token };
}

async function redisPipeline(commands) {
  const { url, token } = redisCreds();
  const res = await fetch(`${url}/pipeline`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(commands),
  });
  if (!res.ok) throw new Error(`REDIS_${res.status}`);
  return (await res.json()).map((r) => r.result);
}

const sha256 = (s) => crypto.createHash("sha256").update(String(s)).digest();

// Constant-time string compare (hashing first makes lengths equal).
export function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha256(a), sha256(b));
}

// Client IP as set by Vercel's edge (it overwrites x-forwarded-for).
export function clientIp(req) {
  const h = req.headers || {};
  const xff = String(h["x-forwarded-for"] || "").split(",")[0].trim();
  return xff || String(h["x-real-ip"] || "") || (req.socket && req.socket.remoteAddress) || "unknown";
}

// Hashed so raw IPs are never stored.
const ipTag = (req) => sha256(`ip:${clientIp(req)}`).toString("hex").slice(0, 24);

/**
 * Fixed-window counter. Returns { ok, retryAfter }.
 * scope "ip" counts per visitor, "global" counts across everyone.
 * failOpen: when Redis is missing or down, let the request through
 * (the route's own storage call then reports the error).
 */
export async function rateLimit(req, { bucket, limit, windowSec, scope = "ip", failOpen = false }) {
  const who = scope === "global" ? "all" : ipTag(req);
  const key = `site:rl:${bucket}:${who}`;
  try {
    const [, count, ttl] = await redisPipeline([
      ["SET", key, "0", "EX", String(windowSec), "NX"],
      ["INCR", key],
      ["TTL", key],
    ]);
    if (Number(count) > limit) return { ok: false, retryAfter: Math.max(1, Number(ttl) || windowSec) };
    return { ok: true, retryAfter: 0 };
  } catch {
    return failOpen ? { ok: true, retryAfter: 0 } : { ok: false, retryAfter: 60, error: true };
  }
}

export function tooMany(res, rl, message = "Too many requests. Please wait a bit and try again.") {
  res.setHeader("Retry-After", String(rl.retryAfter || 60));
  res.status(rl.error ? 503 : 429).json({ error: rl.error ? "Service temporarily unavailable." : message });
}

// Browsers always send Origin on POST. Reject cross-site posts and scripts
// that don't pretend to be the site.
export function sameOrigin(req) {
  const h = req.headers || {};
  const origin = String(h.origin || "");
  const host = String(h["x-forwarded-host"] || h.host || "");
  if (!origin || !host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

// ---- Admin session (signed cookie, no server storage) ----

export const ADMIN_COOKIE = "vs_admin";
const SESSION_SEC = 12 * 60 * 60;

const sign = (adminKey, exp) =>
  crypto.createHmac("sha256", adminKey).update(`admin:${exp}`).digest("base64url");

export function adminCookie(adminKey) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_SEC;
  const value = `${exp}.${sign(adminKey, exp)}`;
  return `${ADMIN_COOKIE}=${value}; Path=/api; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SEC}`;
}

export const clearAdminCookie = () =>
  `${ADMIN_COOKIE}=; Path=/api; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

function readCookie(req, name) {
  const raw = String((req.headers && req.headers.cookie) || "");
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return "";
}

/**
 * True when the request carries a valid admin session cookie, or an
 * "Authorization: Bearer <REVIEWS_ADMIN_KEY>" header (for scripts).
 * Changing REVIEWS_ADMIN_KEY logs every session out.
 */
export function isAdmin(req, adminKey) {
  if (!adminKey) return false;
  const auth = String((req.headers && req.headers.authorization) || "");
  if (auth.startsWith("Bearer ") && safeEqual(auth.slice(7), adminKey)) return true;
  const [exp, mac] = readCookie(req, ADMIN_COOKIE).split(".");
  if (!exp || !mac || !/^\d+$/.test(exp) || Number(exp) < Date.now() / 1000) return false;
  return safeEqual(mac, sign(adminKey, exp));
}
