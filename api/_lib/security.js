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

// POST a batch to Upstash. "/multi-exec" runs it as one atomic transaction,
// "/pipeline" does not. A per-command { error } throws, so callers never
// treat a failed command as a result.
async function redisBatch(path, commands) {
  const { url, token } = redisCreds();
  const res = await fetch(`${url}${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(commands),
  });
  if (!res.ok) throw new Error(`REDIS_${res.status}`);
  const out = await res.json();
  // A discarded transaction answers a single { error } instead of an array.
  if (!Array.isArray(out)) throw new Error(`REDIS_CMD: ${(out && out.error) || "bad response"}`);
  return out.map((r) => {
    if (!r || r.error) throw new Error(`REDIS_CMD: ${(r && r.error) || "empty"}`);
    return r.result;
  });
}

const sha256 = (s) => crypto.createHash("sha256").update(String(s)).digest();
const tag = (s) => sha256(s).toString("hex").slice(0, 24);

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
const ipTag = (req) => tag(`ip:${clientIp(req)}`);

/**
 * Fixed-window counter. Returns { ok, retryAfter }.
 * scope "ip" counts per visitor, "global" counts across everyone.
 * identity: count per this value instead (e.g. an email). It is hashed
 * into the key, so the raw value is never stored.
 * failOpen: when Redis is missing or down, let the request through
 * (the route's own storage call then reports the error).
 */
export async function rateLimit(req, { bucket, limit, windowSec, scope = "ip", identity, failOpen = false }) {
  const who = identity != null ? tag(`id:${identity}`) : scope === "global" ? "all" : ipTag(req);
  const key = `site:rl:${bucket}:${who}`;
  try {
    // One transaction, so the key can't expire between SET and INCR and be
    // recreated by INCR without an expiry.
    const [, count, ttl] = await redisBatch("/multi-exec", [
      ["SET", key, "0", "EX", String(windowSec), "NX"],
      ["INCR", key],
      ["TTL", key],
    ]);
    // Belt and braces: a key with no expiry would block this bucket forever.
    if (Number(ttl) < 0) await redisBatch("/pipeline", [["EXPIRE", key, String(windowSec)]]);
    if (Number(count) > limit) return { ok: false, retryAfter: Math.max(1, Number(ttl) > 0 ? Number(ttl) : windowSec) };
    return { ok: true, retryAfter: 0 };
  } catch {
    return failOpen ? { ok: true, retryAfter: 0 } : { ok: false, retryAfter: 60, error: true };
  }
}

export function tooMany(res, rl, message = "Too many requests. Please wait a bit and try again.") {
  res.setHeader("Retry-After", String(rl.retryAfter || 60));
  res.status(rl.error ? 503 : 429).json({ error: rl.error ? "Service temporarily unavailable." : message });
}

// ---- Media links: only files in our own Vercel Blob store ----

// Public hostname of the store behind BLOB_READ_WRITE_TOKEN, derived the
// same way @vercel/blob does: the token is "vercel_blob_rw_<storeId>_<secret>"
// and public URLs are https://<storeId>.public.blob.vercel-storage.com/...
// Empty when the token is missing or malformed (callers then allow no media).
export function blobStoreHost() {
  const token = String(process.env.BLOB_READ_WRITE_TOKEN || "");
  if (!token.startsWith("vercel_blob_rw_")) return "";
  const [, , , storeId = ""] = token.split("_");
  if (!/^[a-z0-9-]+$/i.test(storeId)) return "";
  return `${storeId}.public.blob.vercel-storage.com`.toLowerCase();
}

// Returns the URL if it is an https file under /testimonials/ in our own
// Blob store, otherwise "". Fails closed.
export function ownBlobUrl(u) {
  const host = blobStoreHost();
  if (!host) return "";
  try {
    const url = new URL(String(u || ""));
    if (url.protocol !== "https:" || url.username || url.password || url.port) return "";
    if (url.hostname !== host || !url.pathname.startsWith("/testimonials/")) return "";
    return url.href;
  } catch {
    return "";
  }
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
