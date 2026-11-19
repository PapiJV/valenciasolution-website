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

export async function redisPipeline(commands) {
  const { url, token } = redisCreds();
  const res = await fetch(`${url}/pipeline`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(commands),
  });
  if (!res.ok) throw new Error(`REDIS_${res.status}`);
  return (await res.json()).map((r) => {
    if (r && r.error) throw new Error(`REDIS_CMD: ${r.error}`);
    return r ? r.result : null;
  });
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

// ---- Admin session (signed cookie + server-side revocation) ----
//
// Cookie value: "<exp>.<sid>.<hmac(exp, sid)>". A fresh random sid is minted
// on every sign-in (session rotation). Sign-out stores the sid in Redis until
// it would have expired, so a copied cookie stops working at once.
// Changing REVIEWS_ADMIN_KEY still logs every session out.

export const ADMIN_COOKIE = "vs_admin";
const SESSION_SEC = 12 * 60 * 60;
const SID_RE = /^[A-Za-z0-9_-]{22}$/;

const sign = (adminKey, exp, sid) =>
  crypto.createHmac("sha256", adminKey).update(`admin:${exp}:${sid}`).digest("base64url");

const cookieAttrs = "Path=/api; HttpOnly; Secure; SameSite=Strict";

export function adminCookie(adminKey) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_SEC;
  const sid = crypto.randomBytes(16).toString("base64url");
  return `${ADMIN_COOKIE}=${exp}.${sid}.${sign(adminKey, exp, sid)}; ${cookieAttrs}; Max-Age=${SESSION_SEC}`;
}

export const clearAdminCookie = () => `${ADMIN_COOKIE}=; ${cookieAttrs}; Max-Age=0`;

function readCookie(req, name) {
  const raw = String((req.headers && req.headers.cookie) || "");
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return "";
}

// Returns { sid, exp } for a correctly signed, unexpired cookie, else null.
function sessionOf(req, adminKey) {
  const [exp, sid, mac, extra] = readCookie(req, ADMIN_COOKIE).split(".");
  if (extra !== undefined || !exp || !sid || !mac) return null;
  if (!/^\d{1,12}$/.test(exp) || !SID_RE.test(sid) || Number(exp) < Date.now() / 1000) return null;
  return safeEqual(mac, sign(adminKey, exp, sid)) ? { sid, exp: Number(exp) } : null;
}

const revokedKey = (sid) => `site:admin:revoked:${sid}`;

// Server-side sign-out: the sid is refused until it would have expired.
export async function revokeAdminSession(req, adminKey) {
  const s = adminKey ? sessionOf(req, adminKey) : null;
  if (!s) return;
  const ttl = Math.max(1, s.exp - Math.floor(Date.now() / 1000));
  await redisPipeline([["SET", revokedKey(s.sid), "1", "EX", String(ttl)]]);
}

// ---- Failed sign-in lockout ----
// 5 wrong keys from one visitor locks that visitor out for 15 minutes.
// 50 wrong keys site-wide locks the admin account for 15 minutes (a botnet
// rotating IPs still can't guess). Applies to the form and the Bearer header.
export const LOCKOUT = { perIp: 5, global: 50, windowSec: 15 * 60 };
const lockKeys = (req) => [`site:lock:admin:${ipTag(req)}`, "site:lock:admin:all"];

// { locked, retryAfter }. Fails closed: no Redis, no admin sign-in.
export async function loginLocked(req) {
  const [ipKey, allKey] = lockKeys(req);
  try {
    const [ip, all, ipTtl, allTtl] = await redisPipeline([["GET", ipKey], ["GET", allKey], ["TTL", ipKey], ["TTL", allKey]]);
    if (Number(ip) >= LOCKOUT.perIp) return { locked: true, retryAfter: Math.max(1, Number(ipTtl) || LOCKOUT.windowSec) };
    if (Number(all) >= LOCKOUT.global) return { locked: true, retryAfter: Math.max(1, Number(allTtl) || LOCKOUT.windowSec) };
    return { locked: false, retryAfter: 0 };
  } catch {
    return { locked: true, retryAfter: 60, error: true };
  }
}

export async function recordLoginFailure(req) {
  const w = String(LOCKOUT.windowSec);
  const cmds = [];
  for (const k of lockKeys(req)) cmds.push(["SET", k, "0", "EX", w, "NX"], ["INCR", k]);
  try {
    await redisPipeline(cmds);
  } catch {
    /* loginLocked() already fails closed when Redis is down */
  }
}

export async function clearLoginFailures(req) {
  try {
    await redisPipeline([["DEL", lockKeys(req)[0]]]);
  } catch {
    /* best effort */
  }
}

/**
 * True when the request carries a valid, unrevoked admin session cookie, or
 * "Authorization: Bearer <REVIEWS_ADMIN_KEY>" (for scripts). Wrong Bearer keys
 * count toward the lockout; a locked-out visitor is refused even with the
 * right key. Fails closed when Redis is unreachable.
 */
export async function isAdmin(req, adminKey) {
  if (!adminKey) return false;
  const auth = String((req.headers && req.headers.authorization) || "");
  if (auth.startsWith("Bearer ")) {
    if ((await loginLocked(req)).locked) return false;
    if (safeEqual(auth.slice(7).trim(), adminKey.trim())) return true;
    await recordLoginFailure(req);
    return false;
  }
  const s = sessionOf(req, adminKey);
  if (!s) return false;
  try {
    const [revoked] = await redisPipeline([["EXISTS", revokedKey(s.sid)]]);
    return Number(revoked) === 0;
  } catch {
    return false;
  }
}

// ---- Admin HTML pages ----
// Strict per-response CSP with a script nonce. Browsers enforce every CSP
// header they receive, so this tightens (never loosens) vercel.json's policy.
export function adminHtml(res) {
  const nonce = crypto.randomBytes(16).toString("base64");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'none'",
      `script-src 'nonce-${nonce}'`,
      "style-src 'unsafe-inline'",
      "img-src 'self' data: https://*.public.blob.vercel-storage.com",
      "media-src https://*.public.blob.vercel-storage.com",
      "connect-src 'self'",
      "form-action 'self'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
    ].join("; "),
  );
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  return nonce;
}

// Same escaping everywhere HTML is built on the server.
export const esc = (s) =>
  String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
