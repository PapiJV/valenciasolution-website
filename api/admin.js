// Admin sign-in for /api/reviews, /api/signups, /api/license and /api/qr.
//
//   GET  /api/admin?next=/api/reviews   -> sign-in form
//   POST /api/admin  key=...&next=...    -> sets a 12-hour HttpOnly cookie, redirects
//   POST /api/admin  logout=1            -> revokes the session server-side, clears the cookie
//
// The key is typed into a form (POST body), never put in the URL, so it
// doesn't end up in browser history, server logs or Referer headers.
// 5 wrong keys locks that visitor out for 15 minutes (see LOCKOUT).
// Env: REVIEWS_ADMIN_KEY. Fails closed if unset.

import { AdminLoginSchema, parse } from "./_lib/schemas.js";
import {
  adminCookie, adminHtml, clearAdminCookie, clearLoginFailures, esc, loginLocked,
  rateLimit, recordLoginFailure, revokeAdminSession, safeEqual, sameOrigin, tooMany,
} from "./_lib/security.js";

const NEXT_OK = new Set(["/api/reviews", "/api/signups", "/api/license", "/api/qr"]);
const nextOf = (v) => (NEXT_OK.has(String(v || "")) ? String(v) : "/api/reviews");

function form(res, next, status = 200, msg = "") {
  adminHtml(res);
  res.setHeader("Referrer-Policy", "same-origin"); // keeps Origin on the form post for sameOrigin()
  res.status(status).send(`<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin sign-in</title>
<style>
  body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f7fb;color:#1a1a2e}
  form{background:#fff;border:1px solid #e2e2ec;border-radius:12px;padding:24px;width:min(340px,calc(100vw - 32px));box-sizing:border-box}
  h1{font-size:18px;margin:0 0 14px} input,button{font:inherit;width:100%;box-sizing:border-box;padding:10px;border-radius:8px}
  input{border:1px solid #c9c9d6;margin-bottom:12px} button{border:0;background:#ff6b35;color:#fff;font-weight:600;cursor:pointer}
  .err{color:#c0392b;font-size:13px;margin:0 0 10px}
</style>
<form method="post" action="/api/admin">
  <h1>Admin sign-in</h1>
  ${msg ? `<p class="err">${esc(msg)}</p>` : ""}
  <input type="password" name="key" placeholder="Admin key" autocomplete="current-password" required autofocus>
  <input type="hidden" name="next" value="${esc(next)}">
  <button type="submit">Sign in</button>
</form>`);
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const adminKey = process.env.REVIEWS_ADMIN_KEY;
  if (!adminKey) {
    res.status(503).json({ error: "Admin is unavailable." });
    return;
  }

  if (req.method === "GET") {
    form(res, nextOf(req.query && req.query.next));
    return;
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }
  if (!sameOrigin(req)) {
    res.status(403).json({ error: "Forbidden." });
    return;
  }

  const p = parse(AdminLoginSchema, req);
  if (!p.ok) {
    form(res, "/api/reviews", 400, "Invalid request.");
    return;
  }
  const next = nextOf(p.data.next);

  if (p.data.logout) {
    try {
      await revokeAdminSession(req, adminKey);
    } catch {
      /* cookie is still cleared below */
    }
    res.setHeader("Set-Cookie", clearAdminCookie());
    res.redirect(303, `/api/admin?next=${encodeURIComponent(next)}`);
    return;
  }

  // Flood guard on top of the failure lockout.
  const rl = await rateLimit(req, { bucket: "admin-login", limit: 20, windowSec: 15 * 60 });
  if (!rl.ok) {
    tooMany(res, rl, "Too many sign-in attempts. Try again in 15 minutes.");
    return;
  }
  const lock = await loginLocked(req);
  if (lock.locked) {
    res.setHeader("Retry-After", String(lock.retryAfter));
    form(res, next, lock.error ? 503 : 429, lock.error ? "Sign-in is temporarily unavailable." : "Too many wrong keys. Sign-in is locked for 15 minutes.");
    return;
  }

  if (!safeEqual(p.data.key.trim(), adminKey.trim())) {
    await recordLoginFailure(req);
    form(res, next, 401, "Wrong key.");
    return;
  }
  await clearLoginFailures(req);
  res.setHeader("Set-Cookie", adminCookie(adminKey));
  res.redirect(303, next);
}
