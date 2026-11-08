// Admin: issue a Notepad licence by hand (club giveaways, existing customers,
// replacements). Same admin session as /api/reviews.
//
//   GET  /api/license          -> form + recent licences
//   POST /api/license  app, tier, note   -> shows the ready-to-send app link
//
// Env: REVIEWS_ADMIN_KEY, LICENSE_PRIVATE_KEY, KV_REST_API_URL / KV_REST_API_TOKEN.

import { APPS, appLink } from "./_lib/apps.js";
import { signLicense } from "./_lib/license.js";
import { isAdmin, redisPipeline, sameOrigin } from "./_lib/security.js";

const esc = (s) =>
  String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function parseBody(req) {
  let b = req.body;
  if (typeof b === "string") {
    try { b = JSON.parse(b); } catch { b = Object.fromEntries(new URLSearchParams(b)); }
  }
  return b && typeof b === "object" ? b : {};
}

async function recent() {
  try {
    const [rows] = await redisPipeline([["LRANGE", "site:licenses", "-25", "-1"]]);
    return (rows || []).map((r) => { try { return JSON.parse(r); } catch { return null; } }).filter(Boolean).reverse();
  } catch {
    return [];
  }
}

async function render(res, issued) {
  const rows = await recent();
  const opts = Object.entries(APPS).map(([k, v]) => `<option value="${k}">${esc(v.name)}</option>`).join("");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.status(200).send(`<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Issue licence</title>
<style>body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f7f7fb;color:#1a1a2e;padding:16px}
.card{background:#fff;border:1px solid #e2e2ec;border-radius:12px;padding:20px;max-width:640px;margin:0 auto 16px}
label{display:block;font-weight:600;margin:10px 0 4px}select,input,textarea,button{font:inherit;width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #c9c9d6}
button{background:#ff6b35;color:#fff;border:0;font-weight:600;margin-top:14px;cursor:pointer}textarea{height:96px;font-family:ui-monospace,monospace;font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px;border-bottom:1px solid #eee;text-align:left}</style>
${issued ? `<div class="card"><h2>Licence ready: ${esc(APPS[issued.app].name)} (${esc(issued.tier)})</h2>
<p>Send this link. Opening it once unlocks the app on that device, offline after that.</p>
<textarea readonly onclick="this.select()">${esc(issued.link)}</textarea></div>` : ""}
<form class="card" method="post" action="/api/license"><h2>Issue a licence</h2>
<label>Notepad</label><select name="app" required>${opts}</select>
<label>Tier</label><select name="tier"><option value="comp">Comp (club giveaway)</option><option value="individual">Individual (paid)</option><option value="club">Club (paid)</option></select>
<label>Note (who it's for)</label><input name="note" maxlength="80" placeholder="e.g. Riverside Hawks U14 / jane@club.ca">
<button type="submit">Create link</button></form>
<div class="card"><h2>Recent licences</h2><table><tr><th>When</th><th>App</th><th>Tier</th><th>Source</th><th>Ref / email</th></tr>
${rows.map((r) => `<tr><td>${esc((r.at || "").slice(0, 16).replace("T", " "))}</td><td>${esc(r.app)}</td><td>${esc(r.tier)}</td><td>${esc(r.source)}</td><td>${esc(r.email || r.note || r.ref)}</td></tr>`).join("")}
</table></div>`);
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (!isAdmin(req, process.env.REVIEWS_ADMIN_KEY)) {
    res.redirect(303, "/api/admin?next=/api/license");
    return;
  }
  if (req.method === "GET") {
    await render(res, null);
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
  const b = parseBody(req);
  const app = String(b.app || "");
  const tier = ["comp", "individual", "club"].includes(b.tier) ? b.tier : "comp";
  const note = String(b.note || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 80);
  if (!APPS[app]) {
    res.status(400).json({ error: "Unknown app." });
    return;
  }
  try {
    const { token, payload } = signLicense({ app, tier, ref: note || "admin" });
    await redisPipeline([[
      "RPUSH", "site:licenses",
      JSON.stringify({ at: new Date().toISOString(), source: "admin", app, tier, lid: payload.lid, note }),
    ]]);
    await render(res, { app, tier, link: appLink(app, token) });
  } catch (e) {
    res.status(501).json({ error: e.message === "LICENSE_NOT_CONFIGURED" ? "LICENSE_PRIVATE_KEY is not set." : "Could not issue licence." });
  }
}
