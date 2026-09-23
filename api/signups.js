// Private admin view of free-offer sign-ups (from /api/register).
//   GET /api/signups?key=KEY               -> HTML table
//   GET /api/signups?key=KEY&format=csv    -> CSV download
//   GET /api/signups?key=KEY&format=json   -> JSON
// Gated by REVIEWS_ADMIN_KEY (same key as /api/reviews). Fails closed.

function creds() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error("NOT_CONFIGURED");
  return { url, token };
}

async function redis(command) {
  const { url, token } = creds();
  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(command),
  });
  if (!res.ok) throw new Error(`REDIS_${res.status}`);
  return (await res.json()).result;
}

const esc = (s) =>
  String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// CSV cell: quote, double quotes, and neutralise spreadsheet formulas.
const csvCell = (v) => {
  let s = String(v == null ? "" : v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replace(/"/g, '""')}"`;
};

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }
  const adminKey = process.env.REVIEWS_ADMIN_KEY;
  if (!adminKey) {
    res.status(501).json({ error: "REVIEWS_ADMIN_KEY is not set." });
    return;
  }
  if (String(req.query.key || "") !== adminKey) {
    res.status(401).json({ error: "Unauthorized." });
    return;
  }

  let rows;
  try {
    rows = (await redis(["LRANGE", "site:signups", "0", "-1"])) || [];
  } catch (e) {
    if (e.message === "NOT_CONFIGURED") {
      res.status(501).json({ error: "Upstash store isn't connected to this project yet." });
      return;
    }
    res.status(502).json({ error: "Storage request failed." });
    return;
  }

  const list = rows
    .map((s) => { try { return JSON.parse(s); } catch { return null; } })
    .filter(Boolean)
    .reverse();

  const format = String(req.query.format || "");
  if (format === "json") {
    res.status(200).json({ count: list.length, signups: list });
    return;
  }

  const cols = ["at", "spotNumber", "sport", "name", "email", "role", "club", "city", "marketingOptIn"];
  if (format === "csv") {
    const csv = [cols.join(",")]
      .concat(list.map((r) => cols.map((c) => csvCell(r[c])).join(",")))
      .join("\r\n");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="free-notepad-signups.csv"');
    res.status(200).send("﻿" + csv);
    return;
  }

  const bySport = list.reduce((m, r) => ((m[r.sport] = (m[r.sport] || 0) + 1), m), {});
  const optIns = list.filter((r) => r.marketingOptIn).length;
  const trs = list.map((r) => `<tr>
    <td>${esc((r.at || "").slice(0, 16).replace("T", " "))}</td>
    <td>#${esc(r.spotNumber)}</td>
    <td>${esc(r.sport)}</td>
    <td><b>${esc(r.name)}</b>${r.role ? `<br><span class="muted">${esc(r.role)}</span>` : ""}</td>
    <td>${esc(r.club)}${r.city ? `<br><span class="muted">${esc(r.city)}</span>` : ""}</td>
    <td><a href="mailto:${esc(r.email)}">${esc(r.email)}</a></td>
    <td>${r.marketingOptIn ? "✅ Yes" : "No"}</td>
  </tr>`).join("\n");
  const keyQ = encodeURIComponent(String(req.query.key));

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(`<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex">
<title>Free offer sign-ups (${list.length})</title>
<style>
  body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#1a1a2e;background:#f7f7fb}
  h1{font-size:18px;margin:0 0 4px} .muted{color:#777;font-size:12px}
  .stats{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}
  .stat{background:#fff;border:1px solid #e2e2ec;border-radius:10px;padding:10px 14px}
  .stat b{font-size:18px;display:block}
  table{border-collapse:collapse;width:100%;background:#fff}
  th,td{border:1px solid #e2e2ec;padding:8px 10px;text-align:left;vertical-align:top}
  th{background:#f0f0f6;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  a.btn{display:inline-block;background:#ff6b35;color:#fff;padding:8px 14px;border-radius:8px;text-decoration:none;font-weight:600}
</style>
<h1>Free Notepad sign-ups — ${list.length} / 100</h1>
<div class="muted">Newest first. Only email people marked "Yes" with marketing (CASL).</div>
<div class="stats">
  ${["basketball", "volleyball", "football", "lacrosse"].map((s) => `<div class="stat"><b>${bySport[s] || 0}</b>${s}</div>`).join("")}
  <div class="stat"><b>${optIns}</b>email opt-ins</div>
</div>
<p><a class="btn" href="/api/signups?key=${keyQ}&format=csv">Download CSV</a></p>
${list.length ? `<table>
  <tr><th>When</th><th>Spot</th><th>Sport</th><th>Coach</th><th>Club</th><th>Email</th><th>Email opt-in</th></tr>
  ${trs}
</table>` : "<p>No sign-ups yet.</p>"}`);
}
