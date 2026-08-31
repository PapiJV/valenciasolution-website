// Private admin view of collected reviews (from /api/review -> Upstash list
// site:reviews). Entries contain reviewer emails, so this is gated by a key.
//
//   GET /api/reviews?key=YOUR_KEY            -> readable HTML table
//   GET /api/reviews?key=YOUR_KEY&format=json -> { count, reviews }
//
// Env: REVIEWS_ADMIN_KEY  (set any random string in the Vercel project).
//      KV_REST_API_URL / KV_REST_API_TOKEN  (or UPSTASH_REDIS_REST_*).
// Fails closed: if REVIEWS_ADMIN_KEY is unset the route is unavailable.

function redisCreds() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error("NOT_CONFIGURED");
  return { url, token };
}

async function redis(command) {
  const { url, token } = redisCreds();
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

export default async function handler(req, res) {
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
    res.setHeader("Cache-Control", "no-store");
    res.status(401).json({ error: "Unauthorized." });
    return;
  }

  let rows;
  try {
    rows = (await redis(["LRANGE", "site:reviews", "0", "-1"])) || [];
  } catch (e) {
    if (e.message === "NOT_CONFIGURED") {
      res.status(501).json({ error: "Upstash store isn't connected to this project yet." });
      return;
    }
    res.status(502).json({ error: "Storage request failed." });
    return;
  }

  const reviews = rows
    .map((s) => {
      try {
        return JSON.parse(s);
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .reverse(); // newest first

  res.setHeader("Cache-Control", "no-store");

  if (String(req.query.format || "") === "json") {
    res.status(200).json({ count: reviews.length, reviews });
    return;
  }

  const trophies = (n) => "🏆".repeat(Math.max(0, Math.min(5, Number(n) || 0)));
  const trs = reviews
    .map(
      (r) => `<tr>
    <td>${esc((r.at || "").slice(0, 16).replace("T", " "))}</td>
    <td>${trophies(r.rating)}</td>
    <td><b>${esc(r.name)}</b>${r.role ? `<br><span class="muted">${esc(r.role)}</span>` : ""}</td>
    <td>${esc(r.message)}</td>
    <td><a href="mailto:${esc(r.email)}">${esc(r.email)}</a></td>
  </tr>`,
    )
    .join("\n");

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(`<!doctype html><meta charset="utf-8">
<title>Reviews (${reviews.length})</title>
<style>
  body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#1a1a2e;background:#f7f7fb}
  h1{font-size:18px;margin:0 0 4px}
  .muted{color:#777;font-size:12px}
  table{border-collapse:collapse;width:100%;margin-top:16px;background:#fff}
  th,td{border:1px solid #e2e2ec;padding:8px 10px;text-align:left;vertical-align:top}
  th{background:#f0f0f6;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  td:nth-child(4){min-width:260px}
</style>
<h1>Collected reviews — ${reviews.length}</h1>
<div class="muted">Newest first. Not published anywhere — paste the good ones into index.html by hand.</div>
${reviews.length ? `<table>
  <tr><th>When</th><th>Rating</th><th>Coach</th><th>Review</th><th>Email</th></tr>
  ${trs}
</table>` : "<p>No reviews collected yet.</p>"}`);
}
