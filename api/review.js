// Stores a coach review submitted from the site's feedback form.
// Upstash Redis (same store as the notepad apps). Reviews are NOT auto-
// published — they land in a list for the team to read and hand-pick from.
//
// Env (either naming): KV_REST_API_URL / KV_REST_API_TOKEN (the Vercel
// Upstash integration) or UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN.
// If neither is set the route answers 501 and the form falls back to email.

const MAX_REVIEWS = 500;

function creds() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error("NOT_CONFIGURED");
  return { url, token };
}

async function redisPipeline(commands) {
  const { url, token } = creds();
  const res = await fetch(`${url}/pipeline`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(commands),
  });
  if (!res.ok) throw new Error(`REDIS_${res.status}`);
  return res.json();
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = null;
    }
  }
  const name = String((body && body.name) || "").trim().slice(0, 80);
  const role = String((body && body.role) || "").trim().slice(0, 80);
  const message = String((body && body.message) || "").trim().slice(0, 800);
  const email = String((body && body.email) || "").trim().slice(0, 120);
  const rating = Math.max(1, Math.min(5, parseInt((body && body.rating), 10) || 0));

  if (!name || message.length < 10 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.status(400).json({ error: "Missing or invalid fields." });
    return;
  }

  try {
    const entry = { name, role, message, email, rating, at: new Date().toISOString() };
    await redisPipeline([
      ["RPUSH", "site:reviews", JSON.stringify(entry)],
      ["LTRIM", "site:reviews", String(-MAX_REVIEWS), "-1"],
    ]);
    res.status(200).json({ ok: true });
  } catch (e) {
    if (e.message === "NOT_CONFIGURED") {
      res.status(501).json({ error: "Review capture isn't configured." });
      return;
    }
    res.status(502).json({ error: "Storage request failed." });
  }
}
