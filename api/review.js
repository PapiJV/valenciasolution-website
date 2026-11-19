// Stores a coach review submitted from the site's feedback form.
// Upstash Redis (same store as the notepad apps). Reviews are NOT auto-
// published — they wait in site:reviews until approved on the admin page
// (/api/reviews), then /api/testimonials serves them to the wall.
//
// Env (either naming): KV_REST_API_URL / KV_REST_API_TOKEN (the Vercel
// Upstash integration) or UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN.
// If neither is set the route answers 501 and the form falls back to email.

import crypto from "node:crypto";
import { ReviewSchema, parse } from "./_lib/schemas.js";
import { rateLimit, sameOrigin, tooMany } from "./_lib/security.js";

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

  if (!sameOrigin(req)) {
    res.status(403).json({ error: "Forbidden." });
    return;
  }
  // 5 per hour per visitor: plenty for a coach, stops bots flooding the list.
  const rl = await rateLimit(req, { bucket: "review", limit: 5, windowSec: 3600, failOpen: true });
  if (!rl.ok) {
    tooMany(res, rl);
    return;
  }

  const p = parse(ReviewSchema, req);
  if (!p.ok) {
    res.status(400).json({ error: "Missing or invalid fields.", fields: p.issues });
    return;
  }
  const { name, role, club, product, headline, consent, access, message, email, media, rating } = p.data;

  try {
    const id = `r_${Date.now().toString(36)}_${crypto.randomBytes(4).toString("hex")}`;
    const entry = { id, name, role, club, product, headline, message, email, media, rating, consent, access, at: new Date().toISOString() };
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
