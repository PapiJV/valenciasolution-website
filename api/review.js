// Stores a coach review submitted from the site's feedback form.
// Upstash Redis (same store as the notepad apps). Reviews are NOT auto-
// published — they wait in site:reviews until approved on the admin page
// (/api/reviews), then /api/testimonials serves them to the wall.
//
// site:reviews keeps only the newest MAX_REVIEWS. Approved entries are also
// kept in the hash site:reviews:approved (id -> entry JSON), so spam can't
// push them off the wall. Entries approved before that hash existed are
// copied into it just before they would be trimmed.
//
// Env (either naming): KV_REST_API_URL / KV_REST_API_TOKEN (the Vercel
// Upstash integration) or UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN.
// If neither is set the route answers 501 and the form falls back to email.

import { ownBlobUrl, rateLimit, sameOrigin, tooMany } from "./_lib/security.js";
import { APPROVED_KEY, LIST_KEY, STATUS_KEY } from "./_lib/reviews.js";

const MAX_REVIEWS = 500;
// Also check a few entries past the trim point, in case another submit
// lands between our check and LTRIM.
const TRIM_MARGIN = 50;

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
  const out = await res.json();
  return out.map((r) => {
    if (!r || r.error) throw new Error(`REDIS_CMD: ${(r && r.error) || "empty"}`);
    return r.result;
  });
}

// Before trimming, copy approved entries that are about to fall off the
// list into the approved hash.
async function keepApproved(len) {
  const end = len - MAX_REVIEWS - 1 + TRIM_MARGIN;
  if (end < 0) return;
  const [rows] = await redisPipeline([["LRANGE", LIST_KEY, "0", String(end)]]);
  const entries = (rows || [])
    .map((s) => {
      try {
        const r = JSON.parse(s);
        return r && (r.id || r.at) ? { key: r.id || r.at, raw: s } : null;
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  if (!entries.length) return;
  const [states] = await redisPipeline([["HMGET", STATUS_KEY, ...entries.map((e) => e.key)]]);
  const keep = entries.filter((e, i) => (states || [])[i] === "approved");
  if (keep.length) await redisPipeline([["HSET", APPROVED_KEY, ...keep.flatMap((e) => [e.key, e.raw])]]);
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
  const club = String((body && body.club) || "").trim().slice(0, 100);
  const product = String((body && body.product) || "").trim().slice(0, 40);
  const headline = String((body && body.headline) || "").trim().slice(0, 90);
  const consent = Boolean(body && body.consent === true);
  const access = ["purchased", "free"].includes(body && body.access) ? body.access : "";
  const message = String((body && body.message) || "").trim().slice(0, 800);
  const email = String((body && body.email) || "").trim().slice(0, 120);
  // Only a file in our own Blob store (from /api/upload); anything else is dropped.
  const media = ownBlobUrl(String((body && body.media) || "").trim().slice(0, 500));
  const rating = Math.max(1, Math.min(5, parseInt((body && body.rating), 10) || 0));

  if (!name || message.length < 10 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.status(400).json({ error: "Missing or invalid fields." });
    return;
  }

  // 3 per day per email address (keyed by a hash, never the raw email).
  const perEmail = await rateLimit(req, {
    bucket: "review-email",
    limit: 3,
    windowSec: 86400,
    identity: `email:${email.toLowerCase()}`,
    failOpen: true,
  });
  if (!perEmail.ok) {
    tooMany(res, perEmail);
    return;
  }

  try {
    const id = `r_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    const entry = { id, name, role, club, product, headline, message, email, media, rating, consent, access, at: new Date().toISOString() };
    const [len] = await redisPipeline([["RPUSH", LIST_KEY, JSON.stringify(entry)]]);
    if (Number(len) > MAX_REVIEWS) {
      try {
        await keepApproved(Number(len));
        await redisPipeline([["LTRIM", LIST_KEY, String(-MAX_REVIEWS), "-1"]]);
      } catch {
        // Never trim unless approved entries were saved first. The review
        // itself is stored; the next submit retries the trim.
      }
    }
    res.status(200).json({ ok: true });
  } catch (e) {
    if (e.message === "NOT_CONFIGURED") {
      res.status(501).json({ error: "Review capture isn't configured." });
      return;
    }
    res.status(502).json({ error: "Storage request failed." });
  }
}
