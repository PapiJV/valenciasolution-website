// Stores a coach review submitted from the site's feedback form.
// Upstash Redis (same store as the notepad apps). Reviews are NOT auto-
// published — they wait in site:reviews until approved on the admin page
// (/api/reviews), then /api/testimonials serves them to the wall.
//
// Env (either naming): KV_REST_API_URL / KV_REST_API_TOKEN (the Vercel
// Upstash integration) or UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN.
// If neither is set the route answers 501 and the form falls back to email.

import crypto from "node:crypto";
import { APPROVED_KEY, MAX_REVIEWS, REVIEWS_KEY, STATUS_KEY, hashOf, parseRows, reviewId } from "./_lib/reviews.js";
import { ReviewSchema, parse } from "./_lib/schemas.js";
import { rateLimit, redisPipeline, sameOrigin, tooMany } from "./_lib/security.js";

// Extra entries read before a trim, in case other submissions land between
// our RPUSH and LTRIM (the trim then removes a few more than we counted).
const TRIM_MARGIN = 25;

// Before trimming the list, copy any approved entry that is about to fall off
// into site:reviews:approved so spam can't push it off the wall. Throws on any
// storage error; the caller then skips the trim.
async function keepApproved(len) {
  const doomed = Math.max(0, len - MAX_REVIEWS) + TRIM_MARGIN;
  const [rows, statusFlat] = await redisPipeline([
    ["LRANGE", REVIEWS_KEY, "0", String(doomed - 1)],
    ["HGETALL", STATUS_KEY],
  ]);
  const status = hashOf(statusFlat);
  const keep = [];
  for (const r of parseRows(rows)) {
    const id = reviewId(r);
    if (id && status[id] === "approved") keep.push(id, JSON.stringify(r));
  }
  if (keep.length) await redisPipeline([["HSET", APPROVED_KEY, ...keep]]);
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

  // 3 per day per email (hashed in the key), whatever IP they come from.
  const perEmail = await rateLimit(req, { bucket: "review-email", limit: 3, windowSec: 86400, identity: email, failOpen: true });
  if (!perEmail.ok) {
    tooMany(res, perEmail, "You've already sent a few reviews today. Please try again tomorrow.");
    return;
  }

  try {
    const id = `r_${Date.now().toString(36)}_${crypto.randomBytes(4).toString("hex")}`;
    const entry = { id, name, role, club, product, headline, message, email, media, rating, consent, access, at: new Date().toISOString() };
    const [len] = await redisPipeline([["RPUSH", REVIEWS_KEY, JSON.stringify(entry)]]);
    if (Number(len) > MAX_REVIEWS) {
      try {
        await keepApproved(Number(len));
        await redisPipeline([["LTRIM", REVIEWS_KEY, String(-MAX_REVIEWS), "-1"]]);
      } catch {
        /* review is saved; skip the trim rather than risk losing approved ones */
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
