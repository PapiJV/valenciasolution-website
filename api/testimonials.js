// Public feed for the testimonial wall (index/fr/es #reviewsGrid).
//
//   GET /api/testimonials -> { testimonials: [...] }  newest first
//
// Only entries approved on the admin page (/api/reviews) AND submitted with
// "OK to publish" ticked are returned. Emails are never included.
// Approval state lives in the hash site:reviews:status (id -> "approved" |
// "hidden"); entries saved before ids existed use their `at` timestamp.
// site:reviews:access (id -> "free") is an admin override that forces the
// "Free access" label on the wall.
//
// site:reviews:approved (id -> entry JSON) keeps approved entries after the
// list has been trimmed; the wall reads the union of both.
//
// Env: KV_REST_API_URL / KV_REST_API_TOKEN (or UPSTASH_REDIS_REST_*).

import { ACCESS_KEY, APPROVED_KEY, REVIEWS_KEY, STATUS_KEY, hashOf, mergeReviews, reviewId } from "./_lib/reviews.js";
import { isOwnBlobUrl } from "./_lib/security.js";

const MAX_ON_WALL = 60;

// Only media from our own Blob store is passed through to the wall.
const safeMedia = (u) => (isOwnBlobUrl(u) ? new URL(u).href : "");

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
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }

  let all, status, accessOverride;
  try {
    const [list, hash, accessHash, approvedHash] = await redisPipeline([
      ["LRANGE", REVIEWS_KEY, "0", "-1"],
      ["HGETALL", STATUS_KEY],
      ["HGETALL", ACCESS_KEY],
      ["HGETALL", APPROVED_KEY],
    ]);
    for (const r of [list, hash, accessHash, approvedHash]) if (!r || r.error) throw new Error("REDIS_CMD");
    all = mergeReviews(list.result || [], approvedHash.result || []); // newest first, deduped
    status = hashOf(hash.result);
    accessOverride = hashOf(accessHash.result);
  } catch (e) {
    res.setHeader("Cache-Control", "no-store");
    res.status(e.message === "NOT_CONFIGURED" ? 501 : 502).json({ testimonials: [] });
    return;
  }

  const testimonials = all
    .filter((r) => r.consent === true && status[reviewId(r)] === "approved")
    .slice(0, MAX_ON_WALL)
    .map((r) => ({
      rating: Math.max(1, Math.min(5, Number(r.rating) || 0)),
      product: r.product || "",
      access: r.access === "free" || accessOverride[reviewId(r)] === "free" ? "free" : r.access === "purchased" ? "purchased" : "",
      name: r.name || "",
      role: r.role || "",
      club: r.club || "",
      headline: r.headline || "",
      message: r.message || "",
      media: safeMedia(r.media),
      at: r.at || "",
    }));

  // Short edge cache: an approval shows on the wall within about a minute.
  res.setHeader("Cache-Control", "public, s-maxage=60, stale-while-revalidate=300");
  res.status(200).json({ testimonials });
}
