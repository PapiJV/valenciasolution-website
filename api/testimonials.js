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
// Env: KV_REST_API_URL / KV_REST_API_TOKEN (or UPSTASH_REDIS_REST_*).

const MAX_ON_WALL = 60;

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

// Only media we host ourselves (Vercel Blob) is passed through to the wall.
function safeMedia(u) {
  try {
    const url = new URL(String(u || ""));
    return url.protocol === "https:" && url.hostname.endsWith(".public.blob.vercel-storage.com") ? url.href : "";
  } catch {
    return "";
  }
}

export default async function handler(req, res) {
  // Crawlable (robots.txt allows it) so Google can render /testimonials, but the JSON itself is never indexed.
  res.setHeader("X-Robots-Tag", "noindex");
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }

  let rows, status, accessOverride;
  try {
    const [list, hash, accessHash] = await redisPipeline([
      ["LRANGE", "site:reviews", "0", "-1"],
      ["HGETALL", "site:reviews:status"],
      ["HGETALL", "site:reviews:access"],
    ]);
    rows = list.result || [];
    status = {};
    const flat = hash.result || [];
    for (let i = 0; i + 1 < flat.length; i += 2) status[flat[i]] = flat[i + 1];
    accessOverride = {};
    const aflat = (accessHash && accessHash.result) || [];
    for (let i = 0; i + 1 < aflat.length; i += 2) accessOverride[aflat[i]] = aflat[i + 1];
  } catch (e) {
    res.setHeader("Cache-Control", "no-store");
    res.status(e.message === "NOT_CONFIGURED" ? 501 : 502).json({ testimonials: [] });
    return;
  }

  const testimonials = rows
    .map((s) => {
      try {
        return JSON.parse(s);
      } catch {
        return null;
      }
    })
    .filter((r) => r && r.consent === true && status[r.id || r.at] === "approved")
    .reverse()
    .slice(0, MAX_ON_WALL)
    .map((r) => ({
      rating: Math.max(1, Math.min(5, Number(r.rating) || 0)),
      product: r.product || "",
      access: r.access === "free" || accessOverride[r.id || r.at] === "free" ? "free" : r.access === "purchased" ? "purchased" : "",
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
