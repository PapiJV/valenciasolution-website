// Review storage shared by /api/review, /api/reviews and /api/testimonials.
//
//   site:reviews           LIST  JSON entries, oldest first, capped at MAX_REVIEWS
//   site:reviews:status    HASH  id -> "approved" | "hidden"
//   site:reviews:access    HASH  id -> "free" (admin override)
//   site:reviews:approved  HASH  id -> full entry JSON for approved reviews
//
// The list is trimmed to the newest MAX_REVIEWS, so spam could otherwise push
// approved testimonials out of it. Approved entries are therefore also kept in
// site:reviews:approved, and every reader uses the union of both.
// "id" is the entry id, or its `at` timestamp for entries saved before ids.

export const REVIEWS_KEY = "site:reviews";
export const STATUS_KEY = "site:reviews:status";
export const ACCESS_KEY = "site:reviews:access";
export const APPROVED_KEY = "site:reviews:approved";
export const MAX_REVIEWS = 500;

export const reviewId = (r) => r.id || r.at;

export const parseRows = (rows) =>
  (rows || [])
    .map((s) => {
      try {
        return JSON.parse(s);
      } catch {
        return null;
      }
    })
    .filter((r) => r && typeof r === "object");

// HGETALL flat array -> plain object.
export function hashOf(flat) {
  const o = {};
  const a = flat || [];
  for (let i = 0; i + 1 < a.length; i += 2) o[a[i]] = a[i + 1];
  return o;
}

// Union of the list and the approved hash, deduped by id, newest first.
export function mergeReviews(listRows, approvedFlat) {
  const seen = new Set();
  const out = [];
  const list = parseRows(listRows).reverse(); // newest first
  const kept = parseRows(Object.values(hashOf(approvedFlat)));
  for (const r of [...list, ...kept]) {
    const id = reviewId(r);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(r);
  }
  // Stable: ties keep list order. ISO timestamps sort as strings.
  return out.sort((a, b) => (String(b.at || "") > String(a.at || "") ? 1 : String(b.at || "") < String(a.at || "") ? -1 : 0));
}
