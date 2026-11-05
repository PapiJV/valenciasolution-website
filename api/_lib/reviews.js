// Review storage helpers shared by /api/reviews and /api/testimonials.
//
//   site:reviews           LIST  newest MAX_REVIEWS entries (JSON)
//   site:reviews:approved  HASH  id -> entry JSON, kept even after trimming
//   site:reviews:status    HASH  id -> "approved" | "hidden"

export const LIST_KEY = "site:reviews";
export const STATUS_KEY = "site:reviews:status";
export const APPROVED_KEY = "site:reviews:approved";

const parse = (s) => {
  try {
    const r = JSON.parse(s);
    return r && typeof r === "object" ? r : null;
  } catch {
    return null;
  }
};

// Union of the list and the approved hash, deduped by id (or `at` for old
// entries), oldest first. The list copy wins when both have it.
export function mergeReviews(listRows, approvedRows) {
  const seen = new Set();
  const out = [];
  for (const r of [...(listRows || []), ...(approvedRows || [])].map(parse)) {
    const key = r && (r.id || r.at);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  // ISO timestamps sort as strings; sort is stable for ties.
  return out.sort((a, b) => String(a.at || "").localeCompare(String(b.at || "")));
}
