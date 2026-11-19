// Free Notepad launch offer: one free Notepad per coach.
// Ends at OFFER_ENDS_AT or after OFFER_CAP sign-ups, whichever comes first.
//
//   GET  /api/register  -> { open, cap, claimed, spotsLeft, endsAt }
//   POST /api/register  -> { ok, sport, appUrl, already? }
//                          appUrl carries a signed licence (#license=...).
//
// Storage: Upstash Redis (same store as /api/review).
//   site:signups:emails  SET   lower-cased emails (dedupe + cap count)
//   site:signups         LIST  JSON entries (read via /api/signups?key=...)
// Env: KV_REST_API_URL / KV_REST_API_TOKEN (or UPSTASH_REDIS_REST_*).

import { APPS, FREE_OFFER_CAP, appLink } from "./_lib/apps.js";
import { metaCommand, signLicense } from "./_lib/license.js";
import crypto from "node:crypto";
import { RegisterSchema, bodyOf, parse } from "./_lib/schemas.js";
import { rateLimit, safeEqual, sameOrigin, tooMany } from "./_lib/security.js";

const OFFER_ENDS_AT = "2027-01-01T04:59:59Z"; // Dec 31, 2026 11:59:59 pm Toronto (EST)
const OFFER_CAP = FREE_OFFER_CAP;


const EMAILS_KEY = "site:signups:emails";
const LIST_KEY = "site:signups";
const LIC_KEY = "site:signups:lic"; // HASH email -> {app, token}

// Repeat sign-ups only get their link back in the browser that claimed it.
// Without this, anyone who knows a coach's email could fetch that coach's
// licence. The cookie holds an HMAC of the email, never the email itself.
const CLAIM_COOKIE = "vs_claim";
const CLAIM_SEC = 400 * 24 * 60 * 60;
function claimMac(email) {
  const secret = String(process.env.LICENSE_PRIVATE_KEY || "");
  if (!secret) throw new Error("LICENSE_NOT_CONFIGURED");
  const k = crypto.createHash("sha256").update(`vs-claim-cookie:${secret}`).digest();
  return crypto.createHmac("sha256", k).update(email).digest("base64url");
}
const claimCookie = (email) =>
  `${CLAIM_COOKIE}=${claimMac(email)}; Path=/api/register; HttpOnly; Secure; SameSite=Strict; Max-Age=${CLAIM_SEC}`;
function hasClaimCookie(req, email) {
  const raw = String((req.headers && req.headers.cookie) || "");
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === CLAIM_COOKIE && safeEqual(part.slice(i + 1).trim(), claimMac(email))) return true;
  }
  return false;
}

// One licence per coach: reuse it on repeat sign-ins so the log stays clean.
async function licenceFor(email, sport) {
  const [prior] = await pipeline([["HGET", LIC_KEY, email]]);
  if (prior) {
    try {
      const p = JSON.parse(prior);
      if (p.app === sport && p.token) return p.token;
    } catch { /* reissue */ }
  }
  const { token, payload } = signLicense({ app: sport, tier: "free", ref: "free-launch-2026" });
  await pipeline([
    ["HSET", LIC_KEY, email, JSON.stringify({ app: sport, token })],
    ["RPUSH", "site:licenses", JSON.stringify({ at: new Date().toISOString(), source: "free-offer", app: sport, tier: "free", lid: payload.lid, email })],
    metaCommand(payload, email),
  ]);
  return token;
}

function creds() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error("NOT_CONFIGURED");
  return { url, token };
}

async function pipeline(commands) {
  const { url, token } = creds();
  const res = await fetch(`${url}/pipeline`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(commands),
  });
  if (!res.ok) throw new Error(`REDIS_${res.status}`);
  const out = await res.json();
  return out.map((r) => {
    if (r && r.error) throw new Error(`REDIS_CMD: ${r.error}`);
    return r ? r.result : null;
  });
}

const isOpenByDate = () => Date.now() <= Date.parse(OFFER_ENDS_AT);

function status(claimed) {
  const spotsLeft = Math.max(0, OFFER_CAP - claimed);
  return {
    open: isOpenByDate() && spotsLeft > 0,
    cap: OFFER_CAP,
    claimed: Math.min(claimed, OFFER_CAP),
    spotsLeft,
    endsAt: OFFER_ENDS_AT,
  };
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "GET") {
    try {
      const [claimed] = await pipeline([["SCARD", EMAILS_KEY]]);
      res.status(200).json(status(Number(claimed) || 0));
    } catch (e) {
      if (e.message === "NOT_CONFIGURED") {
        res.status(501).json({ error: "Sign-up storage isn't configured.", open: isOpenByDate(), cap: OFFER_CAP, endsAt: OFFER_ENDS_AT });
        return;
      }
      res.status(502).json({ error: "Storage request failed." });
    }
    return;
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }

  if (!sameOrigin(req)) {
    res.status(403).json({ error: "Forbidden." });
    return;
  }
  // 5 per hour per visitor: plenty for a coach, stops bots flooding the list.
  const rl = await rateLimit(req, { bucket: "register", limit: 5, windowSec: 3600, failOpen: true });
  if (!rl.ok) {
    tooMany(res, rl);
    return;
  }

  // Honeypot: real people never fill this hidden field.
  if (String(bodyOf(req).website || "").trim()) {
    res.status(200).json({ ok: true });
    return;
  }
  const p = parse(RegisterSchema, req);
  if (!p.ok) {
    res.status(400).json({ error: "Please pick a sport and enter your name and a valid email.", fields: p.issues });
    return;
  }
  // source: ?src= on the link, else the referring site.
  const { sport, name, email, role, club, city, marketingOptIn, source, referrer } = p.data;

  if (!isOpenByDate()) {
    res.status(410).json({ error: "This offer has ended.", ...status(OFFER_CAP) });
    return;
  }

  try {
    const [added, claimed] = await pipeline([
      ["SADD", EMAILS_KEY, email],
      ["SCARD", EMAILS_KEY],
    ]);

    if (Number(added) === 0) {
      // Already registered: resend their link (one free Notepad per coach).
      const [rows] = await pipeline([["LRANGE", LIST_KEY, "0", "-1"]]);
      let prior = null;
      for (const s of rows || []) {
        try {
          const r = JSON.parse(s);
          if (r.email === email) { prior = r; break; }
        } catch { /* skip */ }
      }
      const priorSport = prior && APPS[prior.sport] ? prior.sport : sport;
      if (!hasClaimCookie(req, email)) {
        // Same answer whether or not the email exists in the list beyond this point.
        res.status(200).json({ ok: true, already: true, sport: priorSport, appName: APPS[priorSport].name, appUrl: null });
        return;
      }
      const token = await licenceFor(email, priorSport);
      res.status(200).json({ ok: true, already: true, sport: priorSport, appName: APPS[priorSport].name, appUrl: appLink(priorSport, token) });
      return;
    }

    if (Number(claimed) > OFFER_CAP) {
      await pipeline([["SREM", EMAILS_KEY, email]]);
      res.status(410).json({ error: "All free spots have been claimed.", ...status(OFFER_CAP) });
      return;
    }

    const entry = {
      at: new Date().toISOString(),
      sport, name, email, role, club, city,
      marketingOptIn,
      source,
      referrer,
      consentText: marketingOptIn
        ? "Yes, email me Notepad updates, tips and offers from ValenciaSolution. I can unsubscribe any time."
        : "",
      offer: "free-launch-2026",
      spotNumber: Number(claimed),
    };
    await pipeline([["RPUSH", LIST_KEY, JSON.stringify(entry)]]);
    const token = await licenceFor(email, sport);

    res.setHeader("Set-Cookie", claimCookie(email));
    res.status(200).json({
      ok: true, sport, appName: APPS[sport].name, appUrl: appLink(sport, token),
      ...status(Number(claimed)),
    });
  } catch (e) {
    if (e.message === "NOT_CONFIGURED" || e.message === "LICENSE_NOT_CONFIGURED") {
      res.status(501).json({ error: "Sign-up isn't configured." });
      return;
    }
    res.status(502).json({ error: "Storage request failed." });
  }
}
