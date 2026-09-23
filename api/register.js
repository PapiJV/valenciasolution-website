// Free Notepad launch offer: one free Notepad per coach.
// Ends at OFFER_ENDS_AT or after OFFER_CAP sign-ups, whichever comes first.
//
//   GET  /api/register  -> { open, cap, claimed, spotsLeft, endsAt }
//   POST /api/register  -> { ok, sport, appUrl, already? }
//
// Storage: Upstash Redis (same store as /api/review).
//   site:signups:emails  SET   lower-cased emails (dedupe + cap count)
//   site:signups         LIST  JSON entries (read via /api/signups?key=...)
// Env: KV_REST_API_URL / KV_REST_API_TOKEN (or UPSTASH_REDIS_REST_*).

const OFFER_ENDS_AT = "2026-11-01T03:59:59Z"; // Oct 31, 2026 11:59:59 pm Toronto (EDT)
const OFFER_CAP = 100;

const APPS = {
  basketball: { name: "Basketball Notepad", url: "https://basketball-notepad-do-not-erase-1.vercel.app/" },
  volleyball: { name: "Volleyball Notepad", url: "https://volleyball-notepad-exclusive1sole.vercel.app/" },
  football: { name: "Football Notepad", url: "https://football-notepad.vercel.app/" },
  lacrosse: { name: "Lacrosse Notepad", url: "https://lacrosse-notepad.vercel.app/" },
};

const EMAILS_KEY = "site:signups:emails";
const LIST_KEY = "site:signups";

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

function clean(v, max) {
  return String(v == null ? "" : v).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
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

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = null; }
  }
  body = body || {};

  // Honeypot: real people never fill this hidden field.
  if (clean(body.website, 200)) {
    res.status(200).json({ ok: true });
    return;
  }

  const sport = clean(body.sport, 20).toLowerCase();
  const name = clean(body.name, 80);
  const email = clean(body.email, 120).toLowerCase();
  const role = clean(body.role, 80);
  const club = clean(body.club, 100);
  const city = clean(body.city, 80);
  const marketingOptIn = body.marketingOptIn === true;

  if (!APPS[sport] || !name || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    res.status(400).json({ error: "Please pick a sport and enter your name and a valid email." });
    return;
  }

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
      res.status(200).json({ ok: true, already: true, sport: priorSport, appName: APPS[priorSport].name, appUrl: APPS[priorSport].url });
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
      consentText: marketingOptIn
        ? "Yes, email me Notepad updates, tips and offers from ValenciaSolution. I can unsubscribe any time."
        : "",
      offer: "free-launch-2026",
      spotNumber: Number(claimed),
    };
    await pipeline([["RPUSH", LIST_KEY, JSON.stringify(entry)]]);

    res.status(200).json({
      ok: true, sport, appName: APPS[sport].name, appUrl: APPS[sport].url,
      ...status(Number(claimed)),
    });
  } catch (e) {
    if (e.message === "NOT_CONFIGURED") {
      res.status(501).json({ error: "Sign-up storage isn't configured." });
      return;
    }
    res.status(502).json({ error: "Storage request failed." });
  }
}
