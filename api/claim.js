// Stripe Payment Link "after completion" target.
//
//   GET /api/claim?session_id={CHECKOUT_SESSION_ID}
//     -> verifies the Checkout Session with Stripe (server-side, secret key),
//        issues one signed licence per session, 303s to the app with
//        #license=<token>. Re-visiting the same session returns the same licence.
//
// Storage (Upstash):
//   site:lic:session:<cs_id>  STRING  token (idempotency)
//   site:licenses             LIST    JSON log of every licence issued
// Env: STRIPE_SECRET_KEY (restricted key with Checkout Sessions: Read is enough),
//      LICENSE_PRIVATE_KEY, KV_REST_API_URL / KV_REST_API_TOKEN.

import { APPS, CLUB_MIN_CENTS, PAYMENT_LINKS, appLink } from "./_lib/apps.js";
import { signLicense } from "./_lib/license.js";
import { rateLimit, redisPipeline, tooMany } from "./_lib/security.js";

const SESSION_RE = /^cs_(live|test)_[A-Za-z0-9]{10,200}$/;

function page(res, status, title, msg) {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(status).send(`<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title>
<style>body{font:16px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f7fb;color:#1a1a2e}
main{background:#fff;border:1px solid #e2e2ec;border-radius:14px;padding:28px;max-width:440px;margin:16px}h1{font-size:20px;margin:0 0 10px}a{color:#ff6b35}</style>
<main><h1>${title}</h1><p>${msg}</p><p>Need help? Email <a href="mailto:j@valenciasolution.net">j@valenciasolution.net</a> with your receipt and we'll sort it out.</p></main>`);
}

async function stripeSession(id) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("STRIPE_NOT_CONFIGURED");
  const r = await fetch(
    `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(id)}?expand[]=line_items`,
    { headers: { Authorization: `Bearer ${key}` } }
  );
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`STRIPE_${r.status}`);
  return r.json();
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }

  const id = String((req.query && req.query.session_id) || "");
  if (!SESSION_RE.test(id)) {
    page(res, 400, "Link not recognised", "This page is only reached right after checkout.");
    return;
  }

  const rl = await rateLimit(req, { bucket: "claim", limit: 30, windowSec: 3600, failOpen: true });
  if (!rl.ok) {
    tooMany(res, rl);
    return;
  }

  const KEY = `site:lic:session:${id}`;
  try {
    const [existing] = await redisPipeline([["GET", KEY]]);
    if (existing) {
      const { app, token } = JSON.parse(existing);
      res.redirect(303, appLink(app, token));
      return;
    }

    const s = await stripeSession(id);
    const paid = s && s.status === "complete" && (s.payment_status === "paid" || s.payment_status === "no_payment_required");
    if (!paid) {
      page(res, 402, "Payment not found", "We couldn't confirm a completed payment for this checkout.");
      return;
    }

    const app = PAYMENT_LINKS[s.payment_link];
    if (!APPS[app]) {
      page(res, 409, "Almost there", "Your payment went through, but we couldn't match it to a Notepad automatically.");
      return;
    }
    const item = s.line_items && s.line_items.data && s.line_items.data[0];
    const unit = (item && item.price && item.price.unit_amount) || 0;
    // A 100%-off code (club giveaways) still unlocks the app, but is logged as comp.
    const tier = !s.amount_total ? "comp" : unit >= CLUB_MIN_CENTS ? "club" : "individual";

    const { token, payload } = signLicense({ app, tier, ref: id });
    // NX: if two tabs race, the first licence wins and both get the same one.
    const [set] = await redisPipeline([["SET", KEY, JSON.stringify({ app, token }), "NX"]]);
    if (set !== "OK") {
      const [again] = await redisPipeline([["GET", KEY]]);
      const prior = JSON.parse(again);
      res.redirect(303, appLink(prior.app, prior.token));
      return;
    }
    await redisPipeline([[
      "RPUSH", "site:licenses",
      JSON.stringify({
        at: new Date().toISOString(), source: "stripe", app, tier, lid: payload.lid, ref: id,
        email: (s.customer_details && s.customer_details.email) || "",
        amount: s.amount_total, currency: s.currency,
      }),
    ]]);
    res.redirect(303, appLink(app, token));
  } catch (e) {
    console.error("claim failed", e && e.message);
    page(res, 503, "One moment", "Your payment is safe, but we couldn't open your Notepad just now. Refresh this page in a minute.");
  }
}
