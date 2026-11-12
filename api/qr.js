// Admin: club QR codes for in-person outreach.
//
//   GET  /api/qr                       -> form + every club code made so far, with sign-ups per code
//   POST /api/qr  club, sport?, lang?  -> printable card with the QR code
//   GET  /api/qr?print=<slug>          -> printable card for an existing code
//
// A code opens  https://www.valenciasolution.net/[fr|es]?src=club-<slug>[&sport=x]#freeCard
// The free-offer form already records ?src= on each sign-up, so /api/signups and
// the table below show which clubs actually claimed.
//
// Storage (Upstash): site:qr  HASH slug -> {club, sport, lang, at}

import QRCode from "qrcode";
import { APPS } from "./_lib/apps.js";
import { isAdmin, redisPipeline, sameOrigin } from "./_lib/security.js";

const SITE = "https://www.valenciasolution.net";
const LANGS = { en: "", fr: "/fr", es: "/es" };
const COPY = {
  en: { scan: "Scan to claim your free", any: "Coaching Notepad", sub: "Free for this season's first 1,000 coaches · no subscription" },
  fr: { scan: "Scannez pour obtenir votre", any: "Coaching Notepad gratuit", sub: "Gratuit pour les 1 000 premiers entraîneurs · sans abonnement" },
  es: { scan: "Escanea para obtener tu", any: "Coaching Notepad gratis", sub: "Gratis para los primeros 1.000 entrenadores · sin suscripción" },
};

const esc = (s) =>
  String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const slugify = (s) =>
  String(s || "").toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 30);

function parseBody(req) {
  let b = req.body;
  if (typeof b === "string") {
    try { b = JSON.parse(b); } catch { b = Object.fromEntries(new URLSearchParams(b)); }
  }
  return b && typeof b === "object" ? b : {};
}

function linkFor({ slug, sport, lang }) {
  const q = new URLSearchParams({ src: `club-${slug}` });
  if (sport) q.set("sport", sport);
  return `${SITE}${LANGS[lang] ?? ""}/?${q.toString()}#freeCard`.replace("/fr/?", "/fr?").replace("/es/?", "/es?");
}

const STYLE = `body{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f7f7fb;color:#1a1a2e;padding:16px}
.card{background:#fff;border:1px solid #e2e2ec;border-radius:12px;padding:20px;max-width:640px;margin:0 auto 16px}
label{display:block;font-weight:600;margin:10px 0 4px}select,input,button,a.btn{font:inherit;width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #c9c9d6}
button,a.btn{display:block;text-align:center;text-decoration:none;background:#ff6b35;color:#fff;border:0;font-weight:600;margin-top:14px;cursor:pointer}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px;border-bottom:1px solid #eee;text-align:left}
.print{max-width:420px;margin:0 auto;background:#fff;border:2px solid #1a1a2e;border-radius:18px;padding:28px;text-align:center}
.print h1{font-size:24px;margin:0 0 4px}.print h2{font-size:18px;margin:0 0 16px;font-weight:600}.print svg{width:100%;max-width:300px;height:auto}
.print .club{font-weight:700;margin-top:12px}.print .sub{font-size:13px;color:#555}.print .url{font-size:11px;color:#777;word-break:break-all;margin-top:10px}
@media print{body{background:#fff;padding:0}.noprint{display:none}.print{border-width:2px;margin-top:20mm}}`;

async function printCard(res, code) {
  const url = linkFor(code);
  const svg = await QRCode.toString(url, { type: "svg", errorCorrectionLevel: "M", margin: 1 });
  const t = COPY[code.lang] || COPY.en;
  const app = code.sport && APPS[code.sport];
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(`<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>QR – ${esc(code.club)}</title><style>${STYLE}</style>
<div class="print"><h1>${esc(t.scan)}</h1><h2>${esc(app ? app.name : t.any)}</h2>${svg}
<div class="club">${esc(code.club)}</div><div class="sub">${esc(t.sub)}</div><div class="url">${esc(url)}</div></div>
<div class="card noprint" style="margin-top:16px"><button onclick="print()">Print this card</button>
<a class="btn" style="background:#1a1a2e" href="/api/qr">Back to club codes</a></div>`);
}

async function listPage(res, notice) {
  let codes = [];
  const bySource = {};
  try {
    const [flat, signups] = await redisPipeline([["HGETALL", "site:qr"], ["LRANGE", "site:signups", "0", "-1"]]);
    for (let i = 0; i < (flat || []).length; i += 2) {
      try { codes.push({ slug: flat[i], ...JSON.parse(flat[i + 1]) }); } catch { /* skip */ }
    }
    for (const s of signups || []) {
      try {
        const src = String(JSON.parse(s).source || "");
        if (src.startsWith("club-")) {
          const slug = src.slice(5).split(".")[0];
          bySource[slug] = (bySource[slug] || 0) + 1;
        }
      } catch { /* skip */ }
    }
  } catch { /* storage down: still let the admin make a code */ }
  codes = codes.map((c) => ({ ...c, signups: bySource[c.slug] || 0 })).sort((a, b) => b.signups - a.signups || String(b.at).localeCompare(String(a.at)));
  const opts = `<option value="">Any sport (coach picks)</option>` + Object.entries(APPS).map(([k, v]) => `<option value="${k}">${esc(v.name)}</option>`).join("");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(`<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Club QR codes</title><style>${STYLE}</style>
${notice ? `<div class="card"><strong>${esc(notice)}</strong></div>` : ""}
<form class="card" method="post" action="/api/qr"><h2>Make a club QR code</h2>
<p>One code per club. Coaches who scan it and claim a Notepad are counted under that club.</p>
<label>Club name</label><input name="club" required maxlength="60" placeholder="e.g. Milton Bulldogs">
<label>Sport (optional)</label><select name="sport">${opts}</select>
<label>Language</label><select name="lang"><option value="en">English</option><option value="fr">Français</option><option value="es">Español</option></select>
<button type="submit">Create QR code</button></form>
<div class="card"><h2>Club codes</h2><table><tr><th>Club</th><th>Sport</th><th>Sign-ups</th><th></th></tr>
${codes.map((c) => `<tr><td>${esc(c.club)}</td><td>${esc(c.sport ? (APPS[c.sport] || {}).name || c.sport : "Any")}</td><td><strong>${c.signups}</strong></td>` +
  `<td><a href="/api/qr?print=${encodeURIComponent(c.slug)}">Print</a></td></tr>`).join("") || '<tr><td colspan="4">No club codes yet.</td></tr>'}
</table><p style="font-size:13px;color:#666">Full sign-up details, including every source: <a href="/api/signups">/api/signups</a></p></div>`);
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "same-origin"); // no-referrer would send Origin: null on form posts and fail sameOrigin()
  if (!isAdmin(req, process.env.REVIEWS_ADMIN_KEY)) {
    res.redirect(303, "/api/admin?next=/api/qr");
    return;
  }

  if (req.method === "GET") {
    const p = slugify(req.query && req.query.print);
    if (p) {
      const [raw] = await redisPipeline([["HGET", "site:qr", p]]).catch(() => [null]);
      if (raw) {
        await printCard(res, { slug: p, ...JSON.parse(raw) });
        return;
      }
    }
    await listPage(res, null);
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

  const b = parseBody(req);
  const club = String(b.club || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 60);
  const slug = slugify(club);
  const sport = APPS[b.sport] ? b.sport : "";
  const lang = LANGS[b.lang] !== undefined ? b.lang : "en";
  if (!slug) {
    await listPage(res, "Enter a club name.");
    return;
  }
  const code = { club, sport, lang, at: new Date().toISOString() };
  try {
    await redisPipeline([["HSET", "site:qr", slug, JSON.stringify(code)]]);
  } catch {
    /* still show the card; it just won't be listed */
  }
  await printCard(res, { slug, ...code });
}
