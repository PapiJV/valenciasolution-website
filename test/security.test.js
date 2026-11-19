import { after, beforeEach, describe, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ADMIN_KEY, ORIGIN, call, cookieValue, db, freshIp, reset, setEnv, setRedisDown, stripeSessions,
} from "./helpers.js";

setEnv();
const admin = (await import("../api/admin.js")).default;
const reviews = (await import("../api/reviews.js")).default;
const review = (await import("../api/review.js")).default;
const signups = (await import("../api/signups.js")).default;
const license = (await import("../api/license.js")).default;
const qr = (await import("../api/qr.js")).default;
const register = (await import("../api/register.js")).default;
const claim = (await import("../api/claim.js")).default;
const activate = (await import("../api/activate.js")).default;
const upload = (await import("../api/upload.js")).default;
const testimonials = (await import("../api/testimonials.js")).default;
const { signLicense } = await import("../api/_lib/license.js");
const { LOCKOUT, adminCookie } = await import("../api/_lib/security.js");

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

beforeEach(() => {
  reset();
  setEnv();
});
after(() => reset());

async function login(ip = freshIp(), key = ADMIN_KEY) {
  return call(admin, { method: "POST", ip, body: { key, next: "/api/reviews" } });
}
async function session(ip = freshIp()) {
  const r = await login(ip);
  assert.equal(r.statusCode, 303);
  return `vs_admin=${cookieValue(r.headers["set-cookie"], "vs_admin")}`;
}

// ---------------------------------------------------------------- AUTH
describe("1. credential storage", () => {
  test("no password/credential is written to storage on login", async () => {
    await login();
    const dump = JSON.stringify([...db.entries()], (_k, v) => (v instanceof Map ? [...v] : v instanceof Set ? [...v] : v));
    assert.ok(!dump.includes(ADMIN_KEY), "admin key must never be persisted");
  });
});

describe("2. session cookie", () => {
  test("HttpOnly, Secure, SameSite=Strict, scoped to /api", async () => {
    const r = await login();
    const c = r.headers["set-cookie"];
    for (const attr of ["HttpOnly", "Secure", "SameSite=Strict", "Path=/api"]) assert.ok(c.includes(attr), attr);
  });

  test("rotated on every login (fresh random session id)", async () => {
    const a = cookieValue((await login()).headers["set-cookie"], "vs_admin");
    const b = cookieValue((await login()).headers["set-cookie"], "vs_admin");
    assert.notEqual(a, b);
    assert.notEqual(a.split(".")[1], b.split(".")[1]);
  });

  test("logout revokes the session server-side (copied cookie stops working)", async () => {
    const cookie = await session();
    assert.equal((await call(reviews, { headers: { cookie }, query: { format: "json" } })).statusCode, 200);
    const out = await call(admin, { method: "POST", headers: { cookie }, body: { logout: "1", next: "/api/reviews" } });
    assert.match(out.headers["set-cookie"], /Max-Age=0/);
    assert.equal((await call(reviews, { headers: { cookie }, query: { format: "json" } })).statusCode, 401);
  });

  test("tampered, legacy-format and expired cookies are rejected", async () => {
    const v = cookieValue(adminCookie(ADMIN_KEY), "vs_admin");
    const [exp, sid, mac] = v.split(".");
    for (const bad of [`${exp}.${sid}.${mac.slice(0, -2)}xx`, `${exp}.${mac}`, `1.${sid}.${mac}`, `${Number(exp) + 1}.${sid}.${mac}`]) {
      const r = await call(reviews, { headers: { cookie: `vs_admin=${bad}` }, query: { format: "json" } });
      assert.equal(r.statusCode, 401, bad);
    }
  });
});

describe("3. login rate limit + lockout", () => {
  test(`locks a visitor for 15 min after ${LOCKOUT.perIp} wrong keys, even for the right key`, async () => {
    const ip = freshIp();
    for (let i = 0; i < LOCKOUT.perIp; i++) assert.equal((await login(ip, "wrong")).statusCode, 401);
    const locked = await login(ip, ADMIN_KEY);
    assert.equal(locked.statusCode, 429);
    assert.ok(Number(locked.headers["retry-after"]) > 800);
    assert.equal((await login(freshIp())).statusCode, 303, "other visitors unaffected");
  });

  test("wrong Bearer keys count toward the same lockout", async () => {
    const ip = freshIp();
    for (let i = 0; i < LOCKOUT.perIp; i++) {
      const r = await call(reviews, { ip, headers: { authorization: "Bearer nope" }, query: { format: "json" } });
      assert.equal(r.statusCode, 401);
    }
    const r = await call(reviews, { ip, headers: { authorization: `Bearer ${ADMIN_KEY}` }, query: { format: "json" } });
    assert.equal(r.statusCode, 401, "locked out");
    assert.equal((await call(reviews, { ip: freshIp(), headers: { authorization: `Bearer ${ADMIN_KEY}` }, query: { format: "json" } })).statusCode, 200);
  });

  test(`account-wide lock after ${LOCKOUT.global} failures from many IPs`, async () => {
    for (let i = 0; i < LOCKOUT.global; i++) await login(freshIp(), "wrong");
    assert.equal((await login(freshIp())).statusCode, 429);
  });

  test("successful login clears that visitor's failure count", async () => {
    const ip = freshIp();
    for (let i = 0; i < LOCKOUT.perIp - 1; i++) await login(ip, "wrong");
    assert.equal((await login(ip)).statusCode, 303);
    for (let i = 0; i < LOCKOUT.perIp - 1; i++) await login(ip, "wrong");
    assert.equal((await login(ip)).statusCode, 303);
  });

  test("fails closed when Redis is down", async () => {
    setRedisDown(true);
    assert.notEqual((await login()).statusCode, 303);
  });
});

// ---------------------------------------------------------------- SECRETS
describe("5. no secrets in shipped client files", () => {
  const files = ["index.html", "fr.html", "es.html", "testimonials.html", "offer/index.html", "js/blob-upload.js"];
  const PATTERNS = [/sk_(live|test)_[A-Za-z0-9]{8,}/, /rk_(live|test)_[A-Za-z0-9]{8,}/, /whsec_[A-Za-z0-9]{8,}/, /vercel_blob_rw_[A-Za-z0-9]+_[A-Za-z0-9]+/, /-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n?[A-Za-z0-9+/]{20,}/, /KV_REST_API_TOKEN\s*[:=]\s*["'][^"']+/];
  for (const f of files) {
    test(f, () => {
      const s = fs.readFileSync(path.join(ROOT, f), "utf8");
      for (const p of PATTERNS) assert.doesNotMatch(s, p);
    });
  }
});

// ---------------------------------------------------------------- ACCESS CONTROL
describe("7. users only get their own data (free-offer link)", () => {
  const body = { sport: "hockey", name: "Coach A", email: "coach.a@example.com" };

  test("first sign-up returns the link and sets an HttpOnly claim cookie", async () => {
    const r = await call(register, { method: "POST", ip: freshIp(), body });
    assert.equal(r.statusCode, 200);
    assert.match(r.body.appUrl, /#license=VS1\./);
    assert.match(r.headers["set-cookie"], /vs_claim=.+HttpOnly; Secure; SameSite=Strict/);
  });

  test("someone else submitting the same email does NOT get the coach's licence", async () => {
    await call(register, { method: "POST", ip: freshIp(), body });
    const r = await call(register, { method: "POST", ip: freshIp(), body });
    assert.equal(r.statusCode, 200);
    assert.equal(r.body.already, true);
    assert.equal(r.body.appUrl, null);
  });

  test("the same browser (claim cookie) gets its own link back", async () => {
    const first = await call(register, { method: "POST", ip: freshIp(), body });
    const cookie = `vs_claim=${cookieValue(first.headers["set-cookie"], "vs_claim")}`;
    const again = await call(register, { method: "POST", ip: freshIp(), headers: { cookie }, body });
    assert.equal(again.body.appUrl, first.body.appUrl);
  });

  test("a claim cookie for one email does not unlock another email", async () => {
    const a = await call(register, { method: "POST", ip: freshIp(), body });
    await call(register, { method: "POST", ip: freshIp(), body: { ...body, email: "coach.b@example.com" } });
    const cookie = `vs_claim=${cookieValue(a.headers["set-cookie"], "vs_claim")}`;
    const r = await call(register, { method: "POST", ip: freshIp(), headers: { cookie }, body: { ...body, email: "coach.b@example.com" } });
    assert.equal(r.body.appUrl, null);
  });

  test("public testimonial feed never exposes emails", async () => {
    await call(review, { method: "POST", ip: freshIp(), body: { name: "A", message: "Great app for my team!", email: "secret@example.com", rating: 5, consent: true } });
    const [row] = db.get("site:reviews").v;
    db.set("site:reviews:status", { v: new Map([[JSON.parse(row).id, "approved"]]) });
    const r = await call(testimonials, {});
    assert.equal(r.body.testimonials.length, 1);
    assert.ok(!JSON.stringify(r.body).includes("secret@example.com"));
  });
});

describe("8. admin routes are locked server-side", () => {
  const routes = { reviews, signups, license, qr };
  for (const [name, h] of Object.entries(routes)) {
    test(`/api/${name} GET without session -> redirect/401, no data`, async () => {
      const r = await call(h, { query: { format: "json" } });
      assert.ok([303, 401].includes(r.statusCode), String(r.statusCode));
      assert.ok(!r.body || !String(JSON.stringify(r.body)).includes("@"));
    });
    test(`/api/${name} POST without session is refused`, async () => {
      const r = await call(h, { method: "POST", body: { id: "x", action: "approve", app: "hockey", club: "X" } });
      assert.ok([303, 401, 405].includes(r.statusCode), String(r.statusCode));
      assert.ok(!String(JSON.stringify(r.body || "")).includes("license="));
    });
  }
  test("licence issuing works only with a session", async () => {
    const cookie = await session();
    const r = await call(license, { method: "POST", headers: { cookie }, body: { app: "hockey", tier: "club", note: "x" } });
    assert.equal(r.statusCode, 200);
    assert.match(r.body, /#license=VS1\./);
  });
  test("REVIEWS_ADMIN_KEY unset -> admin fails closed with a generic message", async () => {
    delete process.env.REVIEWS_ADMIN_KEY;
    const r = await call(admin, {});
    assert.equal(r.statusCode, 503);
    assert.ok(!JSON.stringify(r.body).includes("REVIEWS_ADMIN_KEY"));
  });
});

// ---------------------------------------------------------------- INPUT
describe("9. Zod validation", () => {
  const good = { name: "Coach", message: "Great app for my team!", email: "c@example.com", rating: 4 };
  const bad = {
    "over-long name": { name: "x".repeat(81) },
    "over-long message": { message: "x".repeat(801) },
    "short message": { message: "short" },
    "bad email": { email: "not-an-email" },
    "rating 0": { rating: 0 },
    "rating 9": { rating: 9 },
    "rating text": { rating: "five" },
    "object name": { name: { $gt: "" } },
    "bad access": { access: "admin" },
    "foreign media url": { media: "https://evil.example.com/x.png" },
    "javascript media": { media: "javascript:alert(1)" },
  };
  for (const [label, patch] of Object.entries(bad)) {
    test(`review rejects ${label}`, async () => {
      const r = await call(review, { method: "POST", ip: freshIp(), body: { ...good, ...patch } });
      assert.equal(r.statusCode, 400);
    });
  }
  test("review accepts a valid payload and our own Blob media", async () => {
    const r = await call(review, { method: "POST", ip: freshIp(), body: { ...good, media: "https://teststore.public.blob.vercel-storage.com/testimonials/1.jpg" } });
    assert.equal(r.statusCode, 200);
  });
  test("register rejects unknown sport / long fields", async () => {
    for (const body of [
      { sport: "chess", name: "A", email: "a@example.com" },
      { sport: "hockey", name: "A".repeat(81), email: "a@example.com" },
      { sport: "hockey", name: "A", email: "a@example.com", club: "c".repeat(101) },
      { sport: "__proto__", name: "A", email: "a@example.com" },
    ]) assert.equal((await call(register, { method: "POST", ip: freshIp(), body })).statusCode, 400, JSON.stringify(body).slice(0, 60));
  });
  test("activate rejects malformed device ids and forged tokens", async () => {
    const { token } = signLicense({ app: "hockey", tier: "individual", ref: "t" });
    assert.equal((await call(activate, { method: "POST", body: { token, device: "short" } })).statusCode, 400);
    const forged = token.slice(0, -4) + "AAAA";
    assert.equal((await call(activate, { method: "POST", body: { token: forged, device: "d".repeat(20) } })).statusCode, 400);
    assert.equal((await call(activate, { method: "POST", body: { token, device: "d".repeat(20) } })).statusCode, 200);
  });
  test("licence admin rejects unknown tier/app", async () => {
    const cookie = await session();
    assert.equal((await call(license, { method: "POST", headers: { cookie }, body: { app: "chess" } })).statusCode, 400);
    assert.equal((await call(license, { method: "POST", headers: { cookie }, body: { action: "revoke", lid: "../../x" } })).statusCode, 400);
  });
});

describe("10. injection (no SQL; Redis commands are structured arrays)", () => {
  test("no SQL client or string-built queries in the codebase", () => {
    for (const f of fs.readdirSync(path.join(ROOT, "api"), { recursive: true }).filter((f) => f.endsWith(".js"))) {
      const s = fs.readFileSync(path.join(ROOT, "api", f), "utf8");
      assert.doesNotMatch(s, /\b(SELECT|INSERT INTO|UPDATE \w+ SET|DELETE FROM)\b/, f);
    }
  });
  test("hostile values stay single Redis arguments", async () => {
    const evil = "x\r\nFLUSHALL\r\n";
    await call(review, { method: "POST", ip: freshIp(), body: { name: evil, message: "Great app for my team!", email: "c@example.com", rating: 3 } });
    const { redisLog } = await import("./helpers.js");
    assert.ok(!redisLog.some((c) => c[0] === "FLUSHALL"));
    assert.ok(db.has("site:reviews"));
  });
});

describe("11. XSS", () => {
  test("admin review table escapes stored HTML and ships a nonce CSP", async () => {
    await call(review, { method: "POST", ip: freshIp(), body: { name: "<img src=x onerror=alert(1)>", message: "<script>alert(1)</script> nice", email: "c@example.com", rating: 3 } });
    const cookie = await session();
    const r = await call(reviews, { headers: { cookie } });
    assert.equal(r.statusCode, 200);
    assert.ok(!r.body.includes("<script>alert(1)</script>"));
    assert.ok(!r.body.includes("<img src=x"));
    assert.ok(r.body.includes("&lt;script&gt;"));
    const csp = r.headers["content-security-policy"];
    const nonce = /'nonce-([^']+)'/.exec(csp)[1];
    assert.match(csp, /default-src 'none'/);
    assert.doesNotMatch(csp, /script-src[^;]*unsafe-inline/);
    assert.ok(r.body.includes(`<script nonce="${nonce}">`));
    assert.doesNotMatch(r.body, /\son[a-z]+="/, "no inline event handlers (blocked by CSP)");
  });
  for (const [name, h] of Object.entries({ admin, signups, license, qr })) {
    test(`/api/${name} HTML has CSP without inline handlers`, async () => {
      const cookie = await session();
      const r = await call(h, { headers: { cookie } });
      assert.match(String(r.headers["content-security-policy"]), /script-src 'nonce-/);
      assert.doesNotMatch(String(r.body), /\son[a-z]+="/);
    });
  }
  test("site-wide CSP header is configured in vercel.json", () => {
    const v = JSON.parse(fs.readFileSync(path.join(ROOT, "vercel.json"), "utf8"));
    const all = v.headers.flatMap((h) => h.headers);
    const csp = all.find((h) => h.key === "Content-Security-Policy");
    assert.ok(csp && /object-src 'none'/.test(csp.value) && /frame-ancestors/.test(csp.value));
  });
  test("no dangerouslySetInnerHTML / user data into innerHTML on public pages", () => {
    for (const f of ["index.html", "fr.html", "es.html", "testimonials.html"]) {
      const s = fs.readFileSync(path.join(ROOT, f), "utf8");
      assert.doesNotMatch(s, /dangerouslySetInnerHTML/);
      for (const line of s.split("\n").filter((l) => /\.innerHTML\s*=/.test(l))) {
        assert.doesNotMatch(line, /\bt\.(name|message|headline|role|club|media|product)\b/, line.trim());
      }
    }
  });
});

describe("12. CSRF", () => {
  test("cross-site POST with a valid admin cookie is refused", async () => {
    const cookie = await session();
    for (const [h, body] of [[reviews, { id: "x", action: "hide" }], [license, { app: "hockey" }], [qr, { club: "X" }]]) {
      const r = await call(h, { method: "POST", origin: "https://evil.example", headers: { cookie }, body });
      assert.equal(r.statusCode, 403);
    }
  });
  test("POST with no Origin header is refused", async () => {
    const cookie = await session();
    const r = await call(license, { method: "POST", origin: null, headers: { cookie }, body: { app: "hockey" } });
    assert.equal(r.statusCode, 403);
  });
  test("cross-site login and logout are refused", async () => {
    assert.equal((await call(admin, { method: "POST", origin: "https://evil.example", body: { key: ADMIN_KEY } })).statusCode, 403);
    assert.equal((await call(admin, { method: "POST", origin: "https://evil.example", body: { logout: "1" } })).statusCode, 403);
  });
  test("public POST endpoints refuse cross-site", async () => {
    for (const h of [review, register]) {
      assert.equal((await call(h, { method: "POST", origin: "https://evil.example", body: {} })).statusCode, 403);
    }
  });
});

describe("13. uploads", () => {
  const tokenReq = (pathname) => ({ method: "POST", ip: freshIp(), body: { type: "blob.generate-client-token", payload: { pathname, clientPayload: null, multipart: false } } });
  const tokenPayload = (clientToken) => {
    const b64 = clientToken.split("_").slice(4).join("_");
    const [, payload] = Buffer.from(b64, "base64").toString().split(".");
    return JSON.parse(Buffer.from(payload, "base64").toString());
  };

  test("random-named allowlisted file gets a token limited to its type and size", async () => {
    const r = await call(upload, tokenReq("testimonials/123e4567-e89b-12d3-a456-426614174000.mp4"));
    assert.equal(r.statusCode, 200);
    const p = tokenPayload(r.body.clientToken);
    assert.deepEqual(p.allowedContentTypes, ["video/mp4"]);
    assert.equal(p.maximumSizeInBytes, 100 * 1024 * 1024);
    assert.equal(p.addRandomSuffix, true);
  });
  for (const bad of [
    "testimonials/123e4567-e89b-12d3-a456-426614174000.svg",
    "testimonials/123e4567-e89b-12d3-a456-426614174000.html",
    "testimonials/my-original-name.jpg",
    "../index.html",
    "other/123e4567-e89b-12d3-a456-426614174000.jpg",
  ]) {
    test(`refuses ${bad}`, async () => {
      assert.equal((await call(upload, tokenReq(bad))).statusCode, 400);
    });
  }
  test("per-visitor upload cap", async () => {
    const ip = freshIp();
    const good = "testimonials/123e4567-e89b-12d3-a456-426614174000.jpg";
    for (let i = 0; i < 3; i++) assert.equal((await call(upload, { ...tokenReq(good), ip })).statusCode, 200);
    assert.equal((await call(upload, { ...tokenReq(good), ip })).statusCode, 429);
  });
  test("cross-site token request refused", async () => {
    assert.equal((await call(upload, { ...tokenReq("testimonials/123e4567-e89b-12d3-a456-426614174000.jpg"), origin: "https://evil.example" })).statusCode, 403);
  });
});

describe("14. pricing is decided on the server", () => {
  const PL = "plink_1UJBCS2acRxanCPyQHVaiII0"; // hockey
  const session = (id, unit, total, extra = {}) =>
    stripeSessions.set(id, { id, status: "complete", payment_status: "paid", payment_link: PL, amount_total: total, currency: "cad", line_items: { data: [{ price: { unit_amount: unit } }] }, customer_details: { email: "b@example.com" }, ...extra });
  const tierOf = (r) => JSON.parse(Buffer.from(r.headers.location.split("#license=")[1].split(".")[1], "base64url")).tier;

  test("club tier only when Stripe says >= CA$200 was charged", async () => {
    session("cs_test_aaaaaaaaaaaa", 25000, 28250);
    session("cs_test_bbbbbbbbbbbb", 4999, 5649);
    assert.equal(tierOf(await call(claim, { query: { session_id: "cs_test_aaaaaaaaaaaa", tier: "individual" } })), "club");
    assert.equal(tierOf(await call(claim, { query: { session_id: "cs_test_bbbbbbbbbbbb", tier: "club", amount: "99999" } })), "individual");
  });
  test("unpaid or unknown sessions get no licence", async () => {
    session("cs_test_cccccccccccc", 25000, 28250, { payment_status: "unpaid" });
    assert.equal((await call(claim, { query: { session_id: "cs_test_cccccccccccc" } })).statusCode, 402);
    assert.equal((await call(claim, { query: { session_id: "cs_test_doesnotexist" } })).statusCode, 402);
  });
  test("free-offer tier is always 'free' whatever the client sends", async () => {
    const r = await call(register, { method: "POST", ip: freshIp(), body: { sport: "hockey", name: "A", email: "t@example.com", tier: "club" } });
    const tier = JSON.parse(Buffer.from(r.body.appUrl.split("#license=")[1].split(".")[1], "base64url")).tier;
    assert.equal(tier, "free");
  });
});

// ---------------------------------------------------------------- INFRA
describe("15/16. transport + error hygiene", () => {
  test("HSTS >= 1 year with includeSubDomains", () => {
    const v = JSON.parse(fs.readFileSync(path.join(ROOT, "vercel.json"), "utf8"));
    const h = v.headers.flatMap((x) => x.headers).find((x) => x.key === "Strict-Transport-Security");
    assert.ok(Number(/max-age=(\d+)/.exec(h.value)[1]) >= 31536000 && /includeSubDomains/.test(h.value));
  });
  test("storage failures return generic errors, no stack traces or env names", async () => {
    setRedisDown(true);
    const outs = [
      await call(review, { method: "POST", ip: freshIp(), body: { name: "A", message: "Great app for my team!", email: "c@example.com", rating: 3 } }),
      await call(register, { method: "POST", ip: freshIp(), body: { sport: "hockey", name: "A", email: "a@example.com" } }),
      await call(testimonials, {}),
    ];
    for (const r of outs) {
      const s = JSON.stringify(r.body);
      assert.ok(r.statusCode >= 500, String(r.statusCode));
      assert.doesNotMatch(s, /at \w+ \(|node:internal|REDIS_|KV_REST|_KEY|stack/i);
    }
  });
  test("licence key missing -> generic error", async () => {
    const cookie = await session();
    delete process.env.LICENSE_PRIVATE_KEY;
    const r = await call(license, { method: "POST", headers: { cookie }, body: { app: "hockey" } });
    assert.equal(r.statusCode, 503);
    assert.doesNotMatch(JSON.stringify(r.body), /LICENSE_PRIVATE_KEY/);
  });
});

// ---------------------------------------------------------------- FOLLOW-UP FIXES
const helpers = await import("./helpers.js");
const { rateLimit, isOwnBlobUrl, blobStoreHost } = await import("../api/_lib/security.js");
const { MAX_REVIEWS, APPROVED_KEY } = await import("../api/_lib/reviews.js");
const { APPS, FREE_OFFER_CAP } = await import("../api/_lib/apps.js");

const OWN = "https://teststore.public.blob.vercel-storage.com/testimonials/123e4567-e89b-12d3-a456-426614174000-AbC.jpg";
let mailSeq = 0;
const reviewBody = (patch = {}) => ({ name: "Coach", message: "Great app for my team!", email: `c${mailSeq++}@example.com`, rating: 5, consent: true, ...patch });
const submit = (patch) => call(review, { method: "POST", ip: freshIp(), body: reviewBody(patch) });
const listRows = () => (db.get("site:reviews")?.v || []).map((x) => JSON.parse(x));
const approvedHash = () => db.get(APPROVED_KEY)?.v || new Map();
async function setReview(cookie, id, action) {
  return call(reviews, { method: "POST", headers: { cookie }, body: { id, action } });
}

describe("17. approved testimonials survive spam (list trim)", () => {
  test(`approved entry stays on the wall after ${MAX_REVIEWS + 20} spam submissions`, async () => {
    assert.equal((await submit({ name: "Real Coach" })).statusCode, 200);
    const id = listRows()[0].id;
    const cookie = await session();
    assert.equal((await setReview(cookie, id, "approve")).statusCode, 200);
    for (let i = 0; i < MAX_REVIEWS + 20; i++) assert.equal((await submit({ name: `spam ${i}` })).statusCode, 200);
    assert.equal(listRows().length, MAX_REVIEWS);
    assert.ok(!listRows().some((r) => r.id === id), "trimmed from the list");
    const wall = await call(testimonials, {});
    assert.deepEqual(wall.body.testimonials.map((t) => t.name), ["Real Coach"]);
    const adm = await call(reviews, { headers: { cookie }, query: { format: "json" } });
    assert.ok(adm.body.reviews.some((r) => r.id === id && r.wall === "approved"));
    assert.equal((await setReview(cookie, id, "hide")).statusCode, 200, "id lookup finds hash-only entry");
    assert.equal((await call(testimonials, {})).body.testimonials.length, 0);
  });

  test("entries approved before this change (status only) are copied to the hash before the trim", async () => {
    assert.equal((await submit({ name: "Old Approved" })).statusCode, 200);
    const id = listRows()[0].id;
    db.set("site:reviews:status", { v: new Map([[id, "approved"]]) });
    for (let i = 0; i < MAX_REVIEWS + 5; i++) await submit({ name: `spam ${i}` });
    assert.ok(approvedHash().has(id));
    assert.deepEqual((await call(testimonials, {})).body.testimonials.map((t) => t.name), ["Old Approved"]);
  });

  test("if the copy step fails, the trim is skipped and the review is still saved", async () => {
    await submit({ name: "Old Approved" });
    const id = listRows()[0].id;
    db.set("site:reviews:status", { v: new Map([[id, "approved"]]) });
    for (let i = 0; i < MAX_REVIEWS - 1; i++) await submit();
    assert.equal(listRows().length, MAX_REVIEWS);
    helpers.failCommands.add("HSET");
    const r = await submit({ name: "Extra" });
    assert.equal(r.statusCode, 200);
    assert.equal(listRows().length, MAX_REVIEWS + 1, "not trimmed");
    assert.equal(listRows()[0].id, id);
  });
});

describe("18. approve / hide keep site:reviews:approved in sync", () => {
  test("approve stores the full entry, hide and pending remove it", async () => {
    await submit({ name: "A" });
    const id = listRows()[0].id;
    const cookie = await session();
    assert.equal((await setReview(cookie, id, "approve")).statusCode, 200);
    assert.equal(JSON.parse(approvedHash().get(id)).name, "A");
    assert.equal(db.get("site:reviews:status").v.get(id), "approved");
    assert.equal((await setReview(cookie, id, "hide")).statusCode, 200);
    assert.ok(!approvedHash().has(id));
    assert.equal(db.get("site:reviews:status").v.get(id), "hidden");
    await setReview(cookie, id, "approve");
    assert.equal((await setReview(cookie, id, "pending")).statusCode, 200);
    assert.ok(!approvedHash().has(id));
    assert.ok(!db.get("site:reviews:status").v.has(id));
  });
  test("approve without consent is refused and stores nothing", async () => {
    await submit({ consent: false });
    const id = listRows()[0].id;
    assert.equal((await setReview(await session(), id, "approve")).statusCode, 409);
    assert.ok(!approvedHash().has(id));
  });
});

describe("19. wall reads the union of list + approved hash", () => {
  test("deduped by id, newest first, hash-only entries included", async () => {
    const mk = (id, at, name) => ({ id, at, name, message: "Great app for my team!", email: "x@example.com", rating: 5, consent: true });
    const a = mk("r_a", "2026-01-01T00:00:00.000Z", "A"), b = mk("r_b", "2026-03-01T00:00:00.000Z", "B"), c = mk("r_c", "2026-02-01T00:00:00.000Z", "C");
    db.set("site:reviews", { v: [JSON.stringify(b)] });
    db.set(APPROVED_KEY, { v: new Map([["r_a", JSON.stringify(a)], ["r_b", JSON.stringify(b)], ["r_c", JSON.stringify(c)]]) });
    db.set("site:reviews:status", { v: new Map([["r_a", "approved"], ["r_b", "approved"], ["r_c", "approved"]]) });
    db.set("site:reviews:access", { v: new Map([["r_a", "free"]]) });
    const r = await call(testimonials, {});
    assert.deepEqual(r.body.testimonials.map((t) => t.name), ["B", "C", "A"]);
    assert.equal(r.body.testimonials[2].access, "free", "free-access override still applies");
    assert.ok(!JSON.stringify(r.body).includes("x@example.com"));
    const cookie = await session();
    const adm = await call(reviews, { headers: { cookie }, query: { format: "json" } });
    assert.deepEqual(adm.body.reviews.map((x) => x.id), ["r_b", "r_c", "r_a"]);
  });
  test("hash entries still need status 'approved' to show", async () => {
    db.set(APPROVED_KEY, { v: new Map([["r_x", JSON.stringify({ id: "r_x", at: "2026-01-01T00:00:00Z", name: "X", consent: true })]]) });
    db.set("site:reviews:status", { v: new Map([["r_x", "hidden"]]) });
    assert.equal((await call(testimonials, {})).body.testimonials.length, 0);
  });
});

describe("20. per-email review limit", () => {
  test("3 per email per day across IPs; raw email never stored in keys", async () => {
    const email = "Same.Coach@Example.com";
    for (let i = 0; i < 3; i++) assert.equal((await submit({ email })).statusCode, 200);
    assert.equal((await submit({ email })).statusCode, 429);
    assert.equal((await submit({ email: "other@example.com" })).statusCode, 200);
    const keys = [...db.keys()].filter((k) => k.startsWith("site:rl:review-email:"));
    assert.equal(keys.length, 2);
    for (const k of keys) assert.ok(!k.toLowerCase().includes("example.com"), k);
  });
});

describe("21. rate limiter is atomic", () => {
  const r = () => helpers.req({ ip: freshIp() });
  test("SET NX EX / INCR / TTL go through /multi-exec and keep a TTL", async () => {
    const out = await rateLimit(r(), { bucket: "t", limit: 2, windowSec: 60, scope: "global" });
    assert.equal(out.ok, true);
    assert.deepEqual(helpers.endpointLog, ["/multi-exec"]);
    assert.deepEqual(helpers.redisLog.map((c) => c[0]), ["SET", "INCR", "TTL"]);
    assert.ok(db.get("site:rl:t:all").exp > Date.now());
  });
  test("TTL < 0 sends EXPIRE key windowSec", async () => {
    db.set("site:rl:t:all", { v: "3", exp: 0 }); // stuck key without TTL
    const out = await rateLimit(r(), { bucket: "t", limit: 10, windowSec: 60, scope: "global" });
    assert.equal(out.ok, true);
    assert.ok(helpers.redisLog.some((c) => c[0] === "EXPIRE" && c[1] === "site:rl:t:all" && c[2] === "60"));
    assert.ok(db.get("site:rl:t:all").exp > Date.now());
  });
  for (const [label, reply] of [
    ["per-command error", () => [{ result: "OK" }, { error: "ERR boom" }, { result: 60 }]],
    ["discarded transaction", () => ({ error: "ERR discarded" })],
    ["short reply", () => [{ result: "OK" }]],
  ]) {
    test(`${label}: fails closed, or open with failOpen`, async () => {
      helpers.setMultiOverride(reply);
      const closed = await rateLimit(r(), { bucket: "t", limit: 10, windowSec: 60 });
      assert.equal(closed.ok, false);
      assert.equal(closed.error, true);
      const open = await rateLimit(r(), { bucket: "t", limit: 10, windowSec: 60, failOpen: true });
      assert.equal(open.ok, true);
    });
  }
  test("login lockout counters also use /multi-exec and always have a TTL", async () => {
    await login(freshIp(), "wrong");
    assert.ok(helpers.endpointLog.includes("/multi-exec"));
    const lockKeys = [...db.keys()].filter((k) => k.startsWith("site:lock:admin:"));
    assert.equal(lockKeys.length, 2);
    for (const k of lockKeys) assert.ok(db.get(k).exp > Date.now(), k);
  });
  test("a lockout counter stuck without TTL gets one back", async () => {
    db.set("site:lock:admin:all", { v: String(LOCKOUT.global), exp: 0 });
    assert.equal((await login(freshIp())).statusCode, 429);
    assert.ok(db.get("site:lock:admin:all").exp > Date.now());
  });
});

describe("22. media locked to our own Blob store", () => {
  test("store host derived from BLOB_READ_WRITE_TOKEN like @vercel/blob", () => {
    assert.equal(blobStoreHost(), "teststore.public.blob.vercel-storage.com");
  });
  test("own store /testimonials/ URL accepted on submit", async () => {
    assert.equal((await submit({ media: OWN })).statusCode, 200);
  });
  for (const [label, url] of [
    ["another store", OWN.replace("teststore", "otherstore")],
    ["http", OWN.replace("https:", "http:")],
    ["wrong path", OWN.replace("/testimonials/", "/other/")],
    ["path traversal", "https://teststore.public.blob.vercel-storage.com/testimonials/../x.jpg"],
    ["credentials", OWN.replace("https://", "https://u:p@")],
    ["port", OWN.replace(".com/", ".com:8443/")],
    ["lookalike host", OWN.replace("teststore.public", "teststore.public.blob.vercel-storage.com.evil")],
  ]) {
    test(`rejects ${label}`, async () => {
      assert.equal(isOwnBlobUrl(url), false);
      assert.equal((await submit({ media: url })).statusCode, 400);
    });
  }
  for (const [label, token] of [["missing", undefined], ["malformed", "not-a-token"], ["bad store id", "vercel_blob_rw_te.st_x"]]) {
    test(`${label} token: no media accepted (fail closed)`, async () => {
      if (token === undefined) delete process.env.BLOB_READ_WRITE_TOKEN;
      else process.env.BLOB_READ_WRITE_TOKEN = token;
      assert.equal(blobStoreHost(), "");
      assert.equal(isOwnBlobUrl(OWN), false);
      assert.equal((await submit({ media: OWN })).statusCode, 400);
    });
  }
  test("wall drops media from other stores; admin shows it as text with exact-host CSP", async () => {
    const other = OWN.replace("teststore", "otherstore");
    const mk = (id, media) => JSON.stringify({ id, at: `2026-01-0${id.slice(-1)}T00:00:00Z`, name: id, message: "Great app!", email: "x@example.com", rating: 5, consent: true, media });
    db.set("site:reviews", { v: [mk("r_1", other), mk("r_2", OWN)] });
    db.set("site:reviews:status", { v: new Map([["r_1", "approved"], ["r_2", "approved"]]) });
    const wall = (await call(testimonials, {})).body.testimonials;
    assert.equal(wall.find((t) => t.name === "r_1").media, "");
    assert.equal(wall.find((t) => t.name === "r_2").media, OWN);
    const cookie = await session();
    const page = await call(reviews, { headers: { cookie } });
    assert.ok(!page.body.includes(`src="${other}"`));
    assert.ok(page.body.includes(other), "shown as escaped text");
    assert.ok(page.body.includes(`<img src="${OWN}"`));
    const csp = page.headers["content-security-policy"];
    assert.match(csp, /img-src 'self' data: https:\/\/teststore\.public\.blob\.vercel-storage\.com(;|$)/);
    assert.match(csp, /media-src https:\/\/teststore\.public\.blob\.vercel-storage\.com(;|$)/);
    assert.doesNotMatch(csp, /\*\./);
  });
  test("admin CSP allows no Blob host when the token is missing", async () => {
    const cookie = await session();
    delete process.env.BLOB_READ_WRITE_TOKEN;
    const csp = (await call(reviews, { headers: { cookie } })).headers["content-security-policy"];
    assert.match(csp, /media-src 'none'/);
    assert.doesNotMatch(csp, /vercel-storage/);
  });
});

describe("23. sign-ups admin page", () => {
  test(`shows the real cap (${FREE_OFFER_CAP}) and every sport`, async () => {
    const cookie = await session();
    const page = await call(signups, { headers: { cookie } });
    assert.equal(page.statusCode, 200);
    assert.match(page.body, /— 0 \/ 1000<\/h1>/);
    assert.equal(Object.keys(APPS).length, 10);
    for (const s of Object.keys(APPS)) assert.ok(page.body.includes(`</b>${s}</div>`), s);
  });
  test("register uses the same cap", async () => {
    assert.equal((await call(register, {})).body.cap, FREE_OFFER_CAP);
  });
});
