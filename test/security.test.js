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
    const r = await call(review, { method: "POST", ip: freshIp(), body: { ...good, media: "https://abc123.public.blob.vercel-storage.com/testimonials/1.jpg" } });
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
