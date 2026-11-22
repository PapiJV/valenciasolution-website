// Test doubles: an in-memory Upstash REST store, a Stripe stub, and
// Vercel-style req/res objects. No network is used.

import crypto from "node:crypto";

export const REDIS_URL = "https://redis.test";
export const ADMIN_KEY = "test-admin-key-0123456789abcdef";
export const HOST = "www.valenciasolution.net";
export const ORIGIN = `https://${HOST}`;

const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
export const LICENSE_PEM = privateKey.export({ type: "pkcs8", format: "pem" });

export function setEnv() {
  process.env.KV_REST_API_URL = REDIS_URL;
  process.env.KV_REST_API_TOKEN = "t";
  process.env.REVIEWS_ADMIN_KEY = ADMIN_KEY;
  process.env.LICENSE_PRIVATE_KEY = LICENSE_PEM;
  process.env.STRIPE_SECRET_KEY = "sk_test_dummy";
  process.env.BLOB_READ_WRITE_TOKEN = "vercel_blob_rw_teststore_secretpart";
}

// ---- in-memory Redis ----
export const db = new Map(); // key -> { v, exp }
export const redisLog = [];
export const endpointLog = []; // "/pipeline" | "/multi-exec" | "/" per request
let redisDown = false;
export const setRedisDown = (v) => { redisDown = v; };
// Commands named here answer {error} (per-command failure).
export const failCommands = new Set();
// When set, /multi-exec answers with this function's return value instead.
let multiOverride = null;
export const setMultiOverride = (fn) => { multiOverride = fn; };

function live(k) {
  const e = db.get(k);
  if (!e) return undefined;
  if (e.exp && e.exp <= Date.now()) { db.delete(k); return undefined; }
  return e;
}
const get = (k, init) => { let e = live(k); if (!e) { e = { v: init() }; db.set(k, e); } return e; };

function run([cmd, ...a]) {
  redisLog.push([cmd, ...a]);
  const C = cmd.toUpperCase();
  switch (C) {
    case "SET": {
      const [k, v, ...opt] = a;
      const nx = opt.includes("NX");
      if (nx && live(k)) return null;
      const i = opt.indexOf("EX");
      db.set(k, { v: String(v), exp: i >= 0 ? Date.now() + Number(opt[i + 1]) * 1000 : 0 });
      return "OK";
    }
    case "GET": { const e = live(a[0]); return e ? e.v : null; }
    case "INCR": { const e = get(a[0], () => "0"); e.v = String(Number(e.v) + 1); return Number(e.v); }
    case "TTL": { const e = live(a[0]); return !e ? -2 : e.exp ? Math.ceil((e.exp - Date.now()) / 1000) : -1; }
    case "DEL": return a.reduce((n, k) => n + (db.delete(k) ? 1 : 0), 0);
    case "EXISTS": return live(a[0]) ? 1 : 0;
    case "SADD": { const s = get(a[0], () => new Set()).v; let n = 0; for (const m of a.slice(1)) if (!s.has(m)) { s.add(m); n++; } return n; }
    case "SREM": { const e = live(a[0]); return e && e.v.delete(a[1]) ? 1 : 0; }
    case "SCARD": { const e = live(a[0]); return e ? e.v.size : 0; }
    case "SISMEMBER": { const e = live(a[0]); return e && e.v.has(a[1]) ? 1 : 0; }
    case "SMEMBERS": { const e = live(a[0]); return e ? [...e.v] : []; }
    case "RPUSH": { const l = get(a[0], () => []).v; l.push(...a.slice(1)); return l.length; }
    case "LTRIM": {
      const e = live(a[0]); if (!e) return "OK";
      const n = e.v.length, st = Number(a[1]) < 0 ? Math.max(0, n + Number(a[1])) : Number(a[1]);
      const en = Number(a[2]) < 0 ? n + Number(a[2]) : Number(a[2]);
      e.v = e.v.slice(st, en + 1); return "OK";
    }
    case "LRANGE": {
      const e = live(a[0]); if (!e) return [];
      const n = e.v.length, st = Number(a[1]) < 0 ? Math.max(0, n + Number(a[1])) : Number(a[1]);
      const en = Number(a[2]) < 0 ? n + Number(a[2]) : Number(a[2]);
      return e.v.slice(st, en + 1);
    }
    case "HSET": { const h = get(a[0], () => new Map()).v; let n = 0; for (let i = 1; i + 1 < a.length; i += 2) { if (!h.has(a[i])) n++; h.set(a[i], String(a[i + 1])); } return n; }
    case "EXPIRE": { const e = live(a[0]); if (!e) return 0; e.exp = Date.now() + Number(a[1]) * 1000; return 1; }
    case "HGET": { const e = live(a[0]); return e && e.v.has(a[1]) ? e.v.get(a[1]) : null; }
    case "HDEL": { const e = live(a[0]); return e && e.v.delete(a[1]) ? 1 : 0; }
    case "HEXISTS": { const e = live(a[0]); return e && e.v.has(a[1]) ? 1 : 0; }
    case "HLEN": { const e = live(a[0]); return e ? e.v.size : 0; }
    case "HGETALL": { const e = live(a[0]); return e ? [...e.v].flat() : []; }
    default: throw new Error(`fake redis: ${C} not implemented`);
  }
}

// ---- Stripe stub ----
export const stripeSessions = new Map();

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (u.startsWith(REDIS_URL)) {
    if (redisDown) return json(503, { error: "down" });
    const body = JSON.parse(opts.body);
    const one = (c) => {
      if (failCommands.has(String(c[0]).toUpperCase())) { redisLog.push(c); return { error: "ERR injected" }; }
      return { result: run(c) };
    };
    if (u.endsWith("/pipeline")) { endpointLog.push("/pipeline"); return json(200, body.map(one)); }
    if (u.endsWith("/multi-exec")) {
      endpointLog.push("/multi-exec");
      if (multiOverride) { body.forEach((c) => redisLog.push(c)); return json(200, multiOverride(body)); }
      return json(200, body.map(one));
    }
    endpointLog.push("/");
    const r = one(body);
    return json(r.error ? 400 : 200, r);
  }
  if (u.startsWith("https://api.stripe.com/v1/checkout/sessions/")) {
    const id = decodeURIComponent(u.split("/").pop().split("?")[0]);
    const s = stripeSessions.get(id);
    return s ? json(200, s) : json(404, { error: { message: "No such session" } });
  }
  throw new Error(`unexpected fetch in test: ${u}`);
};

export function reset() {
  db.clear();
  redisLog.length = 0;
  endpointLog.length = 0;
  failCommands.clear();
  multiOverride = null;
  stripeSessions.clear();
  redisDown = false;
}

// ---- Vercel-style req/res ----
let ipSeq = 0;
export const freshIp = () => `10.0.${(ipSeq >> 8) & 255}.${ipSeq++ & 255}`;

export function req({ method = "GET", query = {}, headers = {}, body, ip = "203.0.113.9", origin = ORIGIN } = {}) {
  const h = { host: HOST, "x-forwarded-for": ip, ...headers };
  if (origin && method !== "GET") h.origin = origin;
  return { method, query, headers: h, body, socket: { remoteAddress: ip } };
}

export function res() {
  const r = {
    statusCode: 200, headers: {}, body: undefined, ended: false,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; return this; },
    getHeader(k) { return this.headers[k.toLowerCase()]; },
    status(c) { this.statusCode = c; return this; },
    json(o) { this.body = o; this.ended = true; return this; },
    send(s) { this.body = s; this.ended = true; return this; },
    end() { this.ended = true; return this; },
    redirect(c, loc) { this.statusCode = c; this.headers.location = loc; this.ended = true; return this; },
  };
  return r;
}

export async function call(handler, opts) {
  const r = res();
  await handler(req(opts), r);
  return r;
}

export const cookieValue = (setCookie, name) => {
  const m = new RegExp(`${name}=([^;]*)`).exec(String(setCookie || ""));
  return m ? m[1] : "";
};
