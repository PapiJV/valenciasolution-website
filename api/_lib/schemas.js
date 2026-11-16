// Server-side validation for every /api payload. Limits match the form
// maxlength attributes in index.html / fr.html / es.html.

import { z } from "zod";
import { APPS } from "./apps.js";

const CTRL = /[\u0000-\u001f\u007f]/g;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// Trimmed single-line text, rejected (not truncated) when over the limit.
const text = (max) =>
  z.preprocess((v) => (v == null ? "" : v), z.string().transform((s) => s.replace(CTRL, " ").trim()).pipe(z.string().max(max)));

// Analytics-only fields: never rejected, cut to size.
const tag = (max) =>
  z.preprocess((v) => (typeof v === "string" ? v : ""), z.string().transform((s) => s.replace(CTRL, " ").trim().slice(0, max)));

const email = z.string().trim().toLowerCase().max(120).regex(EMAIL_RE);
const sport = z.string().trim().toLowerCase().refine((s) => Object.hasOwn(APPS, s), "unknown sport");

// Only files our own Blob store issued (see /api/upload).
export const BLOB_HOST_RE = /^[a-z0-9]+\.public\.blob\.vercel-storage\.com$/;
const blobUrl = z
  .string()
  .max(500)
  .refine((u) => {
    try {
      const x = new URL(u);
      return x.protocol === "https:" && BLOB_HOST_RE.test(x.hostname) && x.pathname.startsWith("/testimonials/");
    } catch {
      return false;
    }
  }, "media must be an uploaded file");

export const ReviewSchema = z.object({
  name: text(80).pipe(z.string().min(1)),
  role: text(80),
  club: text(100),
  product: text(40),
  headline: text(90),
  message: z.preprocess((v) => (v == null ? "" : v), z.string().trim().min(10).max(800)),
  email,
  media: z.union([z.literal(""), blobUrl]).default(""),
  rating: z.coerce.number().int().min(1).max(5),
  consent: z.boolean().default(false),
  access: z.enum(["purchased", "free", ""]).default(""),
});

export const RegisterSchema = z.object({
  sport,
  name: text(80).pipe(z.string().min(1)),
  email,
  role: text(80),
  club: text(100),
  city: text(80),
  website: tag(200),
  marketingOptIn: z.boolean().default(false),
  source: tag(40).transform((s) => s.toLowerCase().replace(/[^a-z0-9._-]/g, "")),
  referrer: tag(100).transform((s) => s.toLowerCase()),
});

export const ActivateSchema = z.object({
  token: z.string().min(10).max(2000),
  device: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/),
});

export const ReviewStatusSchema = z.object({
  id: z.string().min(1).max(80),
  action: z.enum(["approve", "hide", "pending"]),
});

export const AdminLoginSchema = z.object({
  key: z.string().max(512).default(""),
  next: z.string().max(40).optional(),
  logout: z.string().max(4).optional(),
});

const LID = z.string().regex(/^[A-Za-z0-9_-]{6,40}$/);
export const LicenseActionSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("revoke"), lid: LID }),
  z.object({ action: z.literal("restore"), lid: LID }),
  z.object({ action: z.literal("enforce"), lid: z.enum(["on", "off"]) }),
  z.object({
    action: z.literal("issue"),
    app: sport,
    tier: z.enum(["comp", "individual", "club"]).default("comp"),
    note: text(80),
  }),
]);

export const QrSchema = z.object({
  club: text(60).pipe(z.string().min(1)),
  sport: z.union([z.literal(""), sport]).default(""),
  lang: z.enum(["en", "fr", "es"]).default("en"),
});

// Parse a Vercel request body (object, JSON string or urlencoded string).
export function bodyOf(req) {
  let b = req.body;
  if (typeof b === "string") {
    try {
      b = JSON.parse(b);
    } catch {
      b = Object.fromEntries(new URLSearchParams(b));
    }
  }
  return b && typeof b === "object" && !Array.isArray(b) ? b : {};
}

export function parse(schema, req, defaults = {}) {
  const r = schema.safeParse({ ...defaults, ...bodyOf(req) });
  return r.success ? { ok: true, data: r.data } : { ok: false, issues: r.error.issues.map((i) => i.path.join(".") || "body") };
}
