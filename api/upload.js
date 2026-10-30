// Issues short-lived Vercel Blob client-upload tokens for testimonial
// photos/videos. The browser uploads the file straight to Blob storage
// (js/blob-upload.js -> upload()), so files skip the 4.5MB serverless
// request-body limit; this route only ever sees small JSON handshakes.
//
// Env: BLOB_READ_WRITE_TOKEN (set automatically when a Blob store is
// connected to the Vercel project).
//
// js/blob-upload.js is a browser bundle of @vercel/blob/client. Rebuild it
// after bumping @vercel/blob in package.json:
//   echo "export { upload } from '@vercel/blob/client';" > e.mjs
//   npx esbuild e.mjs --bundle --platform=browser --format=esm --minify \
//     --target=es2019 --banner:js="var process=globalThis.process||{env:{},versions:{}};" \
//     --outfile=js/blob-upload.js && rm e.mjs

import { rateLimit, sameOrigin, tooMany } from "./_lib/security.js";

const MAX_BYTES = 100 * 1024 * 1024; // keep in sync with MEDIA_MAX_MB in index.html

// Caps so nobody can fill the Blob store (and the bill). Both fail closed.
const PER_VISITOR_PER_HOUR = 3;
const SITE_WIDE_PER_DAY = 25;
const TOKEN_TTL_MS = 30 * 60 * 1000;

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: "Method not allowed." });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = null;
    }
  }
  // Only browser token requests are accepted. There is no upload-completed
  // callback, so any other event type is rejected.
  if (!body || body.type !== "blob.generate-client-token") {
    res.status(400).json({ error: "Invalid upload request." });
    return;
  }
  if (!sameOrigin(req)) {
    res.status(403).json({ error: "Forbidden." });
    return;
  }
  const perVisitor = await rateLimit(req, { bucket: "upload", limit: PER_VISITOR_PER_HOUR, windowSec: 3600 });
  if (!perVisitor.ok) {
    tooMany(res, perVisitor, "Upload limit reached. Please try again in an hour.");
    return;
  }
  const siteWide = await rateLimit(req, { bucket: "upload", limit: SITE_WIDE_PER_DAY, windowSec: 86400, scope: "global" });
  if (!siteWide.ok) {
    tooMany(res, siteWide, "Uploads are paused for today. Please submit without media or try tomorrow.");
    return;
  }

  try {
    const { handleUpload } = await import("@vercel/blob/client");
    const result = await handleUpload({
      body,
      request: req,
      onBeforeGenerateToken: async (pathname) => {
        if (!/^testimonials\//.test(pathname)) throw new Error("BAD_PATH");
        return {
          allowedContentTypes: ["image/*", "video/*"],
          maximumSizeInBytes: MAX_BYTES,
          addRandomSuffix: true,
          validUntil: Date.now() + TOKEN_TTL_MS,
        };
      },
    });
    res.status(200).json(result);
  } catch (e) {
    res.status(400).json({ error: "Upload failed." });
  }
}
