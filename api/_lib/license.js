// Offline-verifiable Notepad licences.
//
// Token: "VS1.<base64url(JSON payload)>.<base64url(ECDSA P-256 sig, raw r||s)>"
// The signature covers "VS1.<payload>". Apps embed the public key and verify
// with WebCrypto, so no network or cloud account is needed after first open.
//
// Env: LICENSE_PRIVATE_KEY = PKCS#8 PEM (literal "\n" sequences are accepted).

import crypto from "node:crypto";

const PREFIX = "VS1";
const TIERS = new Set(["individual", "club", "free", "comp"]);

function privateKey() {
  const pem = String(process.env.LICENSE_PRIVATE_KEY || "").replace(/\\n/g, "\n").trim();
  if (!pem) throw new Error("LICENSE_NOT_CONFIGURED");
  return crypto.createPrivateKey(pem);
}

const b64u = (buf) => Buffer.from(buf).toString("base64url");

export function signLicense({ app, tier, ref }) {
  if (!app || !TIERS.has(tier)) throw new Error("BAD_LICENSE_INPUT");
  const payload = {
    v: 1,
    app,
    tier,
    lid: crypto.randomBytes(9).toString("base64url"),
    ref: String(ref || "").slice(0, 80),
    iat: Math.floor(Date.now() / 1000),
  };
  const body = `${PREFIX}.${b64u(JSON.stringify(payload))}`;
  const sig = crypto.sign("sha256", Buffer.from(body), { key: privateKey(), dsaEncoding: "ieee-p1363" });
  return { token: `${body}.${b64u(sig)}`, payload };
}
