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

// Server-side check of a token this site issued (same key pair as signing).
export function verifyLicenseToken(token) {
  try {
    const parts = String(token || "").trim().split(".");
    if (parts.length !== 3 || parts[0] !== PREFIX) return null;
    const ok = crypto.verify(
      "sha256",
      Buffer.from(`${parts[0]}.${parts[1]}`),
      { key: crypto.createPublicKey(privateKey()), dsaEncoding: "ieee-p1363" },
      Buffer.from(parts[2], "base64url")
    );
    if (!ok) return null;
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return payload && payload.v === 1 && payload.lid ? payload : null;
  } catch {
    return null;
  }
}

// Device tracking (Upstash):
//   site:lic:meta            HASH lid -> {app, tier, who, at}
//   site:lic:dev:<lid>       HASH deviceId -> ISO last seen
//   site:lic:revoked         SET  lid
//   site:lic:enforce         STRING "on" when device limits are enforced
export const DEVICE_LIMITS = { individual: 4, club: 30, free: 2, comp: 30 };

export function metaCommand(payload, who) {
  return [
    "HSET", "site:lic:meta", payload.lid,
    JSON.stringify({ app: payload.app, tier: payload.tier, who: String(who || payload.ref || "").slice(0, 80), at: new Date().toISOString() }),
  ];
}
