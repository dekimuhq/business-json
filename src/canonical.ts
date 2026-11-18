import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

/**
 * RFC 8785 (JCS) canonical form for the JSON values this spec uses: objects,
 * arrays, strings, booleans, null and finite numbers. Keys sort by UTF-16 code
 * units (the JS default sort), and ECMAScript number serialisation is exactly
 * the form JCS §3.2.2.3 requires. Any other value (undefined, NaN, a function)
 * is a caller bug and throws.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JCS: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
  }
  throw new TypeError(`JCS: unsupported value of type ${typeof value}`);
}

/** `sha256:<hex>` of the JCS form — the `profileDigest` a binding record carries. */
export function profileDigest(doc: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalize(doc), "utf8").digest("hex")}`;
}

/** The bytes a verifier signs: the JCS form of the record with `sig` removed. */
export function signingInput(record: Readonly<Record<string, unknown>>): Buffer {
  const { sig: _sig, ...unsigned } = record;
  return Buffer.from(canonicalize(unsigned), "utf8");
}

/** Verify an ed25519 signature given the raw public key as base64url (JWK `x`). */
export function verifyEd25519(message: Buffer, signatureB64url: string, xB64url: string): boolean {
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: xB64url }, format: "jwk" });
    return edVerify(null, message, key, Buffer.from(signatureB64url, "base64url"));
  } catch {
    return false;
  }
}

/** Value of the `_business-json.<domain>` TXT record that binds a domain to a VAT. */
export function dnsRecordValue(vat: string): string {
  return `v=bj1; vat=${vat}`;
}

/** Parse a TXT value written as `v=bj1; vat=…`. Returns the VAT, or null if not a bj1 record. */
export function parseDnsRecord(txt: string): string | null {
  const fields = new Map<string, string>();
  for (const part of txt.split(";")) {
    const m = part.trim().match(/^([a-z]+)=(.*)$/);
    if (m) fields.set(m[1], m[2].trim());
  }
  if (fields.get("v") !== "bj1") return null;
  return fields.get("vat") ?? null;
}
