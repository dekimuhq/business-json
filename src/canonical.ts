import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

/** True when a string holds an unpaired UTF-16 surrogate (not valid Unicode; RFC 8785 §3.2.2.2 forbids it). */
function hasLoneSurrogate(s: string): boolean {
  return /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

/**
 * RFC 8785 (JCS) canonical form for JSON values: objects, arrays, strings,
 * booleans, null and finite numbers. Keys sort by UTF-16 code units (the JS
 * default comparison), and ECMAScript number serialisation is exactly the form
 * JCS §3.2.2.3 requires. Anything else — undefined inside an array, NaN, a Date,
 * a lone surrogate — is not JSON and throws.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    if (hasLoneSurrogate(value)) throw new TypeError("JCS: lone surrogate in string");
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JCS: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${canonicalize(k)}:${canonicalize(v)}`).join(",")}}`;
  }
  throw new TypeError(`JCS: unsupported value ${Object.prototype.toString.call(value)}`);
}

/** `sha256:<hex>` of the JCS form — the `profileDigest` a binding record carries. Hash the document as served, not a parsed copy. */
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

/**
 * Parse a TXT value (SPEC §2 grammar: `;`-separated `key=value` fields, lower-case
 * keys, each key at most once). Returns null when the record is not `v=bj1`.
 * A bj1 record that is malformed (repeated key, no `vat`) comes back with `vat: null`
 * so the caller still counts it toward "exactly one bj1 record".
 */
export function parseDnsRecord(txt: string): { vat: string | null } | null {
  const fields = new Map<string, string>();
  let repeated = false;
  for (const part of txt.split(";")) {
    const m = part.trim().match(/^([a-z]+)=(.*)$/);
    if (!m) continue;
    if (fields.has(m[1])) repeated = true;
    fields.set(m[1], m[2].trim());
  }
  if (fields.get("v") !== "bj1") return null;
  return { vat: repeated ? null : (fields.get("vat") ?? null) };
}
