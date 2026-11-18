import { describe, expect, it } from "vitest";
import { canonicalize, dnsRecordValue, parseDnsRecord, profileDigest } from "./canonical.js";
import { organizationIdentifierMatches, organizationIdentifiersFor } from "./identity.js";
import { parseBindingRecord, parseBusinessJson, parseVerifierMetadata } from "./parse.js";
import { makeDoc, makeRecord, makeVerifier } from "./test-helpers.js";
import { legalNameKey } from "./validate.js";

const signed = (r: Record<string, unknown>) => makeVerifier("https://verify.test").sign(r);

function error(r: { ok: boolean; error?: string }): string {
  expect(r.ok).toBe(false);
  return r.error ?? "";
}

describe("business.json schema", () => {
  it("accepts a minimal document", () => {
    expect(parseBusinessJson(makeDoc()).ok).toBe(true);
  });

  it("returns the document unchanged (the digest is over what was served)", () => {
    const doc = { ...makeDoc(), contact: { email: "hola@acme.example", url: "https://acme.example/contact" } };
    const r = parseBusinessJson(doc);
    expect(r.ok && r.value).toEqual(doc);
  });

  it.each([
    ["lower-case VAT", { vat: "esb12345678" }, /vat must be/],
    ["VAT with separators", { vat: "ES-B12345678" }, /vat must be/],
    ["GR instead of the VIES EL prefix", { vat: "GR123456789" }, /vat must be/],
    ["upper-case domain", { domains: ["Acme.example"] }, /lower-case ASCII hostname/],
    ["Unicode domain (must be an A-label)", { domains: ["acmé.example"] }, /lower-case ASCII hostname/],
    ["IPv4 literal domain", { domains: ["10.0.0.5"] }, /lower-case ASCII hostname/],
    ["repeated domain", { domains: ["acme.example", "acme.example"] }, /must not repeat/],
    ["http binding URL", { binding: "http://verify.test/b" }, /https URL/],
    ["binding URL with a trailing newline", { binding: "https://verify.test/b\n" }, /https URL/],
    ["legalName with a line break", { legalName: "Acme\nBOUND: paypal.com" }, /control/],
    ["legalName with an ANSI escape", { legalName: "Acme\u001b[2J" }, /control/],
    ["legalName with a bidi override", { legalName: "Acme ‮LS" }, /bidi/],
  ])("rejects %s", (_label, override, message) => {
    expect(error(parseBusinessJson({ ...makeDoc(), ...override }))).toMatch(message);
  });

  it("rejects unknown top-level keys", () => {
    expect(error(parseBusinessJson({ ...makeDoc(), iban: "ES00" }))).toMatch(/iban/);
  });

  it("rejects __proto__ keys without polluting", () => {
    const evil = JSON.parse(`{"__proto__":{"polluted":1},${JSON.stringify(makeDoc()).slice(1)}`);
    expect(parseBusinessJson(evil).ok).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("accepts an IDN as an A-label", () => {
    expect(parseBusinessJson(makeDoc({ domains: ["xn--acm-dma.example"] })).ok).toBe(true);
  });
});

describe("binding record schema", () => {
  it("accepts an authority record", () => {
    expect(parseBindingRecord(signed(makeRecord(makeDoc()))).ok).toBe(true);
  });

  it("rejects the self-declared level (removed in review)", () => {
    expect(error(parseBindingRecord(signed(makeRecord(makeDoc(), { level: "declared" }))))).toMatch(/level/);
  });

  it("rejects a record without authority evidence", () => {
    const r = signed(makeRecord(makeDoc()));
    delete r.authority;
    expect(error(parseBindingRecord(r))).toMatch(/authority/);
  });

  it("rejects a record without the certificate organizationName", () => {
    const base = makeRecord(makeDoc());
    const { organizationName: _n, ...authority } = base.authority as Record<string, unknown>;
    expect(error(parseBindingRecord(signed({ ...base, authority })))).toMatch(/organizationName/);
  });

  it("rejects expiresAt beyond the certificate's notAfter", () => {
    const base = makeRecord(makeDoc());
    const r = { ...base, authority: { ...(base.authority as object), certificateNotAfter: "2026-11-15T00:00:00Z" } };
    expect(error(parseBindingRecord(signed(r)))).toMatch(/notAfter/);
  });

  it("rejects expiresAt before issuedAt", () => {
    expect(error(parseBindingRecord(signed(makeRecord(makeDoc(), { expiresAt: "2026-10-01T00:00:00Z" }))))).toMatch(/after issuedAt/);
  });

  it("rejects a lifetime over 30 days", () => {
    expect(error(parseBindingRecord(signed(makeRecord(makeDoc(), { expiresAt: "2026-12-01T10:02:01Z" }))))).toMatch(/at most 30 days/);
  });

  it("rejects a verifier that is not a bare origin", () => {
    expect(error(parseBindingRecord(signed(makeRecord(makeDoc(), { verifier: "https://verify.test/path" }))))).toMatch(/bare https origin/);
  });

  it("rejects a non-canonical base64url signature spelling", () => {
    // 64 bytes = 86 chars with 4 spare low bits in the last one: flip a spare bit, same bytes.
    const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const r = signed(makeRecord(makeDoc())) as { sig: { value: string } };
    const v = r.sig.value;
    const variant = v.slice(0, -1) + ALPHA[ALPHA.indexOf(v.at(-1)!) ^ 1];
    expect(Buffer.from(variant, "base64url").equals(Buffer.from(v, "base64url"))).toBe(true);
    expect(error(parseBindingRecord({ ...r, sig: { ...r.sig, value: variant } }))).toMatch(/canonical base64url/);
  });

  it("treats VIES as optional", () => {
    const withVies = makeRecord(makeDoc(), { vies: { valid: true, name: "ACME EJEMPLO SL", checkedAt: "2026-11-01T10:00:00Z" } });
    expect(parseBindingRecord(signed(withVies)).ok).toBe(true);
  });
});

describe("verifier metadata schema", () => {
  it("rejects a key that is not 32 bytes", () => {
    const meta = { businessVerifierVersion: "0.1", verifier: "https://verify.test", keys: [{ kid: "k1", alg: "ed25519", x: "AAAA" }] };
    expect(error(parseVerifierMetadata(meta))).toMatch(/32 bytes/);
  });
});

describe("JCS", () => {
  it("sorts keys recursively and drops undefined members", () => {
    expect(canonicalize({ b: 1, a: { d: [true, null], c: "x" }, u: undefined })).toBe('{"a":{"c":"x","d":[true,null]},"b":1}');
  });

  it("sorts by UTF-16 code units, not code points (RFC 8785 §3.2.3)", () => {
    // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FB01 (FB01 > D83D).
    expect(canonicalize({ "ﬁ": 1, "\u{1F600}": 2, "é": 3 })).toBe('{"é":3,"😀":2,"ﬁ":1}');
  });

  it("matches RFC 8785 number forms", () => {
    expect(canonicalize([1e21, 0.000001, 1e-7, -0, 5e-324, 333333333.3333333, 9007199254740992])).toBe(
      "[1e+21,0.000001,1e-7,0,5e-324,333333333.3333333,9007199254740992]",
    );
  });

  it("escapes control characters in lower-case hex and leaves non-ASCII literal", () => {
    expect(canonicalize("\u001f\n\"\\€")).toBe('"\\u001f\\n\\"\\\\€"');
  });

  it.each([
    ["NaN", Number.NaN],
    ["Infinity", Infinity],
    ["a Date", new Date(0)],
    ["a lone surrogate", "\ud800"],
    ["a lone low surrogate in a key", { "\udc00": 1 }],
  ])("throws on %s", (_l, v) => {
    expect(() => canonicalize(v)).toThrow(/JCS/);
  });

  it("gives the same digest regardless of key order", () => {
    expect(profileDigest({ a: 1, b: 2 })).toBe(profileDigest({ b: 2, a: 1 }));
  });
});

describe("DNS record", () => {
  it("round-trips", () => {
    expect(parseDnsRecord(dnsRecordValue("ESB12345678"))).toEqual({ vat: "ESB12345678" });
  });

  it("ignores non-bj1 records", () => {
    expect(parseDnsRecord("v=spf1 include:_spf.example ~all")).toBeNull();
  });

  it("returns vat null for a bj1 record without vat or with a repeated key", () => {
    expect(parseDnsRecord("v=bj1")).toEqual({ vat: null });
    expect(parseDnsRecord("v=bj1; vat=A; vat=B")).toEqual({ vat: null });
  });
});

describe("organizationIdentifier", () => {
  it("accepts EL and GR for Greece, XI and GB for Northern Ireland", () => {
    expect(organizationIdentifiersFor("EL123456789")).toEqual(["VATEL-123456789", "VATGR-123456789"]);
    expect(organizationIdentifierMatches("EL123456789", "vatgr-123456789")).toBe(true);
    expect(organizationIdentifierMatches("XI123456789", "VATGB-123456789")).toBe(true);
  });

  it("rejects NTR and other-country identifiers", () => {
    expect(organizationIdentifierMatches("ESB12345678", "NTRES-B12345678")).toBe(false);
    expect(organizationIdentifierMatches("ESB12345678", "VATPT-B12345678")).toBe(false);
  });
});

describe("legalNameKey", () => {
  it("ignores case, punctuation, spacing and accents but not letters", () => {
    expect(legalNameKey("Ácme Ejemplo, S.L.")).toBe(legalNameKey("ACME EJEMPLO SL"));
    expect(legalNameKey("Acme Ejemplo SL")).not.toBe(legalNameKey("Acme Ejemplos SL"));
  });
});
