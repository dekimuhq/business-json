import { describe, expect, it } from "vitest";
import { canonicalize, dnsRecordValue, parseDnsRecord, profileDigest } from "./canonical.js";
import { organizationIdentifierMatches, organizationIdentifiersFor } from "./identity.js";
import { parseBindingRecord, parseBusinessJson } from "./parse.js";
import { makeDoc, makeRecord } from "./test-helpers.js";

const signed = (r: Record<string, unknown>) => ({ ...r, sig: { alg: "ed25519", kid: "k1", value: "A".repeat(86) } });

describe("business.json schema", () => {
  it("accepts a minimal document", () => {
    expect(parseBusinessJson(makeDoc()).ok).toBe(true);
  });

  it.each([
    ["lower-case VAT", { vat: "esb12345678" }],
    ["VAT with separators", { vat: "ES-B12345678" }],
    ["GR instead of the VIES EL prefix", { vat: "GR123456789" }],
    ["upper-case domain", { domains: ["Acme.example"] }],
    ["Unicode domain (must be an A-label)", { domains: ["acmé.example"] }],
    ["repeated domain", { domains: ["acme.example", "acme.example"] }],
    ["http binding URL", { binding: "http://verify.test/b" }],
  ])("rejects %s", (_label, override) => {
    expect(parseBusinessJson({ ...makeDoc(), ...override }).ok).toBe(false);
  });

  it("rejects unknown top-level keys", () => {
    expect(parseBusinessJson({ ...makeDoc(), iban: "ES00" }).ok).toBe(false);
  });

  it("accepts an IDN as an A-label", () => {
    expect(parseBusinessJson(makeDoc({ domains: ["xn--acm-bla.example"] })).ok).toBe(true);
  });
});

describe("binding record schema", () => {
  it("accepts an authority record", () => {
    expect(parseBindingRecord(signed(makeRecord(makeDoc())))).toMatchObject({ ok: true });
  });

  it("rejects the self-declared level (removed in review)", () => {
    expect(parseBindingRecord(signed(makeRecord(makeDoc(), { level: "declared" }))).ok).toBe(false);
  });

  it("rejects a record without authority evidence", () => {
    const r = signed(makeRecord(makeDoc()));
    delete (r as Record<string, unknown>).authority;
    expect(parseBindingRecord(r).ok).toBe(false);
  });

  it("rejects expiresAt beyond the certificate's notAfter", () => {
    const r = parseBindingRecord(signed(makeRecord(makeDoc(), { expiresAt: "2029-01-01T00:00:00Z" })));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/notAfter/);
  });

  it("rejects expiresAt before issuedAt", () => {
    expect(parseBindingRecord(signed(makeRecord(makeDoc(), { expiresAt: "2026-10-01T00:00:00Z" }))).ok).toBe(false);
  });

  it("treats VIES as optional", () => {
    const withVies = makeRecord(makeDoc(), { vies: { valid: true, name: "ACME EJEMPLO SL", checkedAt: "2026-11-01T10:00:00Z" } });
    expect(parseBindingRecord(signed(withVies)).ok).toBe(true);
  });
});

describe("JCS", () => {
  it("sorts keys recursively and drops undefined", () => {
    expect(canonicalize({ b: 1, a: { d: [true, null], c: "x" }, u: undefined })).toBe('{"a":{"c":"x","d":[true,null]},"b":1}');
  });

  it("matches RFC 8785 number and escape forms", () => {
    expect(canonicalize({ n: 1e21, f: 0.000001, s: "€\n" })).toBe('{"f":0.000001,"n":1e+21,"s":"€\\n"}');
  });

  it("throws on non-finite numbers", () => {
    expect(() => canonicalize({ n: Number.NaN })).toThrow();
  });

  it("gives the same digest regardless of key order", () => {
    expect(profileDigest({ a: 1, b: 2 })).toBe(profileDigest({ b: 2, a: 1 }));
  });
});

describe("DNS record", () => {
  it("round-trips", () => {
    expect(parseDnsRecord(dnsRecordValue("ESB12345678"))).toBe("ESB12345678");
  });

  it("ignores non-bj1 records", () => {
    expect(parseDnsRecord("v=spf1 include:_spf.example ~all")).toBeNull();
  });
});

describe("organizationIdentifier", () => {
  it("accepts EL and GR for Greece", () => {
    expect(organizationIdentifiersFor("EL123456789")).toEqual(["VATEL-123456789", "VATGR-123456789"]);
    expect(organizationIdentifierMatches("EL123456789", "vatgr-123456789")).toBe(true);
  });

  it("rejects NTR and other-country identifiers", () => {
    expect(organizationIdentifierMatches("ESB12345678", "NTRES-B12345678")).toBe(false);
    expect(organizationIdentifierMatches("ESB12345678", "VATPT-B12345678")).toBe(false);
  });
});
