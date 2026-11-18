/**
 * Shared test helpers — imported only by *.test.ts files.
 * Not compiled into dist (excluded via tsconfig exclude).
 */
import { generateKeyPairSync, sign } from "node:crypto";
import { profileDigest, signingInput } from "./canonical.js";
import type { BusinessJson, VerifierKey } from "./schema.js";

export function mockFetch(map: Record<string, { status: number; body: string }>): typeof fetch {
  return (async (input: string | URL) => {
    const url = typeof input === "string" ? input : input.href;
    const hit = map[url];
    if (!hit) return { ok: false, status: 404, text: async () => "" } as Response;
    return {
      ok: hit.status >= 200 && hit.status < 300,
      status: hit.status,
      text: async () => hit.body,
      json: async () => JSON.parse(hit.body),
    } as Response;
  }) as typeof fetch;
}

export interface TestVerifier {
  origin: string;
  key: VerifierKey;
  sign(record: Record<string, unknown>): Record<string, unknown>;
}

export function makeVerifier(origin: string, kid = "k1"): TestVerifier {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const x = publicKey.export({ format: "jwk" }).x as string;
  const key: VerifierKey = { kid, alg: "ed25519", x };
  return {
    origin,
    key,
    sign(record) {
      const unsigned = { ...record };
      delete unsigned.sig;
      const value = sign(null, signingInput(unsigned), privateKey).toString("base64url");
      return { ...unsigned, sig: { alg: "ed25519", kid, value } };
    },
  };
}

export const DOMAIN = "acme.example";
export const VAT = "ESB12345678";

export function makeDoc(overrides: Partial<BusinessJson> = {}): BusinessJson {
  return {
    businessJsonVersion: "0.1",
    legalName: "Acme Ejemplo, S.L.",
    vat: VAT,
    address: { street: "Calle Mayor 1", postalCode: "28001", locality: "Madrid", country: "ES" },
    domains: [DOMAIN],
    contact: { email: "hola@acme.example" },
    binding: `https://verify.test/b/${VAT}/binding.json`,
    ...overrides,
  };
}

export function makeRecord(doc: BusinessJson, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    bindingRecordVersion: "0.1",
    verifier: "https://verify.test",
    vat: doc.vat,
    level: "authority",
    authority: {
      method: "qseal",
      organizationIdentifier: `VAT${doc.vat.slice(0, 2)}-${doc.vat.slice(2)}`,
      certificatePolicies: ["0.4.0.194112.1.3"],
      certificateSha256: "a".repeat(64),
      certificateNotAfter: "2028-01-01T00:00:00Z",
      signedAt: "2026-11-01T10:00:00Z",
      revocationCheckedAt: "2026-11-01T10:00:05Z",
    },
    domains: doc.domains.map((domain) => ({ domain, dnsCheckedAt: "2026-11-01T10:01:00Z" })),
    profileDigest: profileDigest(doc),
    issuedAt: "2026-11-01T10:02:00Z",
    expiresAt: "2027-02-01T10:02:00Z",
    ...overrides,
  };
}

export const NOW = new Date("2026-11-18T12:00:00Z");

export function goodTxt(vat = VAT): (name: string) => Promise<string[][]> {
  return async (name) => {
    if (name === `_business-json.${DOMAIN}`) return [[`v=bj1; vat=${vat}`]];
    throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  };
}

export const noCname = async (): Promise<string[]> => {
  throw Object.assign(new Error("no data"), { code: "ENODATA" });
};
