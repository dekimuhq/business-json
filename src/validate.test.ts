import { describe, expect, it } from "vitest";
import type { BusinessJson } from "./schema.js";
import {
  DOMAIN, NOW, VAT, goodTxt, makeDoc, makeRecord, makeVerifier, mockFetch, noCname, type TestVerifier,
} from "./test-helpers.js";
import { validateDomain, type ValidateOptions } from "./validate.js";

const DOC_URL = `https://${DOMAIN}/.well-known/business.json`;
const META_URL = "https://verify.test/.well-known/business-verifier.json";

function setup(opts: {
  doc?: BusinessJson;
  record?: Record<string, unknown>;
  verifier?: TestVerifier;
  extra?: Record<string, { status: number; body: string }>;
} = {}): ValidateOptions & { verifier: TestVerifier } {
  const verifier = opts.verifier ?? makeVerifier("https://verify.test");
  const doc = opts.doc ?? makeDoc();
  const record = opts.record ?? verifier.sign(makeRecord(doc));
  return {
    verifier,
    trusted: [{ origin: "https://verify.test" }],
    now: NOW,
    resolveTxt: goodTxt(),
    resolveCname: noCname,
    fetchImpl: mockFetch({
      [DOC_URL]: { status: 200, body: JSON.stringify(doc) },
      [doc.binding]: { status: 200, body: JSON.stringify(record) },
      [META_URL]: {
        status: 200,
        body: JSON.stringify({ businessVerifierVersion: "0.1", verifier: "https://verify.test", keys: [verifier.key] }),
      },
      ...opts.extra,
    }),
  };
}

async function reasons(opts: ValidateOptions): Promise<string[]> {
  const r = await validateDomain(DOMAIN, opts);
  return r.status === "not-bound" ? r.reasons : [];
}

describe("validateDomain", () => {
  it("binds when every check passes", async () => {
    const r = await validateDomain(DOMAIN, setup());
    expect(r.status).toBe("bound");
    if (r.status === "bound") expect(r.record.authority.organizationIdentifier).toBe(`VATES-${VAT.slice(2)}`);
  });

  it("normalises the queried domain (case, trailing dot)", async () => {
    expect((await validateDomain("ACME.example.", setup())).status).toBe("bound");
  });

  it("returns no-profile (unknown) when there is no document", async () => {
    const opts = setup();
    const r = await validateDomain("other.example", opts);
    expect(r.status).toBe("no-profile");
  });

  // Skeptic A1: a document can name any verifier, including one its author runs.
  it("refuses a correctly signed binding from an untrusted verifier", async () => {
    const attacker = makeVerifier("https://evil.test");
    const doc = makeDoc({ binding: `https://evil.test/b/${VAT}` });
    const record = attacker.sign(makeRecord(doc, { verifier: "https://evil.test" }));
    const opts = setup({
      doc,
      record,
      extra: {
        "https://evil.test/.well-known/business-verifier.json": {
          status: 200,
          body: JSON.stringify({ businessVerifierVersion: "0.1", verifier: "https://evil.test", keys: [attacker.key] }),
        },
      },
    });
    expect((await reasons(opts)).join()).toMatch(/not a trusted verifier/);
  });

  it("refuses a record signed by a key the trusted verifier does not publish", async () => {
    const forger = makeVerifier("https://verify.test");
    const record = forger.sign(makeRecord(makeDoc()));
    expect((await reasons(setup({ record }))).join()).toMatch(/signature does not verify/);
  });

  it("refuses a record whose fields were changed after signing", async () => {
    const verifier = makeVerifier("https://verify.test");
    const signed = verifier.sign(makeRecord(makeDoc()));
    const tampered = { ...signed, expiresAt: "2027-12-01T00:00:00Z" };
    expect((await reasons(setup({ verifier, record: tampered }))).join()).toMatch(/signature does not verify/);
  });

  it("uses pinned keys instead of fetching metadata", async () => {
    const opts = setup();
    const pinned = { ...opts, trusted: [{ origin: "https://verify.test", keys: [makeVerifier("x").key] }] };
    expect((await reasons(pinned)).join()).toMatch(/signature does not verify/);
    const good = { ...opts, trusted: [{ origin: "https://verify.test", keys: [opts.verifier.key] }] };
    expect((await validateDomain(DOMAIN, good)).status).toBe("bound");
  });

  it("refuses an unknown kid", async () => {
    const verifier = makeVerifier("https://verify.test", "k-other");
    const opts = setup({ verifier });
    const withOtherKey = { ...opts, trusted: [{ origin: "https://verify.test", keys: [{ ...verifier.key, kid: "k1" }] }] };
    expect((await reasons(withOtherKey)).join()).toMatch(/unknown signing key k-other/);
  });

  it("refuses a key outside its validity window at issuedAt", async () => {
    const opts = setup();
    const retired = { ...opts, trusted: [{ origin: "https://verify.test", keys: [{ ...opts.verifier.key, notAfter: "2026-10-01T00:00:00Z" }] }] };
    expect((await reasons(retired)).join()).toMatch(/not valid at issuedAt/);
  });

  // Skeptic A8: a CNAME at _business-json can point at a name someone else controls.
  it("refuses a TXT record reached through a CNAME", async () => {
    const opts = { ...setup(), resolveCname: async () => ["takeover.saas.example"] };
    expect((await reasons(opts)).join()).toMatch(/is a CNAME/);
  });

  it("refuses when the TXT record names another VAT", async () => {
    const opts = { ...setup(), resolveTxt: goodTxt("ESB99999999") };
    expect((await reasons(opts)).join()).toMatch(/names ESB99999999/);
  });

  it("refuses when there is no TXT record", async () => {
    const opts = { ...setup(), resolveTxt: async () => { throw Object.assign(new Error("x"), { code: "ENOTFOUND" }); } };
    expect((await reasons(opts)).join()).toMatch(/no TXT record/);
  });

  it("refuses two bj1 TXT records", async () => {
    const opts = { ...setup(), resolveTxt: async () => [[`v=bj1; vat=${VAT}`], ["v=bj1; vat=ESB1"]] };
    expect((await reasons(opts)).join()).toMatch(/more than one/);
  });

  it("refuses a document that changed after binding", async () => {
    const verifier = makeVerifier("https://verify.test");
    const record = verifier.sign(makeRecord(makeDoc()));
    const changed = makeDoc({ contact: { email: "pay-here@attacker.example" } });
    expect((await reasons(setup({ verifier, record, doc: changed }))).join()).toMatch(/profileDigest mismatch/);
  });

  it("refuses an expired binding", async () => {
    const opts = { ...setup(), now: new Date("2027-03-01T00:00:00Z") };
    expect((await reasons(opts)).join()).toMatch(/expired/);
  });

  it("refuses when the queried domain is missing from the document or the binding", async () => {
    const verifier = makeVerifier("https://verify.test");
    const doc = makeDoc({ domains: [DOMAIN, "shop.acme.example"] });
    const record = verifier.sign(makeRecord(makeDoc({ domains: ["shop.acme.example"] }), { profileDigest: makeRecord(doc).profileDigest }));
    expect((await reasons(setup({ verifier, doc, record }))).join()).toMatch(/binding does not include acme.example/);
  });

  it("refuses a binding for another VAT", async () => {
    const verifier = makeVerifier("https://verify.test");
    const other = makeDoc({ vat: "ESB99999999" });
    const record = verifier.sign(makeRecord(other, { profileDigest: makeRecord(makeDoc()).profileDigest }));
    expect((await reasons(setup({ verifier, record }))).join()).toMatch(/binding is for ESB99999999/);
  });

  it("refuses a certificate organizationIdentifier that names another VAT", async () => {
    const verifier = makeVerifier("https://verify.test");
    const base = makeRecord(makeDoc());
    const record = verifier.sign({ ...base, authority: { ...(base.authority as object), organizationIdentifier: "VATES-B99999999" } });
    expect((await reasons(setup({ verifier, record }))).join()).toMatch(/does not name ESB12345678/);
  });

  it("reports a malformed document as not-bound", async () => {
    const opts = setup({ extra: { [DOC_URL]: { status: 200, body: JSON.stringify({ hello: "world" }) } } });
    expect((await reasons(opts)).join()).toMatch(/business.json:/);
  });

  it("refuses an oversized document", async () => {
    const opts = setup({ extra: { [DOC_URL]: { status: 200, body: " ".repeat(70 * 1024) + "{}" } } });
    expect((await reasons(opts)).join()).toMatch(/larger than/);
  });

  it("passes redirect: error to fetch", async () => {
    let seen: RequestInit | undefined;
    const base = setup();
    const spy = (async (u: string, init?: RequestInit) => { seen = init; return base.fetchImpl!(u, init); }) as typeof fetch;
    await validateDomain(DOMAIN, { ...base, fetchImpl: spy });
    expect(seen?.redirect).toBe("error");
  });
});
