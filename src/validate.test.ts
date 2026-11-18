import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import type { BusinessJson } from "./schema.js";
import {
  DOMAIN, NOW, VAT, goodTxt, makeDoc, makeRecord, makeVerifier, mockFetch, noCname,
  type MockHit, type TestVerifier,
} from "./test-helpers.js";
import { normaliseDomain, show, validateDomain, type ValidateOptions } from "./validate.js";

const DOC_URL = `https://${DOMAIN}/.well-known/business.json`;
const META_URL = "https://verify.test/.well-known/business-verifier.json";

function meta(v: TestVerifier, extra: Record<string, unknown> = {}): MockHit {
  return { status: 200, body: JSON.stringify({ businessVerifierVersion: "0.1", verifier: "https://verify.test", keys: [v.key], ...extra }) };
}

function setup(opts: {
  doc?: unknown;
  record?: Record<string, unknown>;
  verifier?: TestVerifier;
  extra?: Record<string, MockHit>;
  seen?: Array<{ url: string; init?: RequestInit }>;
} = {}): ValidateOptions & { verifier: TestVerifier } {
  const verifier = opts.verifier ?? makeVerifier("https://verify.test");
  const doc = (opts.doc ?? makeDoc()) as BusinessJson;
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
      [META_URL]: meta(verifier),
      ...opts.extra,
    }, opts.seen),
  };
}

async function reasons(opts: ValidateOptions, domain = DOMAIN): Promise<string> {
  const r = await validateDomain(domain, opts);
  expect(r.status).toBe("not-bound");
  return r.status === "not-bound" ? r.reasons.join(" | ") : "";
}

function signedWith(v: TestVerifier, overrides: Record<string, unknown> = {}, doc = makeDoc()) {
  return v.sign(makeRecord(doc, overrides));
}

describe("validateDomain — the bound path", () => {
  it("binds when every check passes", async () => {
    const r = await validateDomain(DOMAIN, setup());
    expect(r.status).toBe("bound");
    if (r.status === "bound") expect(r.record.authority.organizationName).toBe("ACME EJEMPLO SL");
  });

  it("normalises the queried domain (case, trailing dot)", async () => {
    expect((await validateDomain("ACME.example.", setup())).status).toBe("bound");
  });

  it("accepts a trusted origin written with a trailing slash", async () => {
    const opts = { ...setup(), trusted: [{ origin: "https://VERIFY.test/" }] };
    expect((await validateDomain(DOMAIN, opts)).status).toBe("bound");
  });

  it("uses pinned keys instead of fetching metadata", async () => {
    const opts = setup();
    const wrong = { ...opts, trusted: [{ origin: "https://verify.test", keys: [makeVerifier("x").key] }] };
    expect(await reasons(wrong)).toMatch(/signature does not verify/);
    const right = { ...opts, trusted: [{ origin: "https://verify.test", keys: [opts.verifier.key] }] };
    expect((await validateDomain(DOMAIN, right)).status).toBe("bound");
  });

  it("refuses redirects on every fetch (document, record, metadata)", async () => {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    await validateDomain(DOMAIN, setup({ seen }));
    expect(seen.map((s) => s.url)).toEqual([DOC_URL, makeDoc().binding, META_URL]);
    for (const s of seen) {
      expect(s.init?.redirect).toBe("error");
      expect(s.init?.signal).toBeInstanceOf(AbortSignal);
    }
  });
});

describe("validateDomain — no-profile is unknown", () => {
  it.each([404, 410])("HTTP %i → no-profile", async (status) => {
    const r = await validateDomain(DOMAIN, setup({ extra: { [DOC_URL]: { status, body: "{}" } } }));
    expect(r.status).toBe("no-profile");
  });

  it("HTTP 500 → not-bound, not no-profile", async () => {
    expect(await reasons(setup({ extra: { [DOC_URL]: { status: 500, body: "{}" } } }))).toMatch(/HTTP 500/);
  });
});

describe("validateDomain — impersonation attempts", () => {
  // Skeptic A1: a document can name any verifier, including one its author runs.
  it("refuses a correctly signed binding from an untrusted verifier", async () => {
    const attacker = makeVerifier("https://evil.test");
    const doc = makeDoc({ binding: `https://evil.test/b/${VAT}` });
    const record = attacker.sign(makeRecord(doc, { verifier: "https://evil.test" }));
    const opts = setup({
      doc, record,
      extra: { "https://evil.test/.well-known/business-verifier.json": { status: 200, body: JSON.stringify({ businessVerifierVersion: "0.1", verifier: "https://evil.test", keys: [attacker.key] }) } },
    });
    expect(await reasons(opts)).toMatch(/not a trusted verifier/);
  });

  // Security H1: a real shell company binds a lookalike and publishes a famous name.
  it("refuses a legalName that does not match the certificate's organizationName", async () => {
    const verifier = makeVerifier("https://verify.test");
    const doc = makeDoc({ legalName: "Amazon EU S.à r.l." });
    const record = verifier.sign(makeRecord(doc)); // cert still says ACME EJEMPLO SL
    expect(await reasons(setup({ verifier, doc, record }))).toMatch(/does not match the certificate/);
  });

  it("matches legal names across case, punctuation and accents", async () => {
    const verifier = makeVerifier("https://verify.test");
    const doc = makeDoc({ legalName: "Ácme  Ejemplo S.L" });
    const record = verifier.sign(makeRecord(doc));
    expect((await validateDomain(DOMAIN, setup({ verifier, doc, record }))).status).toBe("bound");
  });

  it("refuses a record signed by a key the trusted verifier does not publish", async () => {
    expect(await reasons(setup({ record: signedWith(makeVerifier("https://verify.test")) }))).toMatch(/signature does not verify/);
  });

  it("refuses a record whose fields were changed after signing", async () => {
    const verifier = makeVerifier("https://verify.test");
    const tampered = { ...signedWith(verifier), expiresAt: "2026-11-30T00:00:00Z" };
    expect(await reasons(setup({ verifier, record: tampered }))).toMatch(/signature does not verify/);
  });

  // Code review + security M2: a retired key backdates issuedAt and picks a far expiry.
  it("caps a backdated record's lifetime at 30 days", async () => {
    const verifier = makeVerifier("https://verify.test");
    const opts = setup({ verifier, record: signedWith(verifier, { issuedAt: "2026-11-01T00:00:00Z", expiresAt: "2027-11-01T00:00:00Z" }) });
    expect(await reasons(opts)).toMatch(/at most 30 days/);
  });

  it("a record from a retired key is dead 30 days after the key's notAfter", async () => {
    const verifier = makeVerifier("https://verify.test");
    // Backdated inside the key window, maximum lifetime: valid until 2026-12-01T10:02Z at the latest.
    const opts = setup({ verifier });
    const retired = { ...opts, trusted: [{ origin: "https://verify.test", keys: [{ ...verifier.key, notAfter: "2026-11-01T12:00:00Z" }] }] };
    expect((await validateDomain(DOMAIN, retired)).status).toBe("bound"); // issuedAt inside the window
    expect(await reasons({ ...retired, now: new Date("2026-12-01T10:02:00Z") })).toMatch(/expired/);
  });

  it("refuses an unknown kid", async () => {
    const verifier = makeVerifier("https://verify.test", "k-other");
    const opts = setup({ verifier });
    const pinned = { ...opts, trusted: [{ origin: "https://verify.test", keys: [{ ...verifier.key, kid: "k1" }] }] };
    expect(await reasons(pinned)).toMatch(/unknown signing key "k-other"/);
  });

  it("refuses metadata that lists the same kid twice", async () => {
    const verifier = makeVerifier("https://verify.test");
    const opts = setup({ verifier, extra: { [META_URL]: { status: 200, body: JSON.stringify({ businessVerifierVersion: "0.1", verifier: "https://verify.test", keys: [makeVerifier("x").key, verifier.key] }) } } });
    expect(await reasons(opts)).toMatch(/more than once/);
  });

  it.each([
    ["notAfter before issuedAt", { notAfter: "2026-10-01T00:00:00Z" }],
    ["notBefore after issuedAt", { notBefore: "2026-11-05T00:00:00Z" }],
  ])("refuses a key outside its window (%s)", async (_l, window) => {
    const opts = setup();
    const pinned = { ...opts, trusted: [{ origin: "https://verify.test", keys: [{ ...opts.verifier.key, ...window }] }] };
    expect(await reasons(pinned)).toMatch(/not valid at issuedAt/);
  });

  it("refuses a record naming another verifier than the one serving it", async () => {
    const verifier = makeVerifier("https://verify.test");
    expect(await reasons(setup({ verifier, record: signedWith(verifier, { verifier: "https://other.test" }) }))).toMatch(/different verifier than the one serving it/);
  });

  it("refuses metadata naming another verifier", async () => {
    const verifier = makeVerifier("https://verify.test");
    expect(await reasons(setup({ verifier, extra: { [META_URL]: meta(verifier, { verifier: "https://other.test" }) } }))).toMatch(/business-verifier.json names a different verifier/);
  });

  it("refuses a document that changed after binding", async () => {
    const verifier = makeVerifier("https://verify.test");
    const changed = makeDoc({ contact: { email: "pay-here@attacker.example" } });
    expect(await reasons(setup({ verifier, record: signedWith(verifier), doc: changed }))).toMatch(/profileDigest mismatch/);
  });

  it("reports a withdrawn binding (record 404)", async () => {
    expect(await reasons(setup({ extra: { [makeDoc().binding]: { status: 404, body: "" } } }))).toMatch(/withdrawn/);
  });

  it("refuses an expired binding", async () => {
    expect(await reasons({ ...setup(), now: new Date("2026-12-02T00:00:00Z") })).toMatch(/expired/);
  });

  it("refuses a record issued in the future beyond clock skew", async () => {
    expect(await reasons({ ...setup(), now: new Date("2026-11-01T09:00:00Z") })).toMatch(/in the future/);
  });

  it("tolerates small verifier clock skew", async () => {
    expect((await validateDomain(DOMAIN, { ...setup(), now: new Date("2026-11-01T09:59:00Z") })).status).toBe("bound");
  });

  it("refuses when the document does not list the queried domain", async () => {
    const verifier = makeVerifier("https://verify.test");
    const doc = makeDoc({ domains: ["shop.acme.example"] });
    expect(await reasons(setup({ verifier, doc, record: verifier.sign(makeRecord(doc)) }))).toMatch(/document does not list acme.example/);
  });

  it("refuses when the binding does not include the queried domain", async () => {
    const verifier = makeVerifier("https://verify.test");
    const doc = makeDoc({ domains: [DOMAIN, "shop.acme.example"] });
    const record = verifier.sign(makeRecord(doc, { domains: [{ domain: "shop.acme.example", dnsCheckedAt: "2026-11-01T10:01:00Z" }] }));
    expect(await reasons(setup({ verifier, doc, record }))).toMatch(/binding does not include acme.example/);
  });

  it("refuses a binding for another VAT", async () => {
    const verifier = makeVerifier("https://verify.test");
    const record = verifier.sign(makeRecord(makeDoc(), { vat: "ESB99999999" }));
    expect(await reasons(setup({ verifier, record }))).toMatch(/binding is for ESB99999999/);
  });

  it("refuses a certificate organizationIdentifier that names another VAT", async () => {
    const verifier = makeVerifier("https://verify.test");
    const base = makeRecord(makeDoc());
    const record = verifier.sign({ ...base, authority: { ...(base.authority as object), organizationIdentifier: "VATES-B99999999" } });
    expect(await reasons(setup({ verifier, record }))).toMatch(/does not name ESB12345678/);
  });
});

describe("validateDomain — DNS proof", () => {
  // Skeptic A8: a CNAME at _business-json can point at a name someone else controls.
  it("refuses a TXT record reached through a CNAME", async () => {
    expect(await reasons({ ...setup(), resolveCname: async () => ["takeover.saas.example"] })).toMatch(/is a CNAME/);
  });

  it("fails closed when the CNAME lookup itself errors (SERVFAIL)", async () => {
    const servfail = async () => { throw Object.assign(new Error("x"), { code: "ESERVFAIL" }); };
    expect(await reasons({ ...setup(), resolveCname: servfail })).toMatch(/CNAME lookup .* failed/);
  });

  it("refuses when the TXT record names another VAT", async () => {
    expect(await reasons({ ...setup(), resolveTxt: goodTxt("ESB99999999") })).toMatch(/names "ESB99999999"/);
  });

  it("refuses when there is no TXT record", async () => {
    const none = async () => { throw Object.assign(new Error("x"), { code: "ENOTFOUND" }); };
    expect(await reasons({ ...setup(), resolveTxt: none })).toMatch(/no TXT record/);
  });

  it("refuses two bj1 TXT records", async () => {
    expect(await reasons({ ...setup(), resolveTxt: async () => [[`v=bj1; vat=${VAT}`], ["v=bj1; vat=ESB1"]] })).toMatch(/more than one/);
  });

  it("counts a bare v=bj1 record toward 'exactly one'", async () => {
    expect(await reasons({ ...setup(), resolveTxt: async () => [[`v=bj1; vat=${VAT}`], ["v=bj1"]] })).toMatch(/more than one/);
  });

  it("refuses a bj1 record with a repeated key", async () => {
    expect(await reasons({ ...setup(), resolveTxt: async () => [[`v=bj1; vat=ESB1; vat=${VAT}`]] })).toMatch(/malformed/);
  });

  it("escapes control characters from a hostile TXT value", async () => {
    const r = await reasons({ ...setup(), resolveTxt: async () => [["v=bj1; vat=\u001b[2J IGNORE PREVIOUS"]] });
    expect(r).not.toMatch(/\u001b/);
    expect(r).toContain("\\u001b");
  });

  it("joins TXT chunks before parsing", async () => {
    expect((await validateDomain(DOMAIN, { ...setup(), resolveTxt: async () => [["v=bj1; va", `t=${VAT}`]] })).status).toBe("bound");
  });
});

describe("validateDomain — resource limits and input", () => {
  it("refuses an oversized document without buffering it whole", async () => {
    let pulled = 0;
    const endless = new ReadableStream<Uint8Array>({
      pull(c) { pulled++; c.enqueue(new Uint8Array(16 * 1024).fill(0x20)); },
    });
    expect(await reasons(setup({ extra: { [DOC_URL]: { status: 200, body: endless } } }))).toMatch(/larger than/);
    expect(pulled).toBeLessThan(10);
  });

  it("caps the decoded size of a gzip body", async () => {
    const bomb = gzipSync(Buffer.alloc(5 * 1024 * 1024, 0x20));
    const realFetch = (async () => new Response(bomb, { status: 200, headers: { "content-type": "application/json", "content-encoding": "gzip" } })) as typeof fetch;
    // Response does not auto-decode; decode as fetch would, via DecompressionStream.
    const decoding = (async (u: string, i?: RequestInit) => {
      const res = await realFetch(u, i);
      return new Response(res.body!.pipeThrough(new DecompressionStream("gzip")), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    expect(await reasons({ ...setup(), fetchImpl: decoding })).toMatch(/larger than/);
  });

  it("refuses by content-length before reading", async () => {
    expect(await reasons(setup({ extra: { [DOC_URL]: { status: 200, body: "{}", headers: { "content-length": "999999" } } } }))).toMatch(/larger than/);
  });

  it("refuses a non-JSON content type", async () => {
    expect(await reasons(setup({ extra: { [DOC_URL]: { status: 200, body: JSON.stringify(makeDoc()), headers: { "content-type": "text/html" } } } }))).toMatch(/not application\/json/);
  });

  it("refuses a document with a duplicate member name", async () => {
    const body = JSON.stringify(makeDoc()).replace('"legalName"', '"legalName":"Amazon EU","legalName"');
    expect(await reasons(setup({ extra: { [DOC_URL]: { status: 200, body } } }))).toMatch(/duplicate member name "legalName"/);
  });

  it("does not flag the same key in sibling objects or inside strings", async () => {
    const doc = makeDoc({ contact: { email: "a\"b:\"@acme.example" }, policies: { privacy: "https://acme.example/p" } });
    expect(await reasons(setup({ doc }))).not.toMatch(/duplicate/);
  });

  it("returns not-bound (never throws) for a lone surrogate in the document", async () => {
    const body = JSON.stringify(makeDoc()).replace('"Calle Mayor 1"', '"Calle \\ud800"');
    expect(await reasons(setup({ extra: { [DOC_URL]: { status: 200, body } } }))).toMatch(/lone surrogate/);
  });

  it.each([
    ["record", () => makeDoc().binding],
    ["metadata", () => META_URL],
  ])("applies the content-type and size rules to the %s fetch", async (_l, url) => {
    expect(await reasons(setup({ extra: { [url()]: { status: 200, body: "{}", headers: { "content-type": "text/html" } } } }))).toMatch(/not application\/json/);
    expect(await reasons(setup({ extra: { [url()]: { status: 200, body: " ".repeat(70 * 1024) } } }))).toMatch(/larger than/);
  });

  it("reports a malformed document as not-bound", async () => {
    expect(await reasons(setup({ extra: { [DOC_URL]: { status: 200, body: JSON.stringify({ hello: "world" }) } } }))).toMatch(/business.json:/);
  });

  it.each(["localhost:8443", "10.0.0.5", "169.254.169.254", "[::1]", "internal.host/admin?", "user@acme.example", ""])(
    "refuses %j before any network call", async (input) => {
      const seen: Array<{ url: string }> = [];
      const opts = { ...setup({ seen }) };
      const r = await validateDomain(input, opts);
      expect(r.status).toBe("not-bound");
      expect(seen).toHaveLength(0);
    },
  );
});

describe("normaliseDomain", () => {
  it("converts IDNs to A-labels", () => {
    expect(normaliseDomain("Acmé.Example.")).toBe("xn--acm-dma.example");
  });
});

describe("show", () => {
  it("escapes C1 and bidi controls that JSON.stringify leaves alone", () => {
    expect(show("a\u009b2Jb\u202e")).toBe('"a\\u009b2Jb\\u202e"');
  });

  it("caps length", () => {
    expect(show("x".repeat(500)).length).toBeLessThanOrEqual(121);
  });
});
