import { resolveCname as dnsResolveCname, resolveTxt as dnsResolveTxt } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { parseDnsRecord, profileDigest, signingInput, verifyEd25519 } from "./canonical.js";
import { organizationIdentifierMatches } from "./identity.js";
import { parseBindingRecord, parseBusinessJson, parseVerifierMetadata } from "./parse.js";
import { domainSchema, type BindingRecord, type BusinessJson, type VerifierKey } from "./schema.js";

/** Documents above this size are refused (SPEC §6), counted after decompression. */
export const MAX_DOCUMENT_BYTES = 64 * 1024;
/** Each fetch gives up after this long (SPEC §6). */
export const FETCH_TIMEOUT_MS = 10_000;
/** Tolerated verifier clock skew for `issuedAt` in the future. */
export const CLOCK_SKEW_MS = 5 * 60 * 1000;

/**
 * A verifier the relying party trusts, configured OUT OF BAND. The `binding`
 * URL inside a business.json is only a locator — a document can name any
 * verifier, including one its author runs (SPEC §5, rule 1).
 */
export interface TrustedVerifier {
  /** HTTPS origin, e.g. `https://verify.dekimu.com`. Normalised with `new URL().origin`. */
  origin: string;
  /** Pinned keys. When absent, keys come from the origin's business-verifier.json on each call. */
  keys?: VerifierKey[];
}

export interface ValidateOptions {
  trusted: readonly TrustedVerifier[];
  fetchImpl?: typeof fetch;
  resolveTxt?: (name: string) => Promise<string[][]>;
  resolveCname?: (name: string) => Promise<string[]>;
  now?: Date;
}

/**
 * `no-profile`: the domain publishes no business.json. That is UNKNOWN, never a
 * negative or positive signal — most real businesses publish none.
 * `not-bound`: a document exists but at least one check failed. Treat as unverified.
 * `bound`: every check in SPEC §6 passed. Display `record.authority.organizationName`
 * and `record.vat` — never the document's self-declared fields (SPEC §5, rule 2).
 */
export type ValidateResult =
  | { status: "bound"; domain: string; doc: BusinessJson; record: BindingRecord }
  | { status: "not-bound"; domain: string; reasons: string[]; doc?: BusinessJson }
  | { status: "no-profile"; domain: string; reason: string };

/** Quote an untrusted value for a reason string: escapes control characters, caps length. */
export function show(value: unknown): string {
  // JSON.stringify escapes C0 only; also escape DEL, C1 (0x9B is a CSI introducer) and bidi overrides.
  const s = JSON.stringify(String(value)).replace(
    /[\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  return s.length > 120 ? `${s.slice(0, 117)}…"` : s;
}

type Fetched = { ok: true; value: unknown } | { ok: false; status?: number; error: string };

async function fetchJson(url: string, fetchImpl: typeof fetch): Promise<Fetched> {
  let res: Response;
  try {
    // No redirects: a redirect could move the document to a host the domain does not control.
    res = await fetchImpl(url, {
      redirect: "error",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (e) {
    return { ok: false, error: `fetch ${url}: ${(e as Error).name}` };
  }
  const tooBig: Fetched = { ok: false, error: `${url}: larger than ${MAX_DOCUMENT_BYTES} bytes` };
  if (!res.ok) {
    await res.body?.cancel().catch(() => {});
    return { ok: false, status: res.status, error: `fetch ${url}: HTTP ${res.status}` };
  }
  const type = res.headers?.get("content-type") ?? "";
  if (!/^application\/json\s*(;|$)/i.test(type)) {
    await res.body?.cancel().catch(() => {});
    return { ok: false, error: `${url}: content-type ${show(type)} is not application/json` };
  }
  if (Number(res.headers.get("content-length") ?? 0) > MAX_DOCUMENT_BYTES) {
    await res.body?.cancel().catch(() => {});
    return tooBig;
  }
  // Stream with a byte cap: fetch decompresses transparently, so the cap applies
  // to the decoded size and a small gzip bomb cannot expand past it.
  const chunks: Uint8Array[] = [];
  let n = 0;
  try {
    const reader = res.body?.getReader();
    if (!reader) return { ok: false, error: `${url}: empty body` };
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.byteLength;
      if (n > MAX_DOCUMENT_BYTES) {
        await reader.cancel().catch(() => {});
        return tooBig;
      }
      chunks.push(value);
    }
  } catch (e) {
    return { ok: false, error: `fetch ${url}: ${(e as Error).name}` };
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, error: `${url}: not UTF-8 JSON` };
  }
}

function originOf(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === "https:" ? u.origin : null;
  } catch {
    return null;
  }
}

/**
 * Normalise a queried domain BEFORE any I/O (SPEC §6, step 1): IDN → A-label,
 * lower-case, no trailing dot, and it must be a plain hostname — no port, path,
 * credentials or IP literal. Returns null when it is not one.
 */
export function normaliseDomain(input: string): string | null {
  const trimmed = input.trim().replace(/\.$/, "");
  if (!trimmed || /[/:@?#\s\\]/.test(trimmed) || isIP(trimmed.replace(/^\[|\]$/g, ""))) return null;
  const ascii = domainToASCII(trimmed);
  return ascii && domainSchema.safeParse(ascii).success ? ascii : null;
}

const NO_RECORD = new Set(["ENODATA", "ENOTFOUND"]);

/** DNS check (SPEC §2) for the queried domain: direct TXT only, exactly one bj1 record, naming this VAT. */
async function checkDns(domain: string, vat: string, opts: ValidateOptions): Promise<string | null> {
  const name = `_business-json.${domain}`;
  const resolveCname = opts.resolveCname ?? dnsResolveCname;
  const resolveTxt = opts.resolveTxt ?? dnsResolveTxt;
  try {
    const cnames = await resolveCname(name);
    if (cnames.length > 0) return `${name} is a CNAME; the TXT record must sit at the name itself`;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "";
    // Only "no such record" means no CNAME. SERVFAIL/timeout must not skip the rule.
    if (!NO_RECORD.has(code)) return `CNAME lookup for ${name} failed (${show(code || (e as Error).message)})`;
  }
  let records: string[][];
  try {
    records = await resolveTxt(name);
  } catch (e) {
    return `no TXT record at ${name} (${show((e as NodeJS.ErrnoException).code ?? (e as Error).message)})`;
  }
  const bj1 = records.map((chunks) => parseDnsRecord(chunks.join(""))).filter((r) => r !== null);
  if (bj1.length === 0) return `no v=bj1 TXT record at ${name}`;
  if (bj1.length > 1) return `more than one v=bj1 TXT record at ${name}`;
  const found = bj1[0].vat;
  if (found === null) return `malformed v=bj1 TXT record at ${name}`;
  if (found !== vat) return `TXT at ${name} names ${show(found)}, document names ${vat}`;
  return null;
}

async function keysFor(trusted: TrustedVerifier, fetchImpl: typeof fetch): Promise<{ keys: VerifierKey[] } | { error: string }> {
  if (trusted.keys) return { keys: trusted.keys };
  const meta = await fetchJson(`${trusted.origin}/.well-known/business-verifier.json`, fetchImpl);
  if (!meta.ok) return { error: meta.error };
  const parsed = parseVerifierMetadata(meta.value);
  if (!parsed.ok) return { error: `business-verifier.json: ${show(parsed.error)}` };
  if (parsed.value.verifier !== trusted.origin) return { error: "business-verifier.json names a different verifier" };
  return { keys: parsed.value.keys };
}

function inWindow(key: VerifierKey, at: number): boolean {
  if (!Number.isFinite(at)) return false;
  if (key.notBefore) { const t = Date.parse(key.notBefore); if (!Number.isFinite(t) || at < t) return false; }
  if (key.notAfter) { const t = Date.parse(key.notAfter); if (!Number.isFinite(t) || at > t) return false; }
  return true;
}

/** Compare a document's legalName with the certificate's organizationName (SPEC §3, rule 5). */
export function legalNameKey(name: string): string {
  return name.normalize("NFKD").replace(/\p{M}/gu, "").toUpperCase().replace(/[^\p{L}\p{N}]/gu, "");
}

function normaliseOrigin(origin: string): string | null {
  return originOf(origin);
}

/**
 * Check a binding record against a document and a trusted verifier. Returns failure reasons; empty = bound.
 * `recordInput` MUST be the record as just fetched from `trusted.origin` — a cached or
 * document-supplied record bypasses withdrawal (SPEC §6). `rawDoc` is the document as served.
 */
export async function checkBinding(
  domain: string,
  doc: BusinessJson,
  rawDoc: unknown,
  recordInput: unknown,
  trusted: TrustedVerifier,
  opts: ValidateOptions,
): Promise<{ reasons: string[]; record?: BindingRecord }> {
  const parsed = parseBindingRecord(recordInput);
  if (!parsed.ok) return { reasons: [`binding record: ${show(parsed.error)}`] };
  const record = parsed.value;
  const reasons: string[] = [];
  const origin = normaliseOrigin(trusted.origin);

  if (record.verifier !== origin) reasons.push("binding record names a different verifier than the one serving it");

  const keys = await keysFor({ ...trusted, origin: origin ?? trusted.origin }, opts.fetchImpl ?? fetch);
  if ("error" in keys) {
    reasons.push(keys.error);
  } else {
    const matches = keys.keys.filter((k) => k.kid === record.sig.kid);
    if (matches.length === 0) reasons.push(`unknown signing key ${show(record.sig.kid)}`);
    else if (matches.length > 1) reasons.push(`verifier publishes key ${show(record.sig.kid)} more than once`);
    else if (!inWindow(matches[0], Date.parse(record.issuedAt))) reasons.push(`key ${show(record.sig.kid)} was not valid at issuedAt`);
    else if (!verifyEd25519(signingInput(recordInput as Record<string, unknown>), record.sig.value, matches[0].x)) reasons.push("signature does not verify");
  }

  if (record.vat !== doc.vat) reasons.push(`binding is for ${record.vat}, document names ${doc.vat}`);
  if (!organizationIdentifierMatches(record.vat, record.authority.organizationIdentifier)) {
    reasons.push(`certificate organizationIdentifier ${show(record.authority.organizationIdentifier)} does not name ${record.vat}`);
  }
  if (legalNameKey(doc.legalName) !== legalNameKey(record.authority.organizationName)) {
    reasons.push(`document legalName ${show(doc.legalName)} does not match the certificate's ${show(record.authority.organizationName)}`);
  }
  if (!record.domains.some((d) => d.domain === domain)) reasons.push(`binding does not include ${domain}`);
  const now = (opts.now ?? new Date()).getTime();
  if (now >= Date.parse(record.expiresAt)) reasons.push(`binding expired at ${record.expiresAt}`);
  if (now + CLOCK_SKEW_MS < Date.parse(record.issuedAt)) reasons.push("binding issuedAt is in the future");
  if (record.profileDigest !== profileDigest(rawDoc)) reasons.push("document changed since the verifier bound it (profileDigest mismatch)");

  return { reasons, record };
}

/** Run SPEC §6 for one domain. */
export async function validateDomain(domainInput: string, opts: ValidateOptions): Promise<ValidateResult> {
  const domain = normaliseDomain(domainInput);
  if (!domain) return { status: "not-bound", domain: domainInput, reasons: [`${show(domainInput)} is not a hostname`] };
  const fetchImpl = opts.fetchImpl ?? fetch;

  const got = await fetchJson(`https://${domain}/.well-known/business.json`, fetchImpl);
  if (!got.ok) {
    if (got.status === 404 || got.status === 410) return { status: "no-profile", domain, reason: got.error };
    return { status: "not-bound", domain, reasons: [got.error] };
  }
  const parsed = parseBusinessJson(got.value);
  if (!parsed.ok) return { status: "not-bound", domain, reasons: [`business.json: ${show(parsed.error)}`] };
  const doc = parsed.value;

  const reasons: string[] = [];
  if (!doc.domains.includes(domain)) reasons.push(`document does not list ${domain} in domains`);

  const dnsProblem = await checkDns(domain, doc.vat, opts);
  if (dnsProblem) reasons.push(dnsProblem);

  const bindingOrigin = originOf(doc.binding);
  const trusted = opts.trusted.find((t) => normaliseOrigin(t.origin) === bindingOrigin);
  if (!trusted) {
    reasons.push(`binding is held by ${show(bindingOrigin ?? doc.binding)}, which is not a trusted verifier`);
    return { status: "not-bound", domain, reasons, doc };
  }

  const rec = await fetchJson(doc.binding, fetchImpl);
  if (!rec.ok) {
    reasons.push(rec.status === 404 || rec.status === 410 ? `binding withdrawn by the verifier (${rec.error})` : rec.error);
    return { status: "not-bound", domain, reasons, doc };
  }
  const checked = await checkBinding(domain, doc, got.value, rec.value, trusted, opts);
  reasons.push(...checked.reasons);

  if (reasons.length || !checked.record) return { status: "not-bound", domain, reasons, doc };
  return { status: "bound", domain, doc, record: checked.record };
}
