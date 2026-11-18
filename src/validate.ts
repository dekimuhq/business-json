import { resolveCname as dnsResolveCname, resolveTxt as dnsResolveTxt } from "node:dns/promises";
import { parseDnsRecord, profileDigest, signingInput, verifyEd25519 } from "./canonical.js";
import { organizationIdentifierMatches } from "./identity.js";
import { parseBindingRecord, parseBusinessJson, parseVerifierMetadata } from "./parse.js";
import type { BindingRecord, BusinessJson, VerifierKey } from "./schema.js";

/** Documents above this size are refused before parsing (SPEC §Fetching). */
export const MAX_DOCUMENT_BYTES = 64 * 1024;

/**
 * A verifier the relying party trusts, configured OUT OF BAND. The `binding`
 * URL inside a business.json is only a locator — a document can name any
 * verifier, including one its author runs (SPEC §Trust, rule 1).
 */
export interface TrustedVerifier {
  /** HTTPS origin, e.g. `https://verify.dekimu.com`. */
  origin: string;
  /** Pinned keys. When absent, keys come from the origin's business-verifier.json. */
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
 * `bound`: every check in SPEC §Validation passed.
 */
export type ValidateResult =
  | { status: "bound"; domain: string; doc: BusinessJson; record: BindingRecord }
  | { status: "not-bound"; domain: string; reasons: string[]; doc?: BusinessJson }
  | { status: "no-profile"; domain: string; reason: string };

async function fetchJson(url: string, fetchImpl: typeof fetch): Promise<{ ok: true; value: unknown } | { ok: false; status?: number; error: string }> {
  let res: Response;
  try {
    // No redirects: a redirect could move the document to a host the domain does not control.
    res = await fetchImpl(url, { redirect: "error", headers: { accept: "application/json" } });
  } catch (e) {
    return { ok: false, error: `fetch ${url}: ${(e as Error).message}` };
  }
  if (!res.ok) return { ok: false, status: res.status, error: `fetch ${url}: HTTP ${res.status}` };
  const text = await res.text();
  if (Buffer.byteLength(text, "utf8") > MAX_DOCUMENT_BYTES) return { ok: false, error: `${url}: larger than ${MAX_DOCUMENT_BYTES} bytes` };
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, error: `${url}: not JSON` };
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

/** DNS check (SPEC §Domain proof): direct TXT only, one bj1 record, naming this VAT. */
async function checkDns(domain: string, vat: string, opts: ValidateOptions): Promise<string | null> {
  const name = `_business-json.${domain}`;
  const resolveCname = opts.resolveCname ?? dnsResolveCname;
  const resolveTxt = opts.resolveTxt ?? dnsResolveTxt;
  try {
    const cnames = await resolveCname(name);
    if (cnames.length > 0) return `${name} is a CNAME; the TXT record must sit at the name itself`;
  } catch {
    // ENODATA / ENOTFOUND: no CNAME, which is what we want.
  }
  let records: string[][];
  try {
    records = await resolveTxt(name);
  } catch (e) {
    return `no TXT record at ${name} (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`;
  }
  const vats = records.map((chunks) => parseDnsRecord(chunks.join(""))).filter((v): v is string => v !== null);
  if (vats.length === 0) return `no v=bj1 TXT record at ${name}`;
  if (vats.length > 1) return `more than one v=bj1 TXT record at ${name}`;
  if (vats[0] !== vat) return `TXT at ${name} names ${vats[0]}, document names ${vat}`;
  return null;
}

async function keysFor(trusted: TrustedVerifier, fetchImpl: typeof fetch): Promise<{ keys: VerifierKey[] } | { error: string }> {
  if (trusted.keys) return { keys: trusted.keys };
  const meta = await fetchJson(`${trusted.origin}/.well-known/business-verifier.json`, fetchImpl);
  if (!meta.ok) return { error: meta.error };
  const parsed = parseVerifierMetadata(meta.value);
  if (!parsed.ok) return { error: `business-verifier.json: ${parsed.error}` };
  if (originOf(parsed.value.verifier) !== trusted.origin) return { error: "business-verifier.json names a different verifier" };
  return { keys: parsed.value.keys };
}

function inWindow(key: VerifierKey, at: number): boolean {
  if (key.notBefore && at < Date.parse(key.notBefore)) return false;
  if (key.notAfter && at > Date.parse(key.notAfter)) return false;
  return true;
}

/** Check a binding record against a document and a trusted verifier. Returns failure reasons; empty = bound. */
export async function checkBinding(
  domain: string,
  doc: BusinessJson,
  recordInput: unknown,
  trusted: TrustedVerifier,
  opts: ValidateOptions,
): Promise<{ reasons: string[]; record?: BindingRecord }> {
  const parsed = parseBindingRecord(recordInput);
  if (!parsed.ok) return { reasons: [`binding record: ${parsed.error}`] };
  const record = parsed.value;
  const reasons: string[] = [];

  if (originOf(record.verifier) !== trusted.origin) reasons.push("binding record names a different verifier than the one serving it");

  const keys = await keysFor(trusted, opts.fetchImpl ?? fetch);
  if ("error" in keys) {
    reasons.push(keys.error);
  } else {
    const key = keys.keys.find((k) => k.kid === record.sig.kid);
    if (!key) reasons.push(`unknown signing key ${record.sig.kid}`);
    else if (!inWindow(key, Date.parse(record.issuedAt))) reasons.push(`key ${key.kid} was not valid at issuedAt`);
    else if (!verifyEd25519(signingInput(recordInput as Record<string, unknown>), record.sig.value, key.x)) reasons.push("signature does not verify");
  }

  if (record.vat !== doc.vat) reasons.push(`binding is for ${record.vat}, document names ${doc.vat}`);
  if (!organizationIdentifierMatches(record.vat, record.authority.organizationIdentifier)) {
    reasons.push(`certificate organizationIdentifier ${record.authority.organizationIdentifier} does not name ${record.vat}`);
  }
  if (!record.domains.some((d) => d.domain === domain)) reasons.push(`binding does not include ${domain}`);
  const now = (opts.now ?? new Date()).getTime();
  if (now >= Date.parse(record.expiresAt)) reasons.push(`binding expired at ${record.expiresAt}`);
  if (now < Date.parse(record.issuedAt)) reasons.push("binding issuedAt is in the future");
  if (record.profileDigest !== profileDigest(doc)) reasons.push("document changed since the verifier bound it (profileDigest mismatch)");

  return { reasons, record };
}

/** Run SPEC §Validation for one domain. */
export async function validateDomain(domainInput: string, opts: ValidateOptions): Promise<ValidateResult> {
  const domain = domainInput.trim().toLowerCase().replace(/\.$/, "");
  const fetchImpl = opts.fetchImpl ?? fetch;

  const got = await fetchJson(`https://${domain}/.well-known/business.json`, fetchImpl);
  if (!got.ok) {
    if (got.status === 404 || got.status === 410) return { status: "no-profile", domain, reason: got.error };
    return { status: "not-bound", domain, reasons: [got.error] };
  }
  const parsed = parseBusinessJson(got.value);
  if (!parsed.ok) return { status: "not-bound", domain, reasons: [`business.json: ${parsed.error}`] };
  const doc = parsed.value;

  const reasons: string[] = [];
  if (!doc.domains.includes(domain)) reasons.push(`document does not list ${domain} in domains`);

  const dnsProblem = await checkDns(domain, doc.vat, opts);
  if (dnsProblem) reasons.push(dnsProblem);

  const bindingOrigin = originOf(doc.binding);
  const trusted = opts.trusted.find((t) => t.origin === bindingOrigin);
  if (!trusted) {
    reasons.push(`binding is held by ${bindingOrigin ?? doc.binding}, which is not a trusted verifier`);
    return { status: "not-bound", domain, reasons, doc };
  }

  const rec = await fetchJson(doc.binding, fetchImpl);
  if (!rec.ok) {
    reasons.push(rec.error);
    return { status: "not-bound", domain, reasons, doc };
  }
  const checked = await checkBinding(domain, doc, rec.value, trusted, opts);
  reasons.push(...checked.reasons);

  if (reasons.length || !checked.record) return { status: "not-bound", domain, reasons, doc };
  return { status: "bound", domain, doc, record: checked.record };
}
