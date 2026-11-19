#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { open } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseBusinessJson } from "./parse.js";
import type { VerifierKey } from "./schema.js";
import { MAX_DOCUMENT_BYTES, show, validateDomain, type TrustedVerifier, type ValidateOptions } from "./validate.js";

/**
 * Verifier keys the CLI pins when no `--verifier` is given (SPEC §5, rule 1).
 * Pinned, not fetched: trusting whatever key a web host serves would make a
 * hosting compromise a forgery of every binding. This is verify.dekimu.com's
 * `bj-2026-11` key as published at /.well-known/business-verifier.json on
 * 2026-11-20. A rotation ships as a new release that appends the new key.
 */
export const DEFAULT_VERIFIER_KEYS: readonly VerifierKey[] = [
  { kid: "bj-2026-11", alg: "ed25519", x: "xCPLg5cXpBrhYS2uRPmyWllDHanTrMjPtBKw8RpDM68", notBefore: "2026-11-20T00:00:00Z" },
];
export const DEFAULT_VERIFIERS: readonly TrustedVerifier[] = [
  { origin: "https://verify.dekimu.com", keys: [...DEFAULT_VERIFIER_KEYS] },
];

const USAGE = [
  "usage: business-json validate <domain> [--verifier https://origin ...]",
  "       business-json check-file <business.json>",
].join("\n");

export type ExitCode = 0 | 1 | 2 | 3 | 4;

/** Strip control characters from anything printed (values in reasons are already quoted by show()). */
function clean(s: string): string {
  return s.replace(/[\p{Cc}\u202a-\u202e\u2066-\u2069]/gu, "?");
}

/**
 * Exit codes: 0 bound · 1 not bound / invalid · 2 usage · 3 no business.json (unknown)
 * · 4 file passes the schema (says nothing about binding).
 */
export async function runCli(argv: readonly string[], deps: Omit<ValidateOptions, "trusted"> = {}): Promise<ExitCode> {
  const [cmd, target, ...rest] = argv;
  if (cmd === "check-file" && target && rest.length === 0) return checkFile(target);
  if (cmd !== "validate" || !target) {
    console.error(USAGE);
    return 2;
  }
  const trusted: TrustedVerifier[] = [];
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] !== "--verifier" || !rest[i + 1]) { console.error(USAGE); return 2; }
    const raw = rest[++i];
    if (!URL.canParse(raw) || new URL(raw).protocol !== "https:") { console.error(`verifier must be an https URL: ${show(raw)}`); return 2; }
    trusted.push({ origin: new URL(raw).origin });
  }

  const result = await validateDomain(target, { ...deps, trusted: trusted.length ? trusted : DEFAULT_VERIFIERS });
  if (result.status === "no-profile") {
    console.log(`UNKNOWN: ${result.domain} publishes no business.json. This says nothing either way.`);
    return 3;
  }
  if (result.status === "not-bound") {
    console.error(clean(`NOT BOUND: ${show(result.domain)}`));
    for (const r of result.reasons) console.error(clean(`  - ${r}`));
    return 1;
  }
  const { record } = result;
  // Only attested values: the certificate's organizationName and the VAT. Never the
  // document's self-declared legalName/tradingName (SPEC §5, rule 2).
  console.log(clean(`BOUND: ${result.domain} is controlled by the holder of VAT ${record.vat} (${record.authority.organizationName}), per ${record.verifier}`));
  console.log(clean(`  ${record.authority.method} · ${record.authority.organizationIdentifier} · valid until ${record.expiresAt}`));
  return 0;
}

async function checkFile(path: string): Promise<ExitCode> {
  try {
    const fh = await open(path, "r");
    const buf = Buffer.alloc(MAX_DOCUMENT_BYTES + 1);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    await fh.close();
    if (bytesRead > MAX_DOCUMENT_BYTES) { console.error(`INVALID: larger than ${MAX_DOCUMENT_BYTES} bytes`); return 1; }
    const r = parseBusinessJson(JSON.parse(buf.subarray(0, bytesRead).toString("utf8")));
    if (!r.ok) { console.error(clean(`INVALID: ${show(r.error)}`)); return 1; }
    console.log("SCHEMA OK. This checks the file's shape only — it says nothing about who controls the business or the domain.");
    return 4;
  } catch (e) {
    console.error(`INVALID: ${(e as Error).name === "SyntaxError" ? "not JSON" : (e as Error).message}`);
    return 1;
  }
}

/**
 * True only when this file is the process entry point, compared by realpath —
 * under `npx` argv[1] is the `.bin` symlink (agents-txt 0.1.1 exited silently there).
 */
function isEntryPoint(): boolean {
  try {
    return !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  runCli(process.argv.slice(2)).then((code) => process.exit(code));
}
