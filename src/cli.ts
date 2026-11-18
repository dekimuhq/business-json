#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseBusinessJson } from "./parse.js";
import { validateDomain, type TrustedVerifier, type ValidateOptions } from "./validate.js";

/** Trusted when no `--verifier` is given. Relying parties choose their own list (SPEC §Trust). */
export const DEFAULT_VERIFIERS: readonly string[] = ["https://verify.dekimu.com"];

const USAGE = "usage: business-json validate <domain|file.json> [--verifier https://origin ...]";

export type ExitCode = 0 | 1 | 2 | 3;

/** Exit codes: 0 bound · 1 not bound / invalid · 2 usage · 3 no business.json (unknown). */
export async function runCli(argv: readonly string[], deps: Omit<ValidateOptions, "trusted"> = {}): Promise<ExitCode> {
  const [cmd, target, ...rest] = argv;
  if (cmd !== "validate" || !target) {
    console.error(USAGE);
    return 2;
  }
  const origins: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] !== "--verifier" || !rest[i + 1]) { console.error(USAGE); return 2; }
    let u: URL;
    try { u = new URL(rest[++i]); } catch { console.error(`not a URL: ${rest[i]}`); return 2; }
    if (u.protocol !== "https:") { console.error(`verifier must be https: ${rest[i]}`); return 2; }
    origins.push(u.origin);
  }
  const trusted: TrustedVerifier[] = (origins.length ? origins : DEFAULT_VERIFIERS).map((origin) => ({ origin }));

  if (target.endsWith(".json")) {
    try {
      const r = parseBusinessJson(JSON.parse(await readFile(target, "utf8")));
      if (!r.ok) { console.error(`INVALID: ${r.error}`); return 1; }
      console.log(`SCHEMA OK: ${r.value.legalName} (${r.value.vat}). Binding not checked — run against a domain for that.`);
      return 0;
    } catch (e) { console.error(`INVALID: ${(e as Error).message}`); return 1; }
  }

  const result = await validateDomain(target, { ...deps, trusted });
  if (result.status === "no-profile") {
    console.log(`UNKNOWN: ${result.domain} publishes no business.json. This says nothing either way.`);
    return 3;
  }
  if (result.status === "not-bound") {
    console.error(`NOT BOUND: ${result.domain}`);
    for (const r of result.reasons) console.error(`  - ${r}`);
    return 1;
  }
  const { doc, record } = result;
  console.log(`BOUND: ${result.domain} → ${doc.legalName} (${doc.vat})`);
  console.log(`  verifier ${record.verifier} · ${record.authority.method} · ${record.authority.organizationIdentifier} · valid until ${record.expiresAt}`);
  return 0;
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
