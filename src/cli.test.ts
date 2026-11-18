import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import { DEFAULT_VERIFIERS, runCli } from "./cli.js";
import { DOMAIN, NOW, goodTxt, makeDoc, makeRecord, makeVerifier, mockFetch, noCname } from "./test-helpers.js";

let out: MockInstance;
let err: MockInstance;
beforeEach(() => {
  out = vi.spyOn(console, "log").mockImplementation(() => {});
  err = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => vi.restoreAllMocks());

const printed = (m: MockInstance) => m.mock.calls.map((c) => String(c[0])).join("\n");

function deps(doc = makeDoc()) {
  const v = makeVerifier("https://verify.test");
  return {
    now: NOW,
    resolveTxt: goodTxt(),
    resolveCname: noCname,
    fetchImpl: mockFetch({
      [`https://${DOMAIN}/.well-known/business.json`]: { status: 200, body: JSON.stringify(doc) },
      [doc.binding]: { status: 200, body: JSON.stringify(v.sign(makeRecord(doc))) },
      "https://verify.test/.well-known/business-verifier.json": {
        status: 200,
        body: JSON.stringify({ businessVerifierVersion: "0.1", verifier: "https://verify.test", keys: [v.key] }),
      },
    }),
  };
}

describe("cli", () => {
  it("exits 2 on bad usage", async () => {
    expect(await runCli([])).toBe(2);
    expect(await runCli(["validate", DOMAIN, "--verifier"])).toBe(2);
    expect(await runCli(["validate", DOMAIN, "--verifier", "http://verify.test"])).toBe(2);
  });

  it("exits 0 and prints only attested values for a bound domain", async () => {
    expect(await runCli(["validate", DOMAIN, "--verifier", "https://verify.test"], deps())).toBe(0);
    const text = printed(out);
    expect(text).toContain("holder of VAT ESB12345678 (ACME EJEMPLO SL)");
    expect(text).not.toContain("Acme Ejemplo, S.L."); // the self-declared legalName is never printed
  });

  it("exits 1 when the document's verifier is not trusted (default list)", async () => {
    expect(await runCli(["validate", DOMAIN], deps())).toBe(1);
    expect(printed(err)).toMatch(/not a trusted verifier/);
  });

  it("binds nothing through the default verifier until a key is pinned", async () => {
    // Fail-closed by design: DEFAULT_VERIFIERS pins keys, and none exist yet.
    expect(DEFAULT_VERIFIERS[0].keys).toEqual([]);
  });

  it("exits 3 when the domain has no business.json", async () => {
    expect(await runCli(["validate", "nothing.example", "--verifier", "https://verify.test"], deps())).toBe(3);
    expect(printed(out)).toMatch(/UNKNOWN/);
  });

  it("check-file exits 4 (shape only) or 1, never 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bj-"));
    const good = join(dir, "good.json");
    const bad = join(dir, "bad.json");
    const big = join(dir, "big.json");
    writeFileSync(good, JSON.stringify(makeDoc()));
    writeFileSync(bad, JSON.stringify({ ...makeDoc(), vat: "nope" }));
    writeFileSync(big, " ".repeat(70 * 1024));
    expect(await runCli(["check-file", good])).toBe(4);
    expect(await runCli(["check-file", bad])).toBe(1);
    expect(await runCli(["check-file", big])).toBe(1);
    expect(printed(err)).toMatch(/larger than/);
  });

  it("treats a .json-looking argument to validate as a domain, not a file", async () => {
    expect(await runCli(["validate", "./good.json", "--verifier", "https://verify.test"], deps())).toBe(1);
    expect(printed(err)).toMatch(/is not a hostname/);
  });

  // Needs `npm run build` first (CI order: build → test).
  it("runs as a built binary (usage exit code)", () => {
    const bin = new URL("../dist/cli.js", import.meta.url);
    expect(existsSync(bin), "dist/cli.js missing — run npm run build before npm test").toBe(true);
    let status: number | undefined;
    try {
      execFileSync(process.execPath, [bin.pathname], { stdio: "pipe" });
    } catch (e) {
      status = (e as { status?: number }).status;
    }
    expect(status).toBe(2);
  });
});
