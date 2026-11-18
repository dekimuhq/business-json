import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { runCli } from "./cli.js";
import { DOMAIN, NOW, goodTxt, makeDoc, makeRecord, makeVerifier, mockFetch, noCname } from "./test-helpers.js";

vi.spyOn(console, "log").mockImplementation(() => {});
vi.spyOn(console, "error").mockImplementation(() => {});

function deps() {
  const v = makeVerifier("https://verify.test");
  const doc = makeDoc();
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

  it("exits 0 for a bound domain with an explicitly trusted verifier", async () => {
    expect(await runCli(["validate", DOMAIN, "--verifier", "https://verify.test"], deps())).toBe(0);
  });

  it("exits 1 when the document's verifier is not in the trusted list (default list)", async () => {
    expect(await runCli(["validate", DOMAIN], deps())).toBe(1);
  });

  it("exits 3 when the domain has no business.json", async () => {
    expect(await runCli(["validate", "nothing.example", "--verifier", "https://verify.test"], deps())).toBe(3);
  });

  it("schema-checks a local file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bj-"));
    const good = join(dir, "good.json");
    const bad = join(dir, "bad.json");
    writeFileSync(good, JSON.stringify(makeDoc()));
    writeFileSync(bad, JSON.stringify({ ...makeDoc(), vat: "nope" }));
    expect(await runCli(["validate", good])).toBe(0);
    expect(await runCli(["validate", bad])).toBe(1);
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
