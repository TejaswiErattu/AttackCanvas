/**
 * Runs the real rule pack through a local semgrep binary, offline (--metrics=off, a local
 * config, no registry), to pin rule behaviour that string checks on SECURITY_RULESET
 * cannot. Skipped when semgrep is not installed, so CI without it still passes; the skip
 * is reported by Vitest, not hidden.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { SECURITY_RULESET } from "@/server/mcp/semgrepRules";

const available = spawnSync("semgrep", ["--version"], { encoding: "utf8" }).status === 0;
const dir = mkdtempSync(join(tmpdir(), "attackcanvas-semgrep-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** Line numbers where `ruleId` fires on `source`. */
function linesFor(ruleId: string, source: string): number[] {
  const rules = join(dir, "rules.yml");
  const target = join(dir, "sample.js");
  writeFileSync(rules, SECURITY_RULESET);
  writeFileSync(target, source);

  const run = spawnSync(
    "semgrep",
    ["scan", "--config", rules, "--metrics=off", "--disable-version-check", "--json", "--quiet", target],
    { encoding: "utf8", timeout: 120_000 },
  );
  const parsed = JSON.parse(run.stdout) as {
    results: { check_id: string; start: { line: number } }[];
  };
  return parsed.results
    .filter((r) => r.check_id.endsWith(ruleId))
    .map((r) => r.start.line);
}

describe.skipIf(!available)("attackcanvas-jwt-verify-none (real semgrep)", () => {
  it("does not match TextDecoder().decode, the tejaswisummer false positive", () => {
    const source = `function b64urlToJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}
const text = decoder.decode(bytes);
`;
    expect(linesFor("attackcanvas-jwt-verify-none", source)).toEqual([]);
  }, 180_000);

  it("still matches jwt.decode(token) and the algorithms: none form", () => {
    const source = `const jwt = require("jsonwebtoken");
const claims = jwt.decode(token);
jwt.verify(token, key, { algorithms: ["HS256", "none"] });
`;
    expect(linesFor("attackcanvas-jwt-verify-none", source)).toEqual([2, 3]);
  }, 180_000);
});
