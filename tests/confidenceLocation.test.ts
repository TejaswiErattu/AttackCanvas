/**
 * CLAUDE.md rule 2: evidence items pointing to the same file and line count as one source.
 * The highest-scoring item at a shared location is kept, and it earns no second-source bonus.
 */

import { describe, expect, it } from "vitest";
import { confidenceOf } from "@/server/scoring";
import type { ControlGap } from "@/server/detect/types";
import type { Evidence } from "@/shared/schema";

const at = (id: string, over: Partial<Evidence>, filePath?: string, lineStart?: number): Evidence => ({
  id, kind: "code", source: "detector", summary: id,
  ...(filePath !== undefined ? { filePath } : {}),
  ...(lineStart !== undefined ? { lineStart } : {}),
  ...over,
});

const osv = (id: string, file?: string, line?: number) =>
  at(id, { kind: "dependency", source: "osv", ruleId: "GHSA-x" }, file, line);
const code = (id: string, file?: string, line?: number) => at(id, { kind: "config" }, file, line);
const semgrep = (id: string, file?: string, line?: number) =>
  at(id, { kind: "scanner", source: "semgrep", ruleId: "r" }, file, line);

const score = (evidence: Evidence[], assumptions: string[] = []) =>
  confidenceOf(evidence, new Map(), assumptions, ["CWE-400"]);

describe("same-line evidence", () => {
  it("counts a dependency declaration and an advisory on the same manifest line once (NodeGoat t46)", () => {
    const r = score([code("ev-datastore-1", "package.json", 18), osv("ev-osv-2", "package.json", 18)], ["a"]);
    expect(r.value).toBe(0.2); // 0.35 kept, no +0.30, no +0.10, -0.15
    expect(r.breakdown).toEqual(["+0.35 code evidence", "-0.15 unconfirmed assumption: a"]);
  });

  it("keeps the highest-scoring item, whatever the order", () => {
    const a = score([osv("o", "package.json", 18), code("c", "package.json", 18)]);
    const b = score([code("c", "package.json", 18), osv("o", "package.json", 18)]);
    expect(a.value).toBe(0.35);
    expect(b.value).toBe(0.35);
  });

  it("keeps the advisory over a Semgrep finding on the same line (0.30 > 0.25)", () => {
    const r = score([semgrep("s", "app.js", 7), osv("o", "app.js", 7)]);
    expect(r.breakdown).toEqual(["+0.30 known vulnerable dependency (OSV)"]);
  });

  it("does not merge a control gap with the route line it describes (NodeGoat IDOR t3/t52)", () => {
    const gapEv = at("ev-gap-1", { ruleId: "gap:authz_missing" }, "app/routes/index.js", 63);
    const gaps = new Map<string, ControlGap>([
      ["ev-gap-1", { control: "ownership check", certainty: 0.7 } as ControlGap],
    ]);
    const r = confidenceOf([gapEv, code("route", "app/routes/index.js", 63)], gaps, ["a"], ["CWE-639"]);
    expect(r.value).toBe(0.51); // 0.35 + 0.21 + 0.10 - 0.15, as before the rule
  });

  it("merges only on the same line, not the same file", () => {
    const r = score([code("c", "package.json", 18), osv("o", "package.json", 13)]);
    expect(r.value).toBe(0.75); // 0.35 + 0.30 + 0.10
  });
});

describe("genuinely separate locations", () => {
  it("still scores two kinds of evidence at different files, with the second-source bonus", () => {
    const r = score([code("route", "app/routes/index.js", 67), osv("o", "package.json", 17)], ["a"]);
    expect(r.value).toBe(0.6); // 0.35 + 0.30 + 0.10 - 0.15 (NodeGoat t79 keeps its score)
    expect(r.breakdown).toContain("+0.10 second independent source (2 kinds)");
  });

  it("does not merge two items of the same kind on different lines", () => {
    expect(score([osv("a", "package.json", 13), osv("b", "package.json", 17)]).value).toBe(0.3);
  });
});

describe("missing location data", () => {
  it("never merges an item that has no file", () => {
    expect(score([code("c", undefined, 18), osv("o", undefined, 18)]).value).toBe(0.75);
  });

  it("never merges an item that has a file but no line", () => {
    expect(score([code("c", "package.json"), osv("o", "package.json")]).value).toBe(0.75);
  });

  it("does not merge a located item with an unlocated one", () => {
    expect(score([code("c", "package.json", 18), osv("o", "package.json")]).value).toBe(0.75);
  });
});
