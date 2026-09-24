/**
 * The pure parts of scripts/try-pipeline.ts. The script itself is not imported: it runs a
 * live, paid analysis on load.
 */

import { describe, expect, it } from "vitest";
import {
  formatStageLine,
  formatSummary,
  parseTarget,
  parseTimeoutMs,
} from "../scripts/try-pipeline-lib";

describe("parseTarget", () => {
  it("reads shorthand owner/repo", () => {
    expect(parseTarget("acme/canary")).toEqual({ owner: "acme", repo: "canary" });
  });

  it("reads a github.com URL, trimming a trailing .git and any path/query", () => {
    expect(parseTarget("https://github.com/acme/canary.git")).toEqual({
      owner: "acme",
      repo: "canary",
    });
    expect(parseTarget("https://github.com/acme/canary/tree/main")).toEqual({
      owner: "acme",
      repo: "canary",
    });
  });

  it("throws on input that is neither", () => {
    expect(() => parseTarget("not a target")).toThrow();
  });
});

describe("parseTimeoutMs", () => {
  const MAX = 2_147_483_647;

  it("returns the default when no value is given", () => {
    expect(parseTimeoutMs(undefined, 600_000, MAX)).toEqual({ ok: true, value: 600_000 });
  });

  it("accepts a positive integer up to the ceiling", () => {
    expect(parseTimeoutMs("50", 600_000, MAX)).toEqual({ ok: true, value: 50 });
    expect(parseTimeoutMs(String(MAX), 600_000, MAX)).toEqual({ ok: true, value: MAX });
  });

  it("rejects zero, negatives, fractions and non-numbers", () => {
    for (const raw of ["0", "-5", "1.5", "abc", ""]) {
      expect(parseTimeoutMs(raw, 600_000, MAX).ok).toBe(false);
    }
  });

  it("rejects a value above the ceiling, which setTimeout would clamp to 1 ms", () => {
    const parsed = parseTimeoutMs(String(MAX + 1), 600_000, MAX);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.message).toContain(String(MAX));
  });
});

describe("formatStageLine", () => {
  it("reads the current STAGE_LABELS copy, including the Prompt V mod-1 scanning line", () => {
    expect(formatStageLine("scanning", 12.34)).toBe(
      "[  12.3s] scanning — Scanning code, dependencies and missing controls",
    );
  });

  it("pads short elapsed times", () => {
    expect(formatStageLine("queued", 0)).toBe("[   0.0s] queued — Queued");
  });
});

describe("formatSummary", () => {
  it("reports the error line and nothing else for a failed state", () => {
    const lines = formatSummary(
      {
        stage: "failed",
        error: { code: "TIMEOUT", message: "The analysis took too long to finish. Please try again." },
        threatModel: undefined,
        questions: undefined,
        cost: { calls: 2, totalUsd: 0.05 },
      },
      { evidence_backed: 0, assumption_dependent: 0 },
      42.1,
    );
    expect(lines[0]).toBe("stage: failed | elapsed 42.1s");
    expect(lines[1]).toBe(
      "error: [TIMEOUT] The analysis took too long to finish. Please try again.",
    );
    expect(lines).toHaveLength(2);
  });

  it("reports threats, basis counts, questions, gaps, limitations and cost for a complete state", () => {
    const lines = formatSummary(
      {
        stage: "complete",
        error: undefined,
        threatModel: {
          schemaVersion: "1.0",
          analysisLevel: 2,
          repo: {
            owner: "acme",
            name: "canary",
            ref: "main",
            languages: [],
            frameworks: [],
            fileCountAnalyzed: 1,
            analyzedAt: new Date(0).toISOString(),
          },
          components: [],
          dataFlows: [],
          trustBoundaries: [],
          unknowns: [],
          evidence: [
            { id: "ev-gap-1", kind: "inference", source: "detector", summary: "x", ruleId: "gap:authn_missing" },
            { id: "ev-route-1", kind: "code", source: "detector", summary: "y" },
          ],
          threats: [],
          questions: [],
          assumptions: [],
          limitations: ["one", "two"],
        },
        questions: [],
        cost: { calls: 3, totalUsd: 0.12 },
      },
      { evidence_backed: 1, assumption_dependent: 2 },
      5,
    );
    expect(lines).toEqual([
      "stage: complete | elapsed 5.0s",
      "threats: 0",
      "  by basis: evidence_backed 1 | assumption_dependent 2",
      "questions: 0",
      "gaps: 1",
      "limitations: 2",
      "cost: $0.1200 (3 provider response(s))",
    ]);
  });
});
