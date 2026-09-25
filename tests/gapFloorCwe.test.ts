/**
 * CLAUDE.md rule 2, CWE-scoped gap floor: a gap-only threat is lifted to 0.40 only when
 * every CWE it claims is one its cited gaps assert. A real missing control does not vouch
 * for a weakness built on top of it (clickjacking or XSS on top of missing headers).
 */

import { describe, expect, it } from "vitest";
import { confidenceOf, explainConfidence, scoreThreat } from "@/server/scoring";
import type { ControlGap } from "@/server/detect/types";
import type { DraftThreat, Evidence } from "@/shared/schema";

function gapEvidence(id: string, kind: string): Evidence {
  return { id, kind: "code", source: "detector", ruleId: `gap:${kind}`, summary: kind };
}

function gap(id: string, kind: string, cwe: string[], certainty = 0.8): ControlGap {
  return { id, kind, control: kind, certainty, cwe } as unknown as ControlGap;
}

const CSRF_EV = gapEvidence("ev-gap-2", "csrf_missing");
const HEADERS_EV = gapEvidence("ev-gap-3", "security_headers_missing");
const GAPS = new Map<string, ControlGap>([
  ["ev-gap-2", gap("gap-2", "csrf_missing", ["CWE-352"], 0.8)],
  ["ev-gap-3", gap("gap-3", "security_headers_missing", ["CWE-693"], 0.9)],
]);
const ONE_ASSUMPTION = ["The session cookie is sent on cross-site posts."];

const score = (evidence: Evidence[], cwe: string[], assumptions = ONE_ASSUMPTION) =>
  confidenceOf(evidence, GAPS, assumptions, cwe);

describe("matching CWEs", () => {
  it("floors a CSRF threat that claims only the CSRF gap's CWE", () => {
    const r = score([CSRF_EV], ["CWE-352"]);
    expect(r.value).toBe(0.4); // raw 0.24 - 0.15 = 0.09
    expect(r.breakdown.at(-1)).toBe("floor 0.40 applied: gap-only with high certainty");
  });

  it("floors a headers threat that claims only CWE-693, and ignores repeated tags", () => {
    expect(score([HEADERS_EV], ["CWE-693", "CWE-693"]).value).toBe(0.4);
  });
});

describe("extra CWEs", () => {
  it("does not floor a headers threat that also claims clickjacking (CWE-1021)", () => {
    const r = score([HEADERS_EV], ["CWE-1021", "CWE-693"]);
    expect(r.value).toBe(0.12); // raw 0.27 - 0.15, left as is
    expect(r.breakdown.at(-1)).toBe(
      "floor 0.40 not applied: the threat also claims CWE-1021, which the cited gaps do not assert",
    );
  });

  it("does not floor when none of the claimed CWEs is the gap's", () => {
    const r = score([HEADERS_EV], ["CWE-79"]);
    expect(r.value).toBe(0.12);
    expect(r.breakdown.at(-1)).toMatch(/also claims CWE-79/);
  });
});

describe("multiple gaps", () => {
  it("allows the union of the cited gaps' CWEs", () => {
    expect(score([CSRF_EV, HEADERS_EV], ["CWE-352", "CWE-693"]).value).toBe(0.4);
  });

  it("does not use the CWE of a gap the threat does not cite", () => {
    expect(score([HEADERS_EV], ["CWE-693", "CWE-352"]).value).toBe(0.12);
  });

  it("ignores the CWE of a cited gap missing from the map (it has no certainty either)", () => {
    const unmapped = gapEvidence("ev-gap-9", "csrf_missing");
    const r = score([HEADERS_EV, unmapped], ["CWE-693", "CWE-352"]);
    expect(r.breakdown.at(-1)).toMatch(/also claims CWE-352/);
  });
});

describe("missing CWE tags", () => {
  it("does not floor a threat that claims no CWE", () => {
    const r = score([CSRF_EV], []);
    expect(r.value).toBe(0.09);
    expect(r.breakdown.at(-1)).toBe("floor 0.40 not applied: the threat claims no CWE");
  });

  it("does not floor when the cited gap asserts no CWE", () => {
    const bare = new Map([["ev-gap-2", { control: "CSRF protection", certainty: 0.8 }]]);
    const r = confidenceOf([CSRF_EV], bare, ONE_ASSUMPTION, ["CWE-352"]);
    expect(r.value).toBe(0.09);
    expect(r.breakdown.at(-1)).toMatch(/also claims CWE-352/);
  });
});

describe("threats with other evidence", () => {
  const route: Evidence = { id: "ev-route-13", kind: "code", source: "detector", summary: "POST /benefits" };
  const semgrep: Evidence = { id: "ev-semgrep-3", kind: "scanner", source: "semgrep", ruleId: "r", summary: "eval" };

  it("scores route + gap normally whatever the CWEs, with no floor line", () => {
    const r = score([CSRF_EV, route], ["CWE-352", "CWE-639"]);
    expect(r.value).toBe(0.54); // 0.35 + 0.24 + 0.10 - 0.15
    expect(r.breakdown.some((l) => l.startsWith("floor"))).toBe(false);
  });

  it("scores Semgrep + gap normally", () => {
    expect(score([CSRF_EV, semgrep], ["CWE-1021"]).value).toBe(0.44); // 0.25 + 0.24 + 0.10 - 0.15
  });

  it("does not consider the floor (or add a line) when gap certainty is below 0.8", () => {
    const weak = new Map([["ev-gap-3", gap("gap-3", "security_headers_missing", ["CWE-693"], 0.5)]]);
    const r = confidenceOf([HEADERS_EV], weak, [], ["CWE-693"]);
    expect(r.value).toBe(0.15);
    expect(r.breakdown.some((l) => l.startsWith("floor"))).toBe(false);
  });
});

describe("scoreThreat and the explanation", () => {
  const draft = (cwe: string[]): DraftThreat => ({
    title: "t", stride: ["T"], owasp: ["A01:2025"], cwe, componentIds: [], dataFlowIds: [],
    asset: "a", attackScenario: "s", evidenceIds: ["ev-gap-3"], assumptions: ONE_ASSUMPTION,
    dependsOnUnknownIds: [], impact: 4, likelihood: 3, impactReason: "r", likelihoodReason: "r",
    mitigation: { summary: "m", steps: ["s"] },
  });

  it("uses the draft's own CWE list: in scope is visible, clickjacking is hidden", () => {
    const inScope = scoreThreat(draft(["CWE-693"]), "t1", [HEADERS_EV], GAPS);
    const beyond = scoreThreat(draft(["CWE-1021", "CWE-693"]), "t2", [HEADERS_EV], GAPS);
    expect([inScope.threat.confidence, inScope.hidden]).toEqual([0.4, false]);
    expect([beyond.threat.confidence, beyond.hidden]).toEqual([0.12, true]);
  });

  it("explains a floored gap-only threat as raised, and an unfloored one as not raised", () => {
    const raised = explainConfidence([HEADERS_EV], ONE_ASSUMPTION, 0.4);
    const notRaised = explainConfidence([HEADERS_EV], ONE_ASSUMPTION, 0.12);
    expect(raised.exact).toBe(false);
    expect(raised.lines.at(-1)).toMatch(/^Raised to the 40% minimum/);
    expect(notRaised.lines.at(-1)).toMatch(/^Not raised to the 40% minimum/);
    for (const r of [raised, notRaised]) expect(r.lines.join("\n")).not.toMatch(/\d\.\d\d/);
  });

  it("adds no floor line when other evidence contributes", () => {
    const route: Evidence = { id: "ev-route-1", kind: "code", source: "detector", summary: "r" };
    const r = explainConfidence([HEADERS_EV, route], ONE_ASSUMPTION, 0.47);
    expect(r.lines.some((l) => /40% minimum/.test(l))).toBe(false);
  });
});
