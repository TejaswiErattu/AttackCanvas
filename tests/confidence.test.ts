import { describe, expect, it } from "vitest";
import { confidenceOf, explainConfidence } from "@/shared/confidence";
import { scoreThreat } from "@/server/scoring";
import type { DraftThreat, Evidence } from "@/shared/schema";

const code: Evidence = { id: "e-code", kind: "code", source: "detector", summary: "c" };
const semgrep: Evidence = { id: "e-sg", kind: "scanner", source: "semgrep", summary: "s" };
const inference: Evidence = { id: "e-inf", kind: "inference", source: "ai", summary: "i" };
const gap: Evidence = {
  id: "ev-gap-1", kind: "code", source: "detector", ruleId: "gap:authz_missing", summary: "g",
};

describe("explainConfidence", () => {
  it("returns confidenceOf's own breakdown when nothing is uncertain", () => {
    const cited = [code, semgrep];
    const { value, breakdown } = confidenceOf(cited, new Map(), ["assume"]);
    expect(explainConfidence(cited, ["assume"], value)).toEqual({ exact: true, lines: breakdown });
  });

  it("is exact for inference-only, where the points come from inference alone", () => {
    const result = explainConfidence([inference], [], 0.2);
    expect(result).toEqual({ exact: true, lines: ["+0.20 inference only"] });
  });

  it("is qualitative whenever gap evidence is cited, whatever the stored confidence", () => {
    for (const confidence of [0, 0.3, 0.4, 0.9]) {
      const result = explainConfidence([gap], [], confidence);
      expect(result.exact).toBe(false);
      expect(result.lines.join("\n")).not.toMatch(/\d\.\d\d/);
    }
  });

  it("is qualitative when the stored confidence does not match the evidence", () => {
    expect(explainConfidence([code], [], 0.36).exact).toBe(false);
    expect(explainConfidence([code], [], 0.35).exact).toBe(true);
  });

  it("stays qualitative for a threat scoreThreat really scored from a gap", () => {
    const draft: DraftThreat = {
      title: "t", stride: ["E"], owasp: ["A01:2025"], cwe: [], componentIds: [], dataFlowIds: [],
      asset: "a", attackScenario: "s", evidenceIds: [gap.id, code.id], assumptions: [],
      dependsOnUnknownIds: [], impact: 4, likelihood: 4, impactReason: "r", likelihoodReason: "r",
      mitigation: { summary: "m", steps: [] },
    };
    const gaps = new Map([[gap.id, { control: "role check", certainty: 0.9 } as never]]);
    const { threat } = scoreThreat(draft, "t1", [gap, code], gaps);
    const result = explainConfidence([gap, code], [], threat.confidence);
    expect(result.exact).toBe(false);
    expect(result.lines).toContain("Backed by code or configuration evidence");
  });
});
