/**
 * The dashboard's empty state when every scored threat is hidden (< 0.25 confidence):
 * summarizeHidden (server, derived like countByBasis), readHiddenSummary (client
 * normaliser) and emptyMessage (the text ThreatList shows).
 */
import { describe, expect, it } from "vitest";
import { hiddenReasonOf, summarizeHidden } from "@/server/analysis/pipeline";
import { readHiddenSummary } from "@/client/useAnalysis";
import { emptyMessage } from "@/components/ThreatList";
import type { Threat } from "@/shared/schema";

function t(confidence: number, over: Partial<Threat> = {}): Threat {
  return {
    id: `threat-${Math.round(confidence * 1000)}-${over.evidenceIds?.length ?? 0}-${over.assumptions?.length ?? 0}`,
    title: "t",
    stride: ["I"],
    owasp: ["A01:2025"],
    cwe: ["CWE-200"],
    componentIds: ["api"],
    dataFlowIds: [],
    asset: "data",
    attackScenario: "s",
    evidenceIds: [],
    assumptions: [],
    dependsOnUnknownIds: [],
    impact: 3,
    likelihood: 3,
    impactReason: "r",
    likelihoodReason: "r",
    severity: "medium",
    confidence,
    confidenceLabel: "low",
    basis: "assumption_dependent",
    mitigation: { summary: "m", steps: ["s"] },
    priority: "monitor",
    ...over,
  };
}

describe("hiddenReasonOf", () => {
  it("prefers no evidence, then assumptions, then weak evidence", () => {
    expect(hiddenReasonOf(t(0, { assumptions: ["a"] }))).toBe("no_evidence");
    expect(hiddenReasonOf(t(0.2, { evidenceIds: ["ev-1"], assumptions: ["a"] }))).toBe("assumptions");
    expect(hiddenReasonOf(t(0.2, { evidenceIds: ["ev-1"] }))).toBe("weak_evidence");
  });
});

describe("summarizeHidden", () => {
  it("counts hidden threats and the most common reason; 0.25 itself is shown", () => {
    const summary = summarizeHidden([
      t(0.15, { assumptions: ["a"] }),
      t(0.0, { assumptions: ["a", "b"] }),
      t(0.2, { evidenceIds: ["ev-1"], assumptions: ["a"] }),
      t(0.25, { evidenceIds: ["ev-1"] }),
    ]);
    expect(summary).toEqual({ scored: 4, hidden: 3, topReason: "no_evidence", topReasonCount: 2 });
  });

  it("has no reason when nothing is hidden", () => {
    expect(summarizeHidden([t(0.5, { evidenceIds: ["ev-1"] })]).topReason).toBeNull();
    expect(summarizeHidden([])).toEqual({ scored: 0, hidden: 0, topReason: null, topReasonCount: 0 });
  });

  it("breaks a tie toward the more basic reason", () => {
    const summary = summarizeHidden([t(0.1), t(0.2, { evidenceIds: ["ev-1"], assumptions: ["a"] })]);
    expect(summary.topReason).toBe("no_evidence");
  });
});

describe("readHiddenSummary", () => {
  it("normalises junk and rejects an unknown reason", () => {
    expect(readHiddenSummary(undefined)).toBeNull();
    expect(readHiddenSummary({ scored: 3, hidden: "x", topReason: "<b>", topReasonCount: 1 })).toEqual({
      scored: 3,
      hidden: 0,
      topReason: null,
      topReasonCount: 1,
    });
  });
});

describe("emptyMessage", () => {
  it("says all N were scored and hidden, with the most common reason", () => {
    expect(emptyMessage(0, { scored: 29, hidden: 29, topReason: "no_evidence", topReasonCount: 28 })).toBe(
      "29 threats were scored; all fell below 25% confidence. Most common reason: no cited evidence (28 of 29).",
    );
  });

  it("keeps the old texts when nothing was hidden, or when filters emptied the list", () => {
    expect(emptyMessage(0, null)).toBe("This analysis produced no threats above the confidence threshold.");
    expect(emptyMessage(0, { scored: 0, hidden: 0, topReason: null, topReasonCount: 0 })).toBe(
      "This analysis produced no threats above the confidence threshold.",
    );
    expect(emptyMessage(3, { scored: 5, hidden: 2, topReason: "assumptions", topReasonCount: 2 })).toContain(
      "current filters",
    );
  });

  it("uses the singular for one threat", () => {
    expect(emptyMessage(0, { scored: 1, hidden: 1, topReason: "assumptions", topReasonCount: 1 })).toBe(
      "1 threat was scored; all fell below 25% confidence. Most common reason: unconfirmed assumptions (1 of 1).",
    );
  });
});
