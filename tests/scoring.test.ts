import { describe, expect, it } from "vitest";
import {
  basisOf,
  confidenceLabelOf,
  confidenceOf,
  isHidden,
  priorityOf,
  scoreThreat,
  severityOf,
} from "@/server/scoring";
import type { ControlGap } from "@/server/detect/types";
import { ThreatSchema, type DraftThreat, type Evidence } from "@/shared/schema";

let n = 0;
function ev(over: Partial<Evidence>): Evidence {
  n += 1;
  return {
    id: `ev-${n}`,
    kind: "code",
    source: "detector",
    summary: "s",
    ...over,
  };
}
const code = () => ev({ kind: "code", ruleId: "route:handler" });
const semgrep = () => ev({ kind: "scanner", source: "semgrep", ruleId: "r" });
const osv = () => ev({ kind: "dependency", source: "osv", ruleId: "GHSA-x" });
const dev = () => ev({ kind: "developer_answer", source: "developer" });
const inference = () => ev({ kind: "inference", source: "ai" });
const assumptionEv = () => ev({ kind: "assumption", source: "ai" });

function gap(certainty: number, id = `gap-${++n}`): {
  evidence: Evidence;
  entry: [string, ControlGap];
} {
  const evidence = ev({ id: `ev-${id}`, kind: "code", ruleId: "gap:authz_missing" });
  const g = {
    id,
    kind: "authz_missing",
    control: "ownership check",
    certainty,
    cwe: ["CWE-639"],
  } as ControlGap;
  return { evidence, entry: [evidence.id, g] };
}

/** `cwe` defaults to the gap helper's own CWE, so the floor is in scope unless a test says not. */
function score(
  evidence: Evidence[],
  gaps: [string, ControlGap][] = [],
  assumptions: string[] = [],
  cwe: string[] = ["CWE-639"],
) {
  return confidenceOf(evidence, new Map(gaps), assumptions, cwe);
}

const baseDraft: DraftThreat = {
  title: "IDOR on notes",
  stride: ["E"],
  owasp: ["A01:2025"],
  cwe: ["CWE-639"],
  componentIds: [],
  dataFlowIds: [],
  asset: "notes",
  attackScenario: "read another user's note",
  evidenceIds: [],
  assumptions: [],
  dependsOnUnknownIds: [],
  impact: 4,
  likelihood: 4,
  impactReason: "r",
  likelihoodReason: "r",
  mitigation: { summary: "check owner", steps: ["add check"] },
};

describe("severityOf", () => {
  it("maps every impact x likelihood pair by risk band", () => {
    for (let i = 1; i <= 5; i++) {
      for (let l = 1; l <= 5; l++) {
        const risk = i * l;
        const expected =
          risk >= 20 ? "critical" : risk >= 12 ? "high" : risk >= 6 ? "medium" : "low";
        expect(severityOf(i, l)).toBe(expected);
      }
    }
  });

  it("hits the exact boundaries", () => {
    expect(severityOf(1, 5)).toBe("low"); // 5
    expect(severityOf(2, 3)).toBe("medium"); // 6
    expect(severityOf(3, 3)).toBe("medium"); // 9
    expect(severityOf(2, 5)).toBe("medium"); // 10
    expect(severityOf(3, 4)).toBe("high"); // 12
    expect(severityOf(4, 4)).toBe("high"); // 16
    expect(severityOf(5, 3)).toBe("high"); // 15
    expect(severityOf(4, 5)).toBe("critical"); // 20
    expect(severityOf(5, 5)).toBe("critical"); // 25
  });
});

describe("confidenceOf points", () => {
  it("scores each category alone", () => {
    expect(score([code()]).value).toBe(0.35);
    expect(score([semgrep()]).value).toBe(0.25);
    expect(score([osv()]).value).toBe(0.3);
    expect(score([dev()]).value).toBe(0.3);
    expect(score([inference()]).value).toBe(0.2);
  });

  it("gives config evidence code points", () => {
    expect(score([ev({ kind: "config" })]).value).toBe(0.35);
  });

  it("earns nothing from a scanner or dependency source it does not weight", () => {
    expect(score([ev({ kind: "scanner", source: "detector" })]).value).toBe(0);
    expect(score([ev({ kind: "dependency", source: "detector" })]).value).toBe(0);
  });

  it("counts each category once however many items", () => {
    expect(score([code(), code(), code()]).value).toBe(0.35);
    expect(score([semgrep(), semgrep()]).value).toBe(0.25);
  });

  it("adds the second-source bonus once, for two or more distinct categories", () => {
    expect(score([code(), semgrep()]).value).toBe(0.7); // .35+.25+.10
    expect(score([code(), semgrep(), osv()]).value).toBe(1); // .35+.25+.30+.10 = 1.0
    expect(score([code(), code()]).value).toBe(0.35);
  });

  it("gives inference-only points only when nothing else contributes", () => {
    expect(score([inference(), inference()]).value).toBe(0.2);
    expect(score([inference(), code()]).value).toBe(0.35);
    expect(score([inference(), assumptionEv()]).value).toBe(0.2);
  });

  it("subtracts 0.15 per assumption and clamps at 0", () => {
    expect(score([code()], [], ["a"]).value).toBe(0.2);
    expect(score([code()], [], ["a", "b"]).value).toBe(0.05);
    expect(score([code()], [], ["a", "b", "c"]).value).toBe(0);
    expect(score([], [], []).value).toBe(0);
  });

  it("clamps at 1", () => {
    expect(score([code(), semgrep(), osv(), dev()]).value).toBe(1);
  });
});

describe("gap term and floor", () => {
  it("scales the gap by certainty", () => {
    const g = gap(0.5);
    expect(score([g.evidence], [g.entry]).value).toBe(0.15);
  });

  it("uses the strongest gap once", () => {
    const a = gap(0.5);
    const b = gap(0.6);
    // .18, sum 1.1 >= .8 but .18 < .40 so floor lifts it
    expect(score([a.evidence, b.evidence], [a.entry, b.entry]).value).toBe(0.4);
  });

  it("treats a gap missing from the map as certainty 0", () => {
    const g = gap(0.9);
    expect(score([g.evidence], []).value).toBe(0);
  });

  it("applies the floor at exactly 0.8 combined certainty", () => {
    const a = gap(0.4);
    const b = gap(0.4);
    expect(score([a.evidence, b.evidence], [a.entry, b.entry]).value).toBe(0.4);
  });

  it("applies the floor when certainties whose float sum is 0.7999999999999999 reach 0.8", () => {
    // 0.7 + 0.1 === 0.7999999999999999 in IEEE doubles; summed in thousandths it is 800.
    expect(0.7 + 0.1 < 0.8).toBe(true); // the float trap this guards against
    const a = gap(0.7);
    const b = gap(0.1);
    const r = score([a.evidence, b.evidence], [a.entry, b.entry]);
    expect(r.value).toBe(0.4);
    expect(r.breakdown.at(-1)).toBe("floor 0.40 applied: gap-only with high certainty");
  });

  it("does not apply the floor just under 0.8", () => {
    const g = gap(0.79);
    expect(score([g.evidence], [g.entry]).value).toBe(0.237);
  });

  it("does not lift a value already above the floor or add a floor line", () => {
    const g = gap(1);
    const r = score([g.evidence], [g.entry]);
    expect(r.value).toBe(0.4);
    const c = code();
    const mixed = score([g.evidence, c], [g.entry]);
    expect(mixed.value).toBe(0.75); // .30+.35+.10
    expect(mixed.breakdown.some((l) => l.startsWith("floor"))).toBe(false);
  });

  it("does not apply the floor when the gap is mixed with other evidence", () => {
    const g = gap(0.95);
    const r = score([g.evidence, code()], [g.entry], ["a", "b", "c"]);
    expect(r.breakdown.some((l) => l.startsWith("floor"))).toBe(false);
  });

  // CLAUDE.md rule 2: an inference is a conclusion, not direct supporting evidence. It is
  // not one of the "supporting evidence items" the floor looks at, so it neither blocks
  // the floor for a gap-only threat nor adds certainty toward it.
  describe("inference evidence and the floor", () => {
    it("does not block the floor: a near-certain gap plus an inference is still gap-only", () => {
      const g = gap(0.9);
      const r = score([g.evidence, inference()], [g.entry]);
      expect(r.value).toBe(0.4); // raw 0.27, floored
      expect(r.breakdown.at(-1)).toBe("floor 0.40 applied: gap-only with high certainty");
      expect(r.breakdown.some((l) => l.includes("inference"))).toBe(false);
    });

    it("does not satisfy the floor on its own: an inference with no gap gets no floor", () => {
      const r = score([inference(), inference()]);
      expect(r.value).toBe(0.2);
      expect(r.breakdown.some((l) => l.startsWith("floor"))).toBe(false);
    });

    it("does not count toward the 0.8 certainty the floor needs", () => {
      const g = gap(0.5);
      const r = score([g.evidence, inference(), inference()], [g.entry]);
      expect(r.value).toBe(0.15); // gap only, sum 0.5 < 0.8: no floor
      expect(r.breakdown.some((l) => l.startsWith("floor"))).toBe(false);
    });
  });

  it("writes a readable breakdown", () => {
    const g = gap(0.95);
    expect(score([g.evidence], [g.entry], ["no auth"]).breakdown).toEqual([
      "+0.29 control gap: no ownership check (certainty 0.95)",
      "-0.15 unconfirmed assumption: no auth",
      "floor 0.40 applied: gap-only with high certainty",
    ]);
  });
});

describe("the four named cases", () => {
  it("gap-only, certainty 0.95 -> 0.40 medium, assumption_dependent", () => {
    const g = gap(0.95);
    const r = score([g.evidence], [g.entry]);
    expect(r.value).toBe(0.4);
    expect(confidenceLabelOf(r.value)).toBe("medium");
    expect(basisOf([g.evidence])).toBe("assumption_dependent");
  });

  it("gap-only, certainty 0.5 -> 0.15 low, hidden", () => {
    const g = gap(0.5);
    const r = score([g.evidence], [g.entry]);
    expect(r.value).toBe(0.15);
    expect(confidenceLabelOf(r.value)).toBe("low");
    expect(isHidden(r.value)).toBe(true);
  });

  it("gap + semgrep -> 0.635 medium, evidence_backed", () => {
    const g = gap(0.95);
    const s = semgrep();
    const r = score([g.evidence, s], [g.entry]);
    expect(r.value).toBe(0.635);
    expect(confidenceLabelOf(r.value)).toBe("medium");
    expect(basisOf([g.evidence, s])).toBe("evidence_backed");
  });

  it("gap + developer answer + second source -> 0.685 medium, evidence_backed", () => {
    const g = gap(0.95);
    const d = dev();
    const r = score([g.evidence, d], [g.entry]);
    expect(r.value).toBe(0.685);
    expect(confidenceLabelOf(r.value)).toBe("medium");
    expect(basisOf([g.evidence, d])).toBe("evidence_backed");
  });
});

describe("Prompt O verification additions", () => {
  // Hand-written, not derived from the implementation's formula.
  const TABLE: Record<number, string> = {
    1: "low", 2: "low", 3: "low", 4: "low", 5: "low",
    6: "medium", 8: "medium", 9: "medium", 10: "medium",
    12: "high", 15: "high", 16: "high",
    20: "critical", 25: "critical",
  };

  it("matches a hand-written risk table for all 25 combinations", () => {
    const seen = new Set<number>();
    for (let i = 1; i <= 5; i++) {
      for (let l = 1; l <= 5; l++) {
        seen.add(i * l);
        expect(severityOf(i, l), `${i}x${l}`).toBe(TABLE[i * l]);
      }
    }
    expect([...seen].sort((a, b) => a - b)).toEqual(Object.keys(TABLE).map(Number));
  });

  it("pins the 5/6, 11/12 and 19/20 boundaries (11 and 19 are not reachable products)", () => {
    expect(severityOf(1, 5)).toBe("low");
    expect(severityOf(2, 3)).toBe("medium");
    expect(severityOf(2, 5)).toBe("medium"); // 10, highest medium
    expect(severityOf(3, 4)).toBe("high"); // 12, lowest high
    expect(severityOf(4, 4)).toBe("high"); // 16
    expect(severityOf(3, 5)).toBe("high"); // 15, highest high before 20
    expect(severityOf(4, 5)).toBe("critical"); // 20
  });

  it("is evidence_backed for each positive source on its own", () => {
    expect(basisOf([code()])).toBe("evidence_backed");
    expect(basisOf([semgrep()])).toBe("evidence_backed");
    expect(basisOf([osv()])).toBe("evidence_backed");
    expect(basisOf([dev()])).toBe("evidence_backed");
  });

  it("counts osv, developer, inference and gap categories once each", () => {
    expect(score([osv(), osv()]).value).toBe(0.3);
    expect(score([dev(), dev()]).value).toBe(0.3);
    expect(score([inference(), inference(), inference()]).value).toBe(0.2);
    const a = gap(0.9);
    const b = gap(0.9);
    expect(score([a.evidence, b.evidence], [a.entry, b.entry]).breakdown.filter((l) => l.includes("control gap"))).toHaveLength(1);
  });

  it("scores several gaps by the strongest only", () => {
    const a = gap(0.4);
    const b = gap(0.3); // sum 0.7 < 0.8: no floor, so the value is visible
    const r = score([a.evidence, b.evidence], [a.entry, b.entry]);
    expect(r.value).toBe(0.12); // 0.30 x 0.4, not 0.30 x 0.7 = 0.21
    expect(r.breakdown).toEqual(["+0.12 control gap: no ownership check (certainty 0.40)"]);
  });

  it("uses the sum of gap certainties for the floor, not the strongest", () => {
    const alone = gap(0.5);
    expect(score([alone.evidence], [alone.entry]).value).toBe(0.15); // no floor alone
    const a = gap(0.5);
    const b = gap(0.3); // sum exactly 0.8
    const r = score([a.evidence, b.evidence], [a.entry, b.entry]);
    expect(r.value).toBe(0.4);
    expect(r.breakdown.at(-1)).toBe("floor 0.40 applied: gap-only with high certainty");
  });

  const NEUTRAL = "control gap not scored: missing or invalid certainty";
  const clean = (r: { value: number; breakdown: string[] }) => {
    expect(Number.isFinite(r.value)).toBe(true);
    for (const line of r.breakdown) expect(line).not.toMatch(/NaN|Infinity|undefined/);
  };

  it("reports a neutral diagnostic when the gap map entry is missing", () => {
    const r = score([gap(0.9).evidence]);
    expect(r).toEqual({ value: 0, breakdown: [NEUTRAL] });
  });

  it("reports the neutral diagnostic for NaN and Infinity certainty", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      const g = gap(bad);
      const r = score([g.evidence], [g.entry]);
      expect(r).toEqual({ value: 0, breakdown: [NEUTRAL] });
    }
    const wrongType = gap(0.9);
    (wrongType.entry[1] as { certainty: unknown }).certainty = "0.9";
    expect(score([wrongType.evidence], [wrongType.entry]).breakdown).toEqual([NEUTRAL]);
  });

  it("clamps finite out-of-range certainty and shows the clamped value", () => {
    const big = gap(7);
    const rb = score([big.evidence], [big.entry]);
    expect(rb.breakdown[0]).toBe("+0.30 control gap: no ownership check (certainty 1.00)");
    expect(rb.value).toBe(0.4); // 0.30, then gap-only floor
    const neg = gap(-2);
    const rn = score([neg.evidence], [neg.entry]);
    expect(rn.breakdown).toEqual(["+0.00 control gap: no ownership check (certainty 0.00)"]);
    expect(rn.value).toBe(0);
  });

  it("still emits the normal numeric line for a valid gap", () => {
    const g = gap(0.6);
    expect(score([g.evidence], [g.entry])).toEqual({
      value: 0.18,
      breakdown: ["+0.18 control gap: no ownership check (certainty 0.60)"],
    });
  });

  it("uses the strongest valid certainty when valid and invalid gaps are mixed", () => {
    const good = gap(0.4);
    const weaker = gap(0.2);
    const nan = gap(Number.NaN);
    const missing = gap(0.99).evidence; // not in the map
    const r = score(
      [nan.evidence, good.evidence, missing, weaker.evidence],
      [nan.entry, good.entry, weaker.entry],
    );
    expect(r.value).toBe(0.12); // sum 0.6 < 0.8, so no floor
    expect(r.breakdown).toEqual(["+0.12 control gap: no ownership check (certainty 0.40)"]);
  });

  it("never returns NaN, Infinity or undefined in a value or breakdown", () => {
    const nan = gap(Number.NaN);
    const inf = gap(Number.POSITIVE_INFINITY);
    const big = gap(7);
    const neg = gap(-2);
    const all = [nan, inf, big, neg];
    clean(score([gap(0.9).evidence]));
    clean(score(all.map((g) => g.evidence), all.map((g) => g.entry), ["a", "b"]));
    for (const g of all) clean(score([g.evidence, code()], [g.entry], ["a"]));
  });

  it("does not hide exactly 0.25 (Semgrep alone) but hides just below it", () => {
    const s = semgrep();
    const draft = { evidenceIds: [s.id], assumptions: [] } as unknown as DraftThreat;
    const r = scoreThreat({ ...baseDraft, ...draft }, "t", [s], new Map());
    expect(r.threat.confidence).toBe(0.25);
    expect(r.hidden).toBe(false);
    expect(isHidden(0.249)).toBe(true);
  });

  it("scores the gap-only, 0.95, one-assumption example end to end", () => {
    const g = gap(0.95);
    const r = scoreThreat(
      { ...baseDraft, evidenceIds: [g.evidence.id], assumptions: ["owner id is trusted"] },
      "t",
      [g.evidence],
      new Map([g.entry]),
    );
    expect(r.threat.confidence).toBe(0.4); // raw 0.285 - 0.15 = 0.135, floored
    expect(r.threat.confidenceLabel).toBe("medium");
    expect(r.threat.basis).toBe("assumption_dependent");
    expect(r.hidden).toBe(false);
    expect(r.breakdown).toEqual([
      "+0.29 control gap: no ownership check (certainty 0.95)",
      "-0.15 unconfirmed assumption: owner id is trusted",
      "floor 0.40 applied: gap-only with high certainty",
    ]);
  });
});

describe("labels, hiding, basis, priority", () => {
  it("labels at the boundaries", () => {
    expect(confidenceLabelOf(0.7)).toBe("high");
    expect(confidenceLabelOf(0.699)).toBe("medium");
    expect(confidenceLabelOf(0.4)).toBe("medium");
    expect(confidenceLabelOf(0.399)).toBe("low");
    expect(confidenceLabelOf(0)).toBe("low");
    expect(confidenceLabelOf(1)).toBe("high");
  });

  it("hides below 0.25 only", () => {
    expect(isHidden(0.249)).toBe(true);
    expect(isHidden(0.25)).toBe(false);
  });

  it("never counts an inference as a positive observation, whatever its ruleId", () => {
    // Rule 2 names ruleId as the test, but an inference is a conclusion, not an
    // observation: one without a "gap:" prefix still leaves the threat assumption-dependent.
    const inferred = ev({ kind: "inference", source: "ai", ruleId: "arch:inferred-datastore" });
    expect(inferred.ruleId?.startsWith("gap:")).toBe(false);
    expect(basisOf([inferred])).toBe("assumption_dependent");
    expect(basisOf([gap(1).evidence, inferred])).toBe("assumption_dependent");
    expect(basisOf([inferred, code()])).toBe("evidence_backed");
  });

  it("computes basis from positive observations", () => {
    expect(basisOf([])).toBe("assumption_dependent");
    expect(basisOf([inference(), assumptionEv()])).toBe("assumption_dependent");
    expect(basisOf([gap(1).evidence])).toBe("assumption_dependent");
    expect(basisOf([gap(1).evidence, inference()])).toBe("assumption_dependent");
    expect(basisOf([inference(), code()])).toBe("evidence_backed");
    expect(basisOf([ev({ kind: "config" })])).toBe("evidence_backed");
  });

  it("assigns priority", () => {
    expect(priorityOf("critical", 0)).toBe("fix_now");
    expect(priorityOf("high", 0.5)).toBe("fix_now");
    expect(priorityOf("high", 0.499)).toBe("fix_soon");
    expect(priorityOf("medium", 0.5)).toBe("fix_soon");
    expect(priorityOf("medium", 0.499)).toBe("monitor");
    expect(priorityOf("low", 1)).toBe("monitor");
  });
});

describe("scoreThreat", () => {
  const draft = baseDraft;

  it("returns a schema-valid Threat using only cited evidence", () => {
    const g = gap(0.95);
    const s = semgrep();
    const uncited = osv();
    const input = { ...draft, evidenceIds: [g.evidence.id, s.id] };
    const snapshot = JSON.stringify(input);
    const r = scoreThreat(input, "threat-1", [g.evidence, s, uncited], new Map([g.entry]));
    expect(ThreatSchema.safeParse(r.threat).success).toBe(true);
    expect(r.threat).toMatchObject({
      id: "threat-1",
      severity: "high",
      confidence: 0.635,
      confidenceLabel: "medium",
      basis: "evidence_backed",
      priority: "fix_now",
    });
    expect(r.hidden).toBe(false);
    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it("ignores cited ids that do not exist and hides low confidence", () => {
    const r = scoreThreat({ ...draft, evidenceIds: ["nope"] }, "t", [], new Map());
    expect(r.threat.confidence).toBe(0);
    expect(r.threat.basis).toBe("assumption_dependent");
    expect(r.hidden).toBe(true);
  });
});
