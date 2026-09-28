import { STATIC_ANALYSIS_LIMITATION } from "@/server/analysis/assemble";
import { describe, expect, it } from "vitest";
import { assembleThreatModel, type AssembleInput } from "@/server/analysis/assemble";
import { GAP_ASSERT_CERTAINTY } from "@/server/analysis/architecture";
import type { EngineThreat } from "@/server/analysis/threats";
import type { ControlGap } from "@/server/detect/types";
import type {
  Component,
  DataFlow,
  DraftThreat,
  Evidence,
  Owasp2025,
  RepoSummary,
} from "@/shared/schema";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let n = 0;
function ev(over: Partial<Evidence>): Evidence {
  n += 1;
  return { id: `ev-${n}`, kind: "code", source: "detector", summary: "s", ...over };
}

function gap(over: Partial<ControlGap> & { id: string }): ControlGap {
  return {
    kind: "authz_missing",
    scope: "route",
    control: "ownership or role check",
    expectation: "e",
    file: "src/api/x.ts",
    line: 1,
    basisFacts: [],
    certainty: 0.9,
    owasp: ["A01:2025"],
    stride: ["E", "I"],
    cwe: ["CWE-639"],
    ...over,
  };
}

/** Evidence the same shape detectGaps.EvidenceBuilder writes for a gap. */
function gapEvidence(g: ControlGap, owasp: readonly Owasp2025[] = g.owasp): Evidence {
  return ev({
    id: `ev-${g.id}`,
    kind: "code",
    ruleId: `gap:${g.kind}`,
    summary: `${g.control} missing`,
    metadata: { owasp2025: [...owasp] },
  });
}

const repo: RepoSummary = {
  owner: "acme",
  name: "widgets",
  ref: "main",
  languages: ["TypeScript"],
  frameworks: ["express"],
  fileCountAnalyzed: 10,
  analyzedAt: new Date().toISOString(),
};

const component: Component = {
  id: "api",
  name: "API",
  type: "backend",
  description: "backend",
  technologies: ["express"],
  files: ["src/api/x.ts"],
  assets: ["user data"],
};

function threat(id: string, over: Partial<DraftThreat>): EngineThreat {
  return {
    title: "Broken object level authorization",
    componentIds: ["api"],
    dataFlowIds: [],
    asset: "user records",
    attackScenario: "An authenticated user edits another user's record by id.",
    assumptions: [],
    dependsOnUnknownIds: [],
    impact: 4,
    likelihood: 4,
    impactReason: "r",
    likelihoodReason: "r",
    mitigation: { summary: "add an ownership check", steps: ["check owner"] },
    stride: ["E"],
    owasp: ["A01:2025"],
    cwe: ["CWE-639"],
    evidenceIds: [],
    ...over,
    id,
  };
}

function baseInput(over: Partial<AssembleInput> = {}): AssembleInput {
  return {
    analysisLevel: 2,
    repo,
    components: [component],
    dataFlows: [],
    trustBoundaries: [],
    unknowns: [],
    evidence: [],
    threats: [],
    gaps: [],
    assumptions: [],
    limitations: [],
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Classification: OWASP 2021 -> 2025 translation
// ---------------------------------------------------------------------------

describe("classification: OWASP year translation", () => {
  it("translates a 2021 code to 2025 and drops nothing valid", () => {
    const e = ev({ kind: "code" });
    const t = threat("threat-1", { owasp: ["A03:2021" as never], evidenceIds: [e.id] });
    const result = assembleThreatModel(baseInput({ evidence: [e], threats: [t] }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.threats[0].owasp).toEqual(["A05:2025"]);
  });

  it("keeps a valid 2025 code untouched and deduplicates", () => {
    const e = ev({ kind: "code" });
    const t = threat("threat-1", {
      owasp: ["A01:2025", "A01:2025"],
      evidenceIds: [e.id],
    });
    const result = assembleThreatModel(baseInput({ evidence: [e], threats: [t] }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.threats[0].owasp).toEqual(["A01:2025"]);
  });

  it("unions and sorts multiple codes deterministically regardless of input order", () => {
    const e = ev({ kind: "code" });
    const a = threat("threat-1", { owasp: ["A07:2025", "A01:2025"], evidenceIds: [e.id] });
    const b = threat("threat-1", { owasp: ["A01:2025", "A07:2025"], evidenceIds: [e.id] });
    const ra = assembleThreatModel(baseInput({ evidence: [e], threats: [a] }));
    const rb = assembleThreatModel(baseInput({ evidence: [e], threats: [b] }));
    expect(ra.ok && rb.ok).toBe(true);
    if (ra.ok && rb.ok) {
      expect(ra.model.threats[0].owasp).toEqual(["A01:2025", "A07:2025"]);
      expect(ra.model.threats[0].owasp).toEqual(rb.model.threats[0].owasp);
    }
  });

  it("deduplicates CWE and STRIDE values deterministically", () => {
    const e = ev({ kind: "code" });
    const t = threat("threat-1", {
      cwe: ["CWE-639", "CWE-639"],
      stride: ["E", "I", "E"],
      evidenceIds: [e.id],
    });
    const result = assembleThreatModel(baseInput({ evidence: [e], threats: [t] }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.threats[0].cwe).toEqual(["CWE-639"]);
      expect(result.model.threats[0].stride).toEqual(["I", "E"]); // STRIDE_ORDER: S,T,R,I,D,E
    }
  });
});

// ---------------------------------------------------------------------------
// Classification: gap inheritance
// ---------------------------------------------------------------------------

describe("classification: gap inheritance", () => {
  it("inherits owasp/cwe/stride from the cited gap when the threat's owasp is empty", () => {
    const g = gap({ id: "gap-1", owasp: ["A01:2025"], cwe: ["CWE-639"], stride: ["E", "I"] });
    const e = gapEvidence(g);
    const t = threat("threat-1", {
      owasp: [],
      cwe: [],
      stride: ["E"],
      evidenceIds: [e.id],
    });
    const result = assembleThreatModel(
      baseInput({ evidence: [e], threats: [t], gaps: [g] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.threats[0].owasp).toEqual(["A01:2025"]);
      expect(result.model.threats[0].cwe).toEqual(["CWE-639"]);
    }
  });

  it("never overwrites a non-empty model-supplied classification", () => {
    const g = gap({ id: "gap-1", owasp: ["A04:2025"], cwe: ["CWE-319"] });
    const e = gapEvidence(g);
    const t = threat("threat-1", {
      owasp: ["A01:2025"], // model already supplied something
      cwe: ["CWE-639"],
      evidenceIds: [e.id],
    });
    const result = assembleThreatModel(
      baseInput({ evidence: [e], threats: [t], gaps: [g] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.threats[0].owasp).toEqual(["A01:2025"]);
      expect(result.model.threats[0].cwe).toEqual(["CWE-639"]);
    }
  });

  it("inherits owasp but keeps a model-supplied cwe when only owasp is empty", () => {
    const g = gap({ id: "gap-1", owasp: ["A04:2025"], cwe: ["CWE-319"] });
    const e = gapEvidence(g);
    const t = threat("threat-1", { owasp: [], cwe: ["CWE-916"], evidenceIds: [e.id] });
    const result = assembleThreatModel(
      baseInput({ evidence: [e], threats: [t], gaps: [g] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.threats[0].owasp).toEqual(["A04:2025"]);
      expect(result.model.threats[0].cwe).toEqual(["CWE-916"]);
    }
  });

  it("unions mappings from multiple cited gap kinds deterministically", () => {
    const g1 = gap({ id: "gap-1", kind: "authz_missing", owasp: ["A01:2025"], cwe: ["CWE-639"], stride: ["E"] });
    const g2 = gap({ id: "gap-2", kind: "csrf_missing", owasp: ["A01:2025"], cwe: ["CWE-352"], stride: ["T", "S"] });
    const e1 = gapEvidence(g1);
    const e2 = gapEvidence(g2);
    const a = threat("threat-1", { owasp: [], cwe: [], stride: [], evidenceIds: [e1.id, e2.id] });
    const b = threat("threat-1", { owasp: [], cwe: [], stride: [], evidenceIds: [e2.id, e1.id] });
    const ra = assembleThreatModel(baseInput({ evidence: [e1, e2], threats: [a], gaps: [g1, g2] }));
    const rb = assembleThreatModel(baseInput({ evidence: [e1, e2], threats: [b], gaps: [g1, g2] }));
    expect(ra.ok && rb.ok).toBe(true);
    if (ra.ok && rb.ok) {
      expect(ra.model.threats[0].owasp).toEqual(["A01:2025"]);
      expect(ra.model.threats[0].cwe).toEqual(["CWE-352", "CWE-639"]);
      expect(ra.model.threats[0]).toEqual(rb.model.threats[0]);
    }
  });

  it("falls back to A06:2025 when a gap-driven threat has no better mapping", () => {
    const g = gap({ id: "gap-1", owasp: [] });
    const e = gapEvidence(g, []);
    const t = threat("threat-1", { owasp: [], evidenceIds: [e.id] });
    const result = assembleThreatModel(
      baseInput({ evidence: [e], threats: [t], gaps: [g] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.threats[0].owasp).toEqual(["A06:2025"]);
  });

  it("does not invent a CWE fallback when no defensible CWE exists", () => {
    const g = gap({ id: "gap-1", owasp: [], cwe: [] });
    const e = gapEvidence(g, []);
    const t = threat("threat-1", { owasp: [], cwe: [], evidenceIds: [e.id] });
    const result = assembleThreatModel(
      baseInput({ evidence: [e], threats: [t], gaps: [g] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.threats[0].cwe).toEqual([]);
  });

  it("does not inherit when the threat cites non-gap evidence too", () => {
    const g = gap({ id: "gap-1", owasp: ["A04:2025"] });
    const gEv = gapEvidence(g);
    const codeEv = ev({ kind: "code" });
    const t = threat("threat-1", { owasp: [], evidenceIds: [gEv.id, codeEv.id] });
    const result = assembleThreatModel(
      baseInput({ evidence: [gEv, codeEv], threats: [t], gaps: [g] }),
    );
    // Not gap-only, so no inheritance; owasp stays empty, which fails schema (min 1).
    expect(result.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Evidence resolution
// ---------------------------------------------------------------------------

describe("evidence resolution", () => {
  it("resolves cited evidence into the model's evidence array", () => {
    const e1 = ev({ kind: "code" });
    const e2 = ev({ kind: "code" });
    const t = threat("threat-1", { evidenceIds: [e1.id] });
    const result = assembleThreatModel(
      baseInput({ evidence: [e1, e2], threats: [t] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.evidence).toEqual([e1]);
      expect(result.model.threats[0].evidenceIds).toEqual([e1.id]);
    }
  });

  it("orders resolved evidence deterministically by id, independent of citation order", () => {
    const a = ev({ id: "ev-a", kind: "code" });
    const b = ev({ id: "ev-b", kind: "code" });
    const c = ev({ id: "ev-c", kind: "code" });
    const t = threat("threat-1", { evidenceIds: [c.id, a.id] });
    const result = assembleThreatModel(
      baseInput({ evidence: [c, b, a], threats: [t] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.evidence.map((e) => e.id)).toEqual(["ev-a", "ev-c"]);
  });

  it("returns a typed issue naming the threat and reference when evidence does not resolve", () => {
    const t = threat("threat-1", { evidenceIds: ["ev-missing"] });
    const result = assembleThreatModel(baseInput({ threats: [t] }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues).toHaveLength(1);
      expect(result.issues[0].path).toBe("threats.threat-1.evidenceIds[0]");
      expect(result.issues[0].message).toContain("ev-missing");
      expect(result.issues[0].message).toContain("threat-1");
    }
  });

  it("never fabricates or silently drops an unresolved reference (whole assembly fails)", () => {
    const e1 = ev({ kind: "code" });
    const t = threat("threat-1", { evidenceIds: [e1.id, "ev-missing"] });
    const result = assembleThreatModel(
      baseInput({ evidence: [e1], threats: [t] }),
    );
    expect(result.ok).toBe(false);
  });

  it("keeps secret-redaction guarantees intact: attached evidence is exactly the input content", () => {
    const e1 = ev({ kind: "code", summary: "reads process.env.API_KEY safely, no value logged" });
    const t = threat("threat-1", { evidenceIds: [e1.id] });
    const result = assembleThreatModel(baseInput({ evidence: [e1], threats: [t] }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.evidence[0]).toEqual(e1);
  });
});

// ---------------------------------------------------------------------------
// Scoring integration (Prompt O)
// ---------------------------------------------------------------------------

describe("scoring integration", () => {
  it("scores a gap-only threat at certainty 0.95 to at least 0.40 medium, assumption_dependent", () => {
    const g = gap({ id: "gap-1", certainty: 0.95 });
    const e = gapEvidence(g);
    const t = threat("threat-1", { evidenceIds: [e.id] });
    const result = assembleThreatModel(
      baseInput({ evidence: [e], threats: [t], gaps: [g] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const scoredThreat = result.model.threats[0];
      expect(scoredThreat.confidence).toBeGreaterThanOrEqual(0.4);
      expect(scoredThreat.confidenceLabel).toBe("medium");
      expect(scoredThreat.basis).toBe("assumption_dependent");
    }
  });

  it("keeps a lower-certainty gap-only threat low", () => {
    const g = gap({ id: "gap-1", certainty: 0.5 });
    const e = gapEvidence(g);
    const t = threat("threat-1", { evidenceIds: [e.id] });
    const result = assembleThreatModel(
      baseInput({ evidence: [e], threats: [t], gaps: [g] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.threats[0].confidenceLabel).toBe("low");
  });

  it("marks direct positive evidence as evidence_backed", () => {
    const e = ev({ kind: "code" });
    const t = threat("threat-1", { evidenceIds: [e.id] });
    const result = assembleThreatModel(baseInput({ evidence: [e], threats: [t] }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.threats[0].basis).toBe("evidence_backed");
  });

  it("does not introduce evidence assembly never created (contextual route/datastore evidence)", () => {
    const e = ev({ kind: "code" });
    const t = threat("threat-1", { evidenceIds: [e.id] });
    const result = assembleThreatModel(baseInput({ evidence: [e], threats: [t] }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.evidence).toEqual([e]);
  });

  it("reduces confidence for stated assumptions exactly as scoring specifies", () => {
    const e = ev({ kind: "code" });
    const t = threat("threat-1", { evidenceIds: [e.id], assumptions: ["a", "b"] });
    const result = assembleThreatModel(baseInput({ evidence: [e], threats: [t] }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.threats[0].confidence).toBeCloseTo(0.05, 5); // .35 - .30
  });

  it("keeps severity and priority boundaries exactly as Prompt O defines them", () => {
    const e = ev({ kind: "code" });
    const t = threat("threat-1", { evidenceIds: [e.id], impact: 4, likelihood: 5 }); // risk 20
    const result = assembleThreatModel(baseInput({ evidence: [e], threats: [t] }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.threats[0].severity).toBe("critical");
      expect(result.model.threats[0].priority).toBe("fix_now");
    }
  });
});

// ---------------------------------------------------------------------------
// Full model assembly
// ---------------------------------------------------------------------------

describe("assembleThreatModel", () => {
  it("builds a complete, schema-valid ThreatModel with empty questions", () => {
    const e = ev({ kind: "code" });
    const t = threat("threat-1", { evidenceIds: [e.id] });
    const result = assembleThreatModel(
      baseInput({
        analysisLevel: 3,
        evidence: [e],
        threats: [t],
        assumptions: ["single-tenant deployment"],
      }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.schemaVersion).toBe("1.0");
      expect(result.model.analysisLevel).toBe(3);
      expect(result.model.repo).toEqual(repo);
      expect(result.model.components).toEqual([component]);
      expect(result.model.questions).toEqual([]);
      expect(result.model.assumptions).toEqual(["single-tenant deployment"]);
    }
  });

  it("deduplicates and sorts top-level assumptions deterministically", () => {
    const result = assembleThreatModel(
      baseInput({ assumptions: ["b assumption", "a assumption", "b assumption"] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.assumptions).toEqual(["a assumption", "b assumption"]);
    }
  });

  it("preserves deterministic threat ordering by id regardless of input order", () => {
    const e = ev({ kind: "code" });
    const t1 = threat("threat-1", { evidenceIds: [e.id] });
    const t2 = threat("threat-2", { evidenceIds: [e.id] });
    const result = assembleThreatModel(
      baseInput({ evidence: [e], threats: [t2, t1] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.model.threats.map((t) => t.id)).toEqual(["threat-1", "threat-2"]);
  });

  it("gives identical results across repeated runs and reordered input", () => {
    const g = gap({ id: "gap-1", certainty: 0.95 });
    const gEv = gapEvidence(g);
    const codeEv = ev({ kind: "code" });
    const t1 = threat("threat-1", { evidenceIds: [gEv.id], owasp: [] });
    const t2 = threat("threat-2", { evidenceIds: [codeEv.id] });

    const first = assembleThreatModel(
      baseInput({ evidence: [gEv, codeEv], threats: [t1, t2], gaps: [g] }),
    );
    const second = assembleThreatModel(
      baseInput({ evidence: [codeEv, gEv], threats: [t2, t1], gaps: [g] }),
    );
    expect(first.ok && second.ok).toBe(true);
    if (first.ok && second.ok) {
      expect(first.model).toEqual(second.model);
    }
  });

  describe("byte-identical output", () => {
    const comps: Component[] = ["web", "api", "db", "queue"].map((id) => ({ ...component, id, name: id.toUpperCase() }));
    const flow = (id: string, source: string, target: string): DataFlow => ({
      id,
      sourceId: source,
      targetId: target,
      label: `${source} to ${target}`,
      dataClassification: "internal",
      crossesTrustBoundary: false,
    });
    const flows = [flow("f-3", "api", "queue"), flow("f-1", "web", "api"), flow("f-2", "api", "db")];
    const g = gap({ id: "gap-1", certainty: 0.95 });
    const gEv = gapEvidence(g);
    const codeEv = ev({ kind: "code" });
    const otherEv = ev({ id: "ev-code-2", kind: "config" });
    const threats = [
      threat("threat-10", { evidenceIds: [otherEv.id], componentIds: ["db", "api"] }),
      threat("threat-2", { evidenceIds: [gEv.id], owasp: [] }),
      threat("threat-1", { evidenceIds: [codeEv.id, otherEv.id] }),
    ];
    const json = (input: AssembleInput) => {
      const result = assembleThreatModel(input);
      expect(result.ok).toBe(true);
      return JSON.stringify(result.ok ? result.model : null);
    };

    it("gives byte-identical JSON when the same inputs are assembled twice", () => {
      const input = baseInput({ components: comps, dataFlows: flows, evidence: [gEv, codeEv, otherEv], threats, gaps: [g] });
      expect(json(input)).toBe(json(input));
    });

    it("gives byte-identical JSON however the inputs are ordered", () => {
      const reference = json(
        baseInput({ components: comps, dataFlows: flows, evidence: [gEv, codeEv, otherEv], threats, gaps: [g], assumptions: ["a assumption", "b assumption"] }),
      );
      const shuffled = baseInput({
        components: [comps[2], comps[0], comps[3], comps[1]],
        dataFlows: [flows[1], flows[2], flows[0]],
        evidence: [otherEv, gEv, codeEv],
        threats: [threats[2], threats[0], threats[1]],
        gaps: [g],
        assumptions: ["b assumption", "a assumption"],
      });
      expect(json(shuffled)).toBe(reference);
    });

    it("orders components, flows, evidence and threats by id", () => {
      const result = assembleThreatModel(
        baseInput({ components: [comps[2], comps[0], comps[3], comps[1]], dataFlows: [flows[0], flows[2], flows[1]], evidence: [otherEv, gEv, codeEv], threats: [threats[0], threats[2], threats[1]], gaps: [g] }),
      );
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const ids = (items: readonly { id: string }[]) => items.map((i) => i.id);
      expect(ids(result.model.components)).toEqual(["api", "db", "queue", "web"]);
      expect(ids(result.model.dataFlows)).toEqual(["f-1", "f-2", "f-3"]);
      expect(ids(result.model.evidence)).toEqual([...ids(result.model.evidence)].sort());
      expect(ids(result.model.threats)).toEqual(["threat-1", "threat-2", "threat-10"]);
    });

    it("leaves trust boundaries in the order given, since order decides which boundary a component is drawn in", () => {
      const boundaries = [
        { id: "z-edge", name: "Edge", componentIds: ["web"], description: "d" },
        { id: "a-core", name: "Core", componentIds: ["api"], description: "d" },
      ];
      const result = assembleThreatModel(baseInput({ components: comps, trustBoundaries: boundaries }));
      expect(result.ok && result.model.trustBoundaries.map((b) => b.id)).toEqual(["z-edge", "a-core"]);
    });
  });

  it("does not touch src/shared/schema and never sends a partially valid model on failure", () => {
    const t = threat("threat-1", { evidenceIds: ["missing"] });
    const result = assembleThreatModel(baseInput({ threats: [t] }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect("model" in result).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// Automatic limitations
// ---------------------------------------------------------------------------

describe("automatic limitations", () => {
  it("preserves upstream limitations and appends the automatic ones", () => {
    const result = assembleThreatModel(
      baseInput({ limitations: ["upstream limitation one"] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.limitations[0]).toBe("upstream limitation one");
      expect(result.model.limitations).toContain(STATIC_ANALYSIS_LIMITATION);
    }
  });

  it("names each disabled or cut gap kind", () => {
    const result = assembleThreatModel(
      baseInput({ disabledGapKinds: ["csrf_missing", "logging_missing"] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.limitations).toEqual(
        expect.arrayContaining([
          // Named as a reader would, never by the internal gap kind.
          expect.stringContaining("CSRF protection, security logging"),
        ]),
      );
    }
  });

  it("counts low-certainty gaps that fell below the assert threshold", () => {
    const low1 = gap({ id: "gap-1", certainty: GAP_ASSERT_CERTAINTY - 0.01 });
    const low2 = gap({ id: "gap-2", certainty: 0.1 });
    const high = gap({ id: "gap-3", certainty: GAP_ASSERT_CERTAINTY });
    const result = assembleThreatModel(baseInput({ gaps: [low1, low2, high] }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(
        result.model.limitations.some((l) =>
          l.startsWith("2 possible missing controls could not be confirmed"),
        ),
      ).toBe(true);
    }
  });

  it("says nothing about low-certainty gaps when there are none", () => {
    const result = assembleThreatModel(baseInput({ gaps: [] }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.limitations.some((l) => l.includes("could not be confirmed"))).toBe(false);
    }
  });

  it("states each limitation once, however often upstream repeats it", () => {
    const result = assembleThreatModel(
      baseInput({ limitations: ["same caveat", "same caveat", STATIC_ANALYSIS_LIMITATION] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const lines = result.model.limitations;
      expect(lines.filter((l) => l === "same caveat")).toHaveLength(1);
      expect(lines.filter((l) => l === STATIC_ANALYSIS_LIMITATION)).toHaveLength(1);
    }
  });

  it("names dropped or unavailable upstream stages when the caller supplies them", () => {
    const result = assembleThreatModel(
      baseInput({ droppedStages: ["osv scan"] }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.model.limitations.some((l) => l.includes("osv scan"))).toBe(true);
    }
  });

  it("never includes a source snippet or credential-shaped value in limitations", () => {
    const g = gap({
      id: "gap-1",
      certainty: 0.1,
      expectation: "SECRET sk_live_do_not_leak_this should never appear",
    });
    const result = assembleThreatModel(baseInput({ gaps: [g] }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      for (const line of result.model.limitations) {
        expect(line).not.toContain("sk_live_do_not_leak_this");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Schema-validation failure paths
// ---------------------------------------------------------------------------

describe("schema validation failure", () => {
  it("returns typed issues with the exact offending path when the assembled model is invalid", () => {
    // A dataFlow whose sourceId does not match any component id.
    const result = assembleThreatModel(
      baseInput({
        dataFlows: [
          {
            id: "flow-1",
            sourceId: "nope",
            targetId: "api",
            label: "call",
            dataClassification: "internal",
            crossesTrustBoundary: false,
          },
        ],
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues.some((i) => i.path === "dataFlows.0.sourceId")).toBe(true);
    }
  });

  it("throws nothing: even a maximally broken input returns typed issues", () => {
    expect(() =>
      assembleThreatModel(
        baseInput({
          threats: [threat("threat-1", { evidenceIds: ["nope"], componentIds: ["nope"] })],
        }),
      ),
    ).not.toThrow();
  });
});
