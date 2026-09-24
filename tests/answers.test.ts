import { describe, expect, it } from "vitest";
import {
  applyAnswers,
  type ApplyAnswersInput,
  type DeveloperAnswer,
  namesUnknown,
} from "@/server/analysis/answers";
import { gapEvidenceId } from "@/server/analysis/context";
import {
  defaultEffectFor,
  effectsFor,
  type QuestionEffects,
} from "@/server/questions";
import type { ControlGap } from "@/server/detect/types";
import {
  validateThreatModel,
  type DeveloperQuestion,
  type Evidence,
  type RepoSummary,
  type Threat,
  type ThreatModel,
} from "@/shared/schema";

/** Recursively freezes an object graph so any in-place mutation throws in strict mode. */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.values(value as Record<string, unknown>).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const repo: RepoSummary = {
  owner: "acme",
  name: "widgets",
  ref: "main",
  languages: ["TypeScript"],
  frameworks: ["express"],
  fileCountAnalyzed: 10,
  analyzedAt: new Date().toISOString(),
};

function gap(id: string, certainty: number): ControlGap {
  return {
    id,
    kind: "authz_missing",
    scope: "route",
    control: "ownership or role check",
    expectation: "route reads an id and returns a record",
    file: "src/routes/orders.ts",
    line: 10,
    basisFacts: ["fact"],
    certainty,
    owasp: ["A01:2025"],
    stride: ["E"],
    cwe: ["CWE-639"],
  };
}

function gapEvidence(g: ControlGap): Evidence {
  return {
    id: gapEvidenceId(g),
    kind: "code",
    source: "detector",
    ruleId: `gap:${g.kind}`,
    summary: `${g.control} missing`,
  };
}

function codeEvidence(id: string): Evidence {
  return { id, kind: "code", source: "detector", summary: "handler reads req.params.id" };
}

function threat(id: string, over: Partial<Threat>): Threat {
  return {
    id,
    title: `Threat ${id}`,
    stride: ["E"],
    owasp: ["A01:2025"],
    cwe: ["CWE-639"],
    componentIds: ["api"],
    dataFlowIds: [],
    asset: "user records",
    attackScenario: "An authenticated user edits another user's record by id.",
    evidenceIds: [],
    assumptions: [],
    dependsOnUnknownIds: [],
    impact: 3,
    likelihood: 3,
    impactReason: "reason",
    likelihoodReason: "reason",
    severity: "medium",
    confidence: 0.5,
    confidenceLabel: "medium",
    basis: "assumption_dependent",
    mitigation: { summary: "add an ownership check", steps: ["check owner"] },
    priority: "monitor",
    ...over,
  };
}

function question(
  over: Partial<DeveloperQuestion> & { id: string; affectedThreatIds: string[] },
): DeveloperQuestion {
  return {
    text: "Does the handler check that the caller owns the record?",
    whyAsking: "No ownership check was found near the id lookup.",
    options: ["No, it does not check", "Yes, it checks ownership"],
    allowsUnsure: true,
    unknownId: "unknown-1",
    defaultAssumption: "Assume the ownership check is missing.",
    valueScore: 0.6,
    ...over,
  };
}

/**
 * Builds a QuestionEffects sidecar the way selectQuestions would, from real option
 * meanings. `appliesToThreatIds` defaults to the one threat every fixture in this file
 * pairs with its question by naming convention (question("question-1", ...) <->
 * threat("threat-1", ...), question("question-a", ...) <-> threat("threat-a", ...)):
 * pass it explicitly for a fixture that applies to more than one threat, or none.
 */
function effectsOf(
  questionId: string,
  meanings: Parameters<typeof effectsFor>[0],
  gapId?: string,
  appliesToThreatIds?: string[],
): QuestionEffects {
  const options = effectsFor(meanings, gapId !== undefined);
  const def = defaultEffectFor(options);
  if (!def) throw new Error("no cautious default for this fixture's meanings");
  return {
    questionId,
    unknownId: "unknown-1",
    ...(gapId ? { gapId } : {}),
    options,
    default: def,
    appliesToThreatIds: appliesToThreatIds ?? [questionId.replace(/^question-/, "threat-")],
  };
}

function baseModel(over: Partial<ThreatModel> = {}): ThreatModel {
  return {
    schemaVersion: "1.0",
    analysisLevel: 2,
    repo,
    components: [
      {
        id: "api",
        name: "API",
        type: "backend",
        description: "backend",
        technologies: ["express"],
        files: ["src/routes/orders.ts"],
        assets: ["user records"],
      },
    ],
    dataFlows: [],
    trustBoundaries: [],
    unknowns: [],
    evidence: [],
    threats: [],
    questions: [],
    assumptions: [],
    limitations: [],
    ...over,
  };
}

function run(over: Partial<ApplyAnswersInput> & { model: ThreatModel; answers: DeveloperAnswer[] }) {
  return applyAnswers({
    effects: new Map(),
    gaps: [],
    ...over,
  });
}

// ---------------------------------------------------------------------------
// confirms_gap
// ---------------------------------------------------------------------------

describe("answered: confirms_gap", () => {
  it("keeps the gap evidence, adds a developer_answer, and applies the option's deltas", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const t = threat("threat-1", {
      evidenceIds: [gEv.id],
      impact: 3,
      likelihood: 3,
    });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    // meanings index-aligned with q.options: "No" = control_absent (confirms_gap).
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const model = baseModel({ evidence: [gEv], threats: [t], questions: [q] });
    const result = run({
      model,
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    const answerEvidenceId = "ev-answer-question-1";

    expect(updated.evidenceIds).toContain(gEv.id);
    expect(updated.evidenceIds).toContain(answerEvidenceId);
    expect(updated.likelihood).toBe(4); // control_absent: likelihoodDelta +1
    expect(updated.impact).toBe(3);
    expect(updated.severity).toBe("high"); // risk 4*3=12

    // gap(270) + developer(300) + second-source(100) = 670 -> 0.67
    expect(updated.confidence).toBeCloseTo(0.67, 5);
    expect(updated.confidenceLabel).toBe("medium");
    expect(updated.basis).toBe("evidence_backed"); // developer_answer is a positive observation

    const addedEvidence = result.model.evidence.find((e) => e.id === answerEvidenceId);
    expect(addedEvidence).toMatchObject({
      kind: "developer_answer",
      source: "developer",
    });
    expect(addedEvidence?.summary).toContain(q.text);
    expect(addedEvidence?.summary).toContain(q.options[0]);
    expect(addedEvidence?.filePath).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// clears_gap
// ---------------------------------------------------------------------------

describe("answered: clears_gap", () => {
  it("removes the gap evidence, adds a developer_answer, and re-scores", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", {
      evidenceIds: [gEv.id, codeEv.id],
      impact: 3,
      likelihood: 3,
    });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const model = baseModel({ evidence: [gEv, codeEv], threats: [t], questions: [q] });
    const result = run({
      model,
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 1 }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.evidenceIds).not.toContain(gEv.id);
    expect(updated.evidenceIds).toContain(codeEv.id);
    // A "control is present" answer clears the gap; it is not cited as support for the
    // threat, since that would let a safety confirmation inflate confidence in a risk.
    expect(updated.evidenceIds).not.toContain("ev-answer-question-1");
    expect(updated.likelihood).toBe(2); // control_present: likelihoodDelta -1

    // code(350) only, one category -> 0.35
    expect(updated.confidence).toBeCloseTo(0.35, 5);

    expect(result.model.evidence.some((e) => e.id === gEv.id)).toBe(false);
    // Uncited by the (now disproven) threat, but kept in the model for auditability.
    expect(result.model.evidence.some((e) => e.id === "ev-answer-question-1")).toBe(true);
  });

  it("drops a threat that is left with no evidence and no assumption, and records why", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const t = threat("threat-1", { evidenceIds: [gEv.id], assumptions: [] });
    const other = threat("threat-2", { evidenceIds: [gEv.id], assumptions: [] });
    const q = question({
      id: "question-1",
      affectedThreatIds: ["threat-1"],
    });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const model = baseModel({
      evidence: [gEv],
      threats: [t, other],
      questions: [q],
    });
    const result = run({
      model,
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 1 }],
    });

    expect(result.model.threats.map((x) => x.id)).toEqual(["threat-2"]);
    expect(
      result.limitations.some(
        (l) => l.includes("threat-1") && l.includes("developer answer"),
      ),
    ).toBe(true);
    // threat-2 still cites the gap evidence, so it survives in the pool.
    expect(result.model.evidence.some((e) => e.id === gEv.id)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// no_change (model-authored question, no gap involved)
// ---------------------------------------------------------------------------

describe("answered: no_change", () => {
  it("adds evidence and applies deltas without touching any gap", () => {
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [codeEv.id], impact: 3, likelihood: 3 });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    // No gapId: effectsFor treats every meaning as no_change.
    const effects = effectsOf("question-1", ["control_absent", "control_present"]);

    const model = baseModel({ evidence: [codeEv], threats: [t], questions: [q] });
    const result = run({
      model,
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.evidenceIds.sort()).toEqual(["ev-answer-question-1", codeEv.id].sort());
    expect(updated.likelihood).toBe(4);
  });

  it("applies impactDelta on the answered path, isolated from likelihood and away from any clamp boundary", () => {
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [codeEv.id], impact: 3, likelihood: 3 });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    // not_applicable: impactDelta -1, likelihoodDelta -1; no gapId, so resolution is no_change.
    // Paired with control_absent (not chosen) purely so a cautious default exists.
    const effects = effectsOf("question-1", ["not_applicable", "control_absent"]);

    const model = baseModel({ evidence: [codeEv], threats: [t], questions: [q] });
    const result = run({
      model,
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.impact).toBe(2); // 3 + (-1), nowhere near the 1..5 clamp edges
    expect(updated.likelihood).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// skip / unsure
// ---------------------------------------------------------------------------

describe("skipped or unsure", () => {
  it("records the default assumption, applies the default's deltas, and leaves gap evidence in place", () => {
    const g = gap("gap-1", 0.5); // below the floor's certainty bar, so the -0.15 shows through
    const gEv = gapEvidence(g);
    const t = threat("threat-1", { evidenceIds: [gEv.id], assumptions: [], impact: 3, likelihood: 3 });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const model = baseModel({ evidence: [gEv], threats: [t], questions: [q] });
    const result = run({
      model,
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "skipped" }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.evidenceIds).toEqual([gEv.id]); // untouched, no developer_answer added
    expect(updated.assumptions).toEqual([q.defaultAssumption]);
    expect(updated.likelihood).toBe(4); // the cautious default is control_absent-shaped
    // gap(150) - assumption(150) = 0 -> 0.00, no floor (certainty 0.5 < 0.8)
    expect(updated.confidence).toBeCloseTo(0, 5);
    expect(updated.confidenceLabel).toBe("low");
  });

  it("behaves identically for an unsure answer", () => {
    const g = gap("gap-1", 0.5);
    const gEv = gapEvidence(g);
    const t = threat("threat-1", { evidenceIds: [gEv.id], assumptions: [] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const skipped = run({
      model: baseModel({ evidence: [gEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "skipped" }],
    });
    const unsure = run({
      model: baseModel({ evidence: [gEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "unsure" }],
    });

    const a = skipped.model.threats.find((x) => x.id === "threat-1")!;
    const b = unsure.model.threats.find((x) => x.id === "threat-1")!;
    expect(a).toEqual(b);
  });
});

// ---------------------------------------------------------------------------
// Unaffected threats are untouched
// ---------------------------------------------------------------------------

describe("unaffected threats", () => {
  it("leaves a threat named by no answered question byte-identical", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const affected = threat("threat-1", { evidenceIds: [gEv.id] });
    const untouched = threat("threat-2", {
      evidenceIds: ["ev-code-2"],
      confidence: 0.42,
      confidenceLabel: "medium",
    });
    const codeEv2 = codeEvidence("ev-code-2");
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const model = baseModel({
      evidence: [gEv, codeEv2],
      threats: [affected, untouched],
      questions: [q],
    });
    const result = run({
      model,
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }],
    });

    const stillThere = result.model.threats.find((x) => x.id === "threat-2");
    expect(stillThere).toBe(untouched); // same object, not just equal
    expect(stillThere?.confidence).toBe(0.42);
  });
});

// ---------------------------------------------------------------------------
// Bad input is reported, not thrown
// ---------------------------------------------------------------------------

describe("malformed answers", () => {
  it("records a limitation for an answer to a question that does not exist", () => {
    const model = baseModel({ threats: [threat("threat-1", {})] });
    const result = run({ model, answers: [{ questionId: "question-9", status: "skipped" }] });
    expect(result.model.threats).toEqual(model.threats);
    expect(result.limitations.some((l) => l.includes("question-9"))).toBe(true);
  });

  it("records a limitation, and applies the skip default, for an answer that names an option the question does not have", () => {
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [codeEv.id] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"]);

    const model = baseModel({ evidence: [codeEv], threats: [t], questions: [q] });
    const input = { model, effects: new Map([["question-1", effects]]) };
    const result = run({
      ...input,
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 7 }],
    });
    const skipped = run({ ...input, answers: [{ questionId: "question-1", status: "skipped" }] });

    // A bad option index must not be a way to look safer than skipping.
    expect(result.model.threats).toEqual(skipped.model.threats);
    expect(result.limitations.some((l) => l.includes("question-1") && l.includes("7"))).toBe(
      true,
    );
  });

  it('treats "answered" with no option chosen exactly like an explicit skip', () => {
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [codeEv.id] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"]);

    const input = {
      model: baseModel({ evidence: [codeEv], threats: [t], questions: [q] }),
      effects: new Map([["question-1", effects]]),
    };
    const result = run({ ...input, answers: [{ questionId: "question-1", status: "answered" }] });
    const skipped = run({ ...input, answers: [{ questionId: "question-1", status: "skipped" }] });

    expect(result.model.threats).toEqual(skipped.model.threats);
    expect(result.model.threats[0].assumptions).toEqual([q.defaultAssumption]);
    expect(result.limitations.some((l) => l.includes("no option chosen"))).toBe(true);
  });

  it("records a limitation, and applies nothing, when a question has no sidecar entry", () => {
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [codeEv.id] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });

    const model = baseModel({ evidence: [codeEv], threats: [t], questions: [q] });
    // No entry for "question-1" in `effects`.
    const result = run({
      model,
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated).toBe(t);
    expect(result.limitations.some((l) => l.includes("question-1"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// A question left without an answer gets the cautious skip default
// ---------------------------------------------------------------------------

describe("omitted questions", () => {
  it("gives a question missing from `answers` exactly the explicit-skip result, never a safer one", () => {
    const g = gap("gap-1", 0.5);
    const gEv = gapEvidence(g);
    const t1 = threat("threat-1", { evidenceIds: [gEv.id], impact: 4, likelihood: 2 });
    const codeEv = codeEvidence("ev-code-1");
    const t2 = threat("threat-2", { evidenceIds: [codeEv.id] });
    const q1 = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const q2 = question({ id: "question-2", affectedThreatIds: ["threat-2"] });
    const input = {
      model: baseModel({ evidence: [gEv, codeEv], threats: [t1, t2], questions: [q1, q2] }),
      gaps: [g],
      effects: new Map([
        ["question-1", effectsOf("question-1", ["control_absent", "control_present"], "gap-1")],
        ["question-2", effectsOf("question-2", ["control_absent", "control_present"])],
      ]),
    };

    const omitted = run({
      ...input,
      answers: [{ questionId: "question-2", status: "answered", optionIndex: 1 }],
    });
    const skipped = run({
      ...input,
      answers: [
        { questionId: "question-1", status: "skipped" },
        { questionId: "question-2", status: "answered", optionIndex: 1 },
      ],
    });

    expect(omitted.model.threats).toEqual(skipped.model.threats);
    const updated = omitted.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.likelihood).toBe(3); // the cautious default's +1, not left at 2
    expect(updated.assumptions).toEqual([q1.defaultAssumption]);
    expect(updated.severity).toBe("high"); // 4 x 3 = 12; ignoring the omission left it medium (4 x 2)
    expect(
      omitted.limitations.some((l) => l.includes("question-1") && l.includes("treated as skipped")),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// No mutation of inputs
// ---------------------------------------------------------------------------

describe("input immutability", () => {
  it("never mutates the input model, effects, gaps, or answers", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const codeEv = codeEvidence("ev-code-1");
    const affected = threat("threat-1", { evidenceIds: [gEv.id, codeEv.id] });
    const untouched = threat("threat-2", { evidenceIds: [codeEv.id] });
    const q1 = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const q2 = question({
      id: "question-2",
      affectedThreatIds: ["threat-1"],
      allowsUnsure: true,
    });
    const effects1 = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");
    const effects2 = effectsOf("question-2", ["control_absent", "control_present"]);

    const model = deepFreeze(
      baseModel({
        evidence: [gEv, codeEv],
        threats: [affected, untouched],
        questions: [q1, q2],
      }),
    );
    const effects = deepFreeze(
      new Map([
        ["question-1", effects1],
        ["question-2", effects2],
      ]),
    );
    const gaps = deepFreeze([g]);
    const answers = deepFreeze([
      { questionId: "question-1", status: "answered", optionIndex: 1 },
      { questionId: "question-2", status: "skipped" },
    ] as DeveloperAnswer[]);

    expect(() => applyAnswers({ model, effects, gaps, answers })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Reordering and duplicates
// ---------------------------------------------------------------------------

describe("answer order and duplicates", () => {
  it("produces identical output regardless of the order distinct answers are given in", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const codeEv = codeEvidence("ev-code-1");
    const t1 = threat("threat-1", { evidenceIds: [gEv.id] });
    const t2 = threat("threat-2", { evidenceIds: [codeEv.id] });
    const q1 = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const q2 = question({ id: "question-2", affectedThreatIds: ["threat-2"] });
    const effects1 = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");
    const effects2 = effectsOf("question-2", ["control_absent", "control_present"]);
    const effectsMap = new Map([
      ["question-1", effects1],
      ["question-2", effects2],
    ]);

    const forward = run({
      model: baseModel({ evidence: [gEv, codeEv], threats: [t1, t2], questions: [q1, q2] }),
      gaps: [g],
      effects: effectsMap,
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-2", status: "skipped" },
        { questionId: "question-9", status: "skipped" }, // also exercises a malformed entry
      ],
    });
    const reversed = run({
      model: baseModel({ evidence: [gEv, codeEv], threats: [t1, t2], questions: [q1, q2] }),
      gaps: [g],
      effects: effectsMap,
      answers: [
        { questionId: "question-9", status: "skipped" },
        { questionId: "question-2", status: "skipped" },
        { questionId: "question-1", status: "answered", optionIndex: 0 },
      ],
    });

    expect(reversed.model).toEqual(forward.model);
    expect(reversed.limitations).toEqual(forward.limitations);
  });

  it("applies a question's effect exactly once when every duplicate is the identical answer", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const t = threat("threat-1", { evidenceIds: [gEv.id], impact: 3, likelihood: 3 });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const once = run({
      model: baseModel({ evidence: [gEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }],
    });
    const duplicated = run({
      model: baseModel({ evidence: [gEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-1", status: "answered", optionIndex: 0 },
      ],
    });

    // Not merely equal confidence -- the whole scored threat, so a double-applied delta
    // (likelihood +1 twice, or a double second-source bonus) would fail this.
    expect(duplicated.model.threats).toEqual(once.model.threats);
    expect(duplicated.limitations).toEqual([]);
  });

  it("applies neither conflicting answer, only the skip default, when two answers to the same question conflict", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", {
      evidenceIds: [gEv.id, codeEv.id],
      assumptions: [],
      impact: 3,
      likelihood: 3,
    });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    // option 0 = control_absent (+1 likelihood), option 1 = control_present (-1 likelihood).
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");
    const input = {
      model: baseModel({ evidence: [gEv, codeEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
    };

    const result = run({
      ...input,
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-1", status: "answered", optionIndex: 1 },
      ],
    });
    const skipped = run({ ...input, answers: [{ questionId: "question-1", status: "skipped" }] });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    // Exactly the explicit-skip result: a conflict must not be a way to look safer.
    expect(result.model.threats).toEqual(skipped.model.threats);
    expect([...updated.evidenceIds].sort()).toEqual([codeEv.id, gEv.id].sort()); // no developer_answer added
    expect(updated.assumptions).toEqual([q.defaultAssumption]);
    expect(result.model.evidence.some((e) => e.id === "ev-answer-question-1")).toBe(false);
    expect(
      result.limitations.some(
        (l) => l.includes("question-1") && l.includes("conflicting"),
      ),
    ).toBe(true);
  });

  it("rejects a conflict between a skip and an answered value for the same question", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const t = threat("threat-1", { evidenceIds: [gEv.id], assumptions: [] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const result = run({
      model: baseModel({ evidence: [gEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-1", status: "skipped" },
      ],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.evidenceIds).toEqual([gEv.id]); // the answered value was not applied
    expect(updated.assumptions).toEqual([q.defaultAssumption]); // the skip default was
  });

  it("still rejects three duplicates that carry only two distinct values", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [gEv.id, codeEv.id], impact: 3, likelihood: 3 });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const result = run({
      model: baseModel({ evidence: [gEv, codeEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      // Two copies of option 0, one of option 1: still a genuine conflict, not "2 vs 1".
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-1", status: "answered", optionIndex: 1 },
        { questionId: "question-1", status: "answered", optionIndex: 0 },
      ],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect([...updated.evidenceIds].sort()).toEqual([codeEv.id, gEv.id].sort()); // neither value applied
    expect(updated.likelihood).toBe(4); // only the skip default's +1
    expect(result.limitations.filter((l) => l.includes("question-1"))).toHaveLength(1);
  });

  it("emits the conflict limitation exactly once, however many duplicates are given", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [gEv.id, codeEv.id] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const result = run({
      model: baseModel({ evidence: [gEv, codeEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-1", status: "answered", optionIndex: 1 },
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-1", status: "answered", optionIndex: 1 },
      ],
    });

    expect(result.limitations).toHaveLength(1);
  });

  it("produces byte-identical output when conflicting duplicates are reversed", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [gEv.id, codeEv.id] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");
    const effectsMap = new Map([["question-1", effects]]);

    const forward = run({
      model: baseModel({ evidence: [gEv, codeEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: effectsMap,
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-1", status: "answered", optionIndex: 1 },
      ],
    });
    const reversed = run({
      model: baseModel({ evidence: [gEv, codeEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: effectsMap,
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 1 },
        { questionId: "question-1", status: "answered", optionIndex: 0 },
      ],
    });

    expect(reversed.model).toEqual(forward.model);
    expect(reversed.limitations).toEqual(forward.limitations);
  });

  it("resolves an unrelated, unconflicted question normally alongside a conflicting one", () => {
    const gConflict = gap("gap-1", 0.9);
    const evConflict = gapEvidence(gConflict);
    const gOk = gap("gap-2", 0.9);
    const evOk = gapEvidence(gOk);
    const conflicted = threat("threat-1", { evidenceIds: [evConflict.id] });
    const fine = threat("threat-2", { evidenceIds: [evOk.id], impact: 3, likelihood: 3 });
    const qConflict = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const qOk = question({ id: "question-2", affectedThreatIds: ["threat-2"] });
    const effectsConflict = effectsOf(
      "question-1",
      ["control_absent", "control_present"],
      "gap-1",
    );
    const effectsOk = effectsOf("question-2", ["control_absent", "control_present"], "gap-2");

    const result = run({
      model: baseModel({
        evidence: [evConflict, evOk],
        threats: [conflicted, fine],
        questions: [qConflict, qOk],
      }),
      gaps: [gConflict, gOk],
      effects: new Map([
        ["question-1", effectsConflict],
        ["question-2", effectsOk],
      ]),
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-1", status: "answered", optionIndex: 1 },
        { questionId: "question-2", status: "answered", optionIndex: 0 },
      ],
    });

    const stillConflicted = result.model.threats.find((x) => x.id === "threat-1")!;
    const resolved = result.model.threats.find((x) => x.id === "threat-2")!;
    expect(stillConflicted.evidenceIds).toEqual([evConflict.id]); // no answer applied
    expect(stillConflicted.assumptions).toEqual([qConflict.defaultAssumption]); // skip default
    expect(resolved.likelihood).toBe(4); // control_absent applied normally
    expect(resolved.evidenceIds).toContain("ev-answer-question-2");
  });
});

// ---------------------------------------------------------------------------
// Evidence-id collision with existing evidence
// ---------------------------------------------------------------------------

describe("evidence id collision", () => {
  it("keeps the pre-existing evidence item when a developer_answer id collides with it", () => {
    const codeEv = codeEvidence("ev-code-1");
    // Deliberately collides with the id applyAnswers derives for "question-1".
    const collider: Evidence = {
      id: "ev-answer-question-1",
      kind: "code",
      source: "detector",
      summary: "pre-existing finding, not a developer answer",
    };
    const t = threat("threat-1", { evidenceIds: [codeEv.id, collider.id] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"]);

    const model = baseModel({
      evidence: [codeEv, collider],
      threats: [t],
      questions: [q],
    });
    const result = run({
      model,
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }],
    });

    const kept = result.model.evidence.find((e) => e.id === "ev-answer-question-1")!;
    expect(kept.kind).toBe("code");
    expect(kept.summary).toBe("pre-existing finding, not a developer answer");
  });
});

// ---------------------------------------------------------------------------
// clears_gap touches only the relevant gap's evidence
// ---------------------------------------------------------------------------

describe("clears_gap is scoped to its own gap", () => {
  it("removes only the answered gap's evidence, leaving an unrelated gap and positive evidence in place", () => {
    const targetGap = gap("gap-1", 0.9);
    const targetEv = gapEvidence(targetGap);
    const otherGap = gap("gap-2", 0.9);
    const otherEv = gapEvidence(otherGap);
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", {
      evidenceIds: [targetEv.id, otherEv.id, codeEv.id],
    });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf(
      "question-1",
      ["control_absent", "control_present"],
      "gap-1",
    );

    const model = baseModel({
      evidence: [targetEv, otherEv, codeEv],
      threats: [t],
      questions: [q],
    });
    const result = run({
      model,
      gaps: [targetGap, otherGap],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 1 }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.evidenceIds).not.toContain(targetEv.id);
    expect(updated.evidenceIds).toContain(otherEv.id);
    expect(updated.evidenceIds).toContain(codeEv.id);
    expect(result.model.evidence.some((e) => e.id === otherEv.id)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Single citation, no double-counting
// ---------------------------------------------------------------------------

describe("developer_answer citation count", () => {
  it("cites the developer_answer exactly once for confirms_gap", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const t = threat("threat-1", { evidenceIds: [gEv.id] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const result = run({
      model: baseModel({ evidence: [gEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    const citations = updated.evidenceIds.filter((id) => id === "ev-answer-question-1");
    expect(citations).toHaveLength(1);
  });

  it("cites the developer_answer exactly once for no_change", () => {
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [codeEv.id] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"]);

    const result = run({
      model: baseModel({ evidence: [codeEv], threats: [t], questions: [q] }),
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    const citations = updated.evidenceIds.filter((id) => id === "ev-answer-question-1");
    expect(citations).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Skip / unsure make no scoring or evidence change beyond the assumption
// ---------------------------------------------------------------------------

describe("skip and unsure change nothing but the assumption and the deltas", () => {
  it("adds no evidence and removes none, for a question with no gap involved", () => {
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", { evidenceIds: [codeEv.id], assumptions: [] });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"]);

    const result = run({
      model: baseModel({ evidence: [codeEv], threats: [t], questions: [q] }),
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "skipped" }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.evidenceIds).toEqual([codeEv.id]);
    expect(updated.assumptions).toEqual([q.defaultAssumption]);
    expect(result.model.evidence.map((e) => e.id).sort()).toEqual([codeEv.id]);
  });
});

// ---------------------------------------------------------------------------
// Deterministic drop / limitation ordering
// ---------------------------------------------------------------------------

describe("deterministic ordering of drops and limitations", () => {
  it("orders limitations the same way regardless of the drop order or answer order", () => {
    const gapA = gap("gap-a", 0.9);
    const evA = gapEvidence(gapA);
    const gapB = gap("gap-b", 0.9);
    const evB = gapEvidence(gapB);
    const threatA = threat("threat-a", { evidenceIds: [evA.id], assumptions: [] });
    const threatB = threat("threat-b", { evidenceIds: [evB.id], assumptions: [] });
    const qA = question({ id: "question-a", affectedThreatIds: ["threat-a"] });
    const qB = question({ id: "question-b", affectedThreatIds: ["threat-b"] });
    const effectsA = effectsOf("question-a", ["control_absent", "control_present"], "gap-a");
    const effectsB = effectsOf("question-b", ["control_absent", "control_present"], "gap-b");
    const effectsMap = new Map([
      ["question-a", effectsA],
      ["question-b", effectsB],
    ]);

    // model.threats deliberately listed B-before-A: were the output order merely "the
    // order threats were dropped in", it would come out b-then-a here, which does NOT
    // match alphabetical. Only an explicit sort produces the same array as the (properly
    // alphabetical) forward/reversed comparison below.
    const forward = run({
      model: baseModel({
        evidence: [evA, evB],
        threats: [threatB, threatA],
        questions: [qA, qB],
      }),
      gaps: [gapA, gapB],
      effects: effectsMap,
      answers: [
        { questionId: "question-a", status: "answered", optionIndex: 1 },
        { questionId: "question-b", status: "answered", optionIndex: 1 },
      ],
    });
    const reversed = run({
      model: baseModel({
        evidence: [evA, evB],
        threats: [threatB, threatA],
        questions: [qA, qB],
      }),
      gaps: [gapA, gapB],
      effects: effectsMap,
      answers: [
        { questionId: "question-b", status: "answered", optionIndex: 1 },
        { questionId: "question-a", status: "answered", optionIndex: 1 },
      ],
    });

    expect(forward.model.threats.map((t) => t.id)).toEqual([]);
    expect(forward.limitations).toEqual(reversed.limitations);
    expect(forward.limitations).toEqual([...forward.limitations].sort());
    expect(forward.limitations[0]).toContain("threat-a");
    expect(forward.limitations[1]).toContain("threat-b");
    // Both threats' questions have their affectedThreatIds pruned to nothing surviving.
    expect(forward.model.questions.flatMap((q) => q.affectedThreatIds)).toEqual([]);
  });

  it("sorts malformed-answer limitations alphabetically regardless of the input order", () => {
    const model = baseModel({ threats: [threat("threat-1", {})] });

    const forward = run({
      model,
      answers: [
        { questionId: "question-zzz", status: "skipped" },
        { questionId: "question-aaa", status: "skipped" },
      ],
    });
    const reversed = run({
      model,
      answers: [
        { questionId: "question-aaa", status: "skipped" },
        { questionId: "question-zzz", status: "skipped" },
      ],
    });

    expect(forward.limitations).toEqual(reversed.limitations);
    expect(forward.limitations[0]).toContain("question-aaa");
    expect(forward.limitations[1]).toContain("question-zzz");
  });
});

// ---------------------------------------------------------------------------
// Clamping
// ---------------------------------------------------------------------------

describe("impact/likelihood clamping", () => {
  it("does not push likelihood above 5", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const t = threat("threat-1", { evidenceIds: [gEv.id], impact: 3, likelihood: 5 });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const result = run({
      model: baseModel({ evidence: [gEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 0 }], // +1 likelihood
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.likelihood).toBe(5);
  });

  it("does not push likelihood below 1", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", {
      evidenceIds: [gEv.id, codeEv.id],
      impact: 3,
      likelihood: 1,
    });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const result = run({
      model: baseModel({ evidence: [gEv, codeEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 1 }], // -1 likelihood
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.likelihood).toBe(1);
  });

  it("does not push impact below 1", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", {
      evidenceIds: [gEv.id, codeEv.id],
      impact: 1,
      likelihood: 3,
    });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    // not_applicable: likelihoodDelta -1, impactDelta -1, clears_gap.
    const effects = effectsOf(
      "question-1",
      ["control_absent", "not_applicable"],
      "gap-1",
    );

    const result = run({
      model: baseModel({ evidence: [gEv, codeEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 1 }],
    });

    const updated = result.model.threats.find((x) => x.id === "threat-1")!;
    expect(updated.impact).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Drop condition requires BOTH evidence and assumptions to be empty
// ---------------------------------------------------------------------------

describe("drop condition", () => {
  it("does not drop a threat whose evidence is cleared but which already has an assumption", () => {
    const g = gap("gap-1", 0.9);
    const gEv = gapEvidence(g);
    const t = threat("threat-1", {
      evidenceIds: [gEv.id],
      assumptions: ["This code path is rarely exercised in production."],
    });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const effects = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");

    const result = run({
      model: baseModel({ evidence: [gEv], threats: [t], questions: [q] }),
      gaps: [g],
      effects: new Map([["question-1", effects]]),
      answers: [{ questionId: "question-1", status: "answered", optionIndex: 1 }], // clears_gap
    });

    expect(result.model.threats.map((x) => x.id)).toEqual(["threat-1"]);
    const updated = result.model.threats[0];
    expect(updated.evidenceIds).toEqual([]);
    expect(updated.assumptions).toEqual(["This code path is rarely exercised in production."]);
    expect(updated.basis).toBe("assumption_dependent");
  });
});

// ---------------------------------------------------------------------------
// Final output validates against ThreatModelSchema
// ---------------------------------------------------------------------------

describe("schema validity", () => {
  it("produces a model that passes ThreatModelSchema for confirms_gap, clears_gap-with-drop, and skip", () => {
    const gap1 = gap("gap-1", 0.9);
    const ev1 = gapEvidence(gap1);
    const gap2 = gap("gap-2", 0.9);
    const ev2 = gapEvidence(gap2);
    const codeEv = codeEvidence("ev-code-1");

    const confirmed = threat("threat-1", { evidenceIds: [ev1.id] });
    const dropped = threat("threat-2", { evidenceIds: [ev2.id], assumptions: [] });
    const defaulted = threat("threat-3", { evidenceIds: [codeEv.id], assumptions: [] });

    const q1 = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    const q2 = question({ id: "question-2", affectedThreatIds: ["threat-2"] });
    const q3 = question({ id: "question-3", affectedThreatIds: ["threat-3"] });

    const effects1 = effectsOf("question-1", ["control_absent", "control_present"], "gap-1");
    const effects2 = effectsOf("question-2", ["control_absent", "control_present"], "gap-2");
    const effects3 = effectsOf("question-3", ["control_absent", "control_present"]);

    const model = baseModel({
      evidence: [ev1, ev2, codeEv],
      threats: [confirmed, dropped, defaulted],
      questions: [q1, q2, q3],
    });
    const result = run({
      model,
      gaps: [gap1, gap2],
      effects: new Map([
        ["question-1", effects1],
        ["question-2", effects2],
        ["question-3", effects3],
      ]),
      answers: [
        { questionId: "question-1", status: "answered", optionIndex: 0 },
        { questionId: "question-2", status: "answered", optionIndex: 1 },
        { questionId: "question-3", status: "skipped" },
      ],
    });

    const validated = validateThreatModel(result.model);
    expect(validated.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Grouping stays linear in the number of answers
// ---------------------------------------------------------------------------

describe("answer grouping cost", () => {
  it("groups 60,000 answers to one question in well under a second (was quadratic: ~3 s)", () => {
    // The route caps a request at 10 answers; this guards applyAnswers itself. Re-spreading
    // the group per answer copied 1 + 2 + ... + n elements; pushing copies none.
    const answers: DeveloperAnswer[] = Array.from({ length: 60_000 }, () => ({
      questionId: "question-1",
      status: "skipped",
    }));
    const started = performance.now();
    const result = run({ model: baseModel(), answers });
    expect(performance.now() - started).toBeLessThan(1000);
    expect(result.limitations).toEqual(['Answer to unknown question "question-1" was ignored.']);
  });
});

// ---------------------------------------------------------------------------
// An applied answer resolves the assumption about its unknown
// ---------------------------------------------------------------------------

describe("resolved unknown assumptions", () => {
  const ABOUT = "Mode A is in use, per the unknown-1 unknown.";
  const OTHER = "The Worker is deployed with ALLOWED_ORIGINS unset.";

  function setup(answer: DeveloperAnswer) {
    const codeEv = codeEvidence("ev-code-1");
    const t = threat("threat-1", {
      evidenceIds: [codeEv.id],
      assumptions: [ABOUT, OTHER],
      dependsOnUnknownIds: ["unknown-1"],
    });
    const q = question({ id: "question-1", affectedThreatIds: ["threat-1"] });
    return run({
      model: baseModel({ evidence: [codeEv], threats: [t], questions: [q] }),
      effects: new Map([["question-1", effectsOf("question-1", ["control_absent", "control_present"])]]),
      answers: [answer],
    }).model.threats[0];
  }

  it("drops the assumption naming the answered unknown and keeps the rest", () => {
    const updated = setup({ questionId: "question-1", status: "answered", optionIndex: 0 });
    expect(updated.assumptions).toEqual([OTHER]);
    expect(updated.confidence).toBeGreaterThan(
      setup({ questionId: "question-1", status: "skipped" }).confidence,
    );
  });

  it("keeps it when the question is skipped, and adds the default", () => {
    const updated = setup({ questionId: "question-1", status: "skipped" });
    expect(updated.assumptions).toEqual(
      [ABOUT, OTHER, "Assume the ownership check is missing."].sort(),
    );
  });

  it("matches the id as a whole token only", () => {
    expect(namesUnknown("see unknown-csp-header", "unknown-csp-header")).toBe(true);
    expect(namesUnknown("see unknown-csp-header", "unknown-csp")).toBe(false);
    expect(namesUnknown("unknown-10 applies", "unknown-1")).toBe(false);
  });
});
