import { describe, expect, it } from "vitest";
import { AnswerValidationError, applyAnswers } from "@/server/questions/answers";
import { defaultEffectFor, effectsFor, type QuestionEffects } from "@/server/questions";
import type {
  DeveloperQuestion,
  Evidence,
  RepoSummary,
  Threat,
  ThreatModel,
} from "@/shared/schema";

// Scenario: an admin panel whose exposure is unknown. No API calls -- the effects sidecar
// is built the way selectQuestions builds it, from option meanings.

const repo: RepoSummary = {
  owner: "acme",
  name: "widgets",
  ref: "main",
  languages: ["TypeScript"],
  frameworks: ["next"],
  fileCountAnalyzed: 10,
  analyzedAt: new Date().toISOString(),
};

const OPTIONS = ["Public on the internet", "Only on VPN", "Behind SSO"];
const DEFAULT_ASSUMPTION = "Assume the admin panel is reachable from the public internet.";

const codeEvidence: Evidence = {
  id: "ev-admin-route",
  kind: "code",
  source: "detector",
  summary: "admin router mounted at /admin",
  filePath: "src/admin.ts",
};

function threat(id: string, over: Partial<Threat> = {}): Threat {
  return {
    id,
    title: `Threat ${id}`,
    stride: ["E"],
    owasp: ["A01:2025"],
    cwe: ["CWE-284"],
    componentIds: ["admin"],
    dataFlowIds: [],
    asset: "admin functions",
    attackScenario: "An attacker reaches the admin panel and abuses it.",
    evidenceIds: [codeEvidence.id],
    assumptions: ["Per unknown-admin-exposure, the panel may be internet reachable."],
    dependsOnUnknownIds: ["unknown-admin-exposure"],
    impact: 4,
    likelihood: 4,
    impactReason: "Admin access exposes every account.",
    likelihoodReason: "The panel's exposure is unknown.",
    severity: "high",
    confidence: 0.5,
    confidenceLabel: "medium",
    basis: "evidence_backed",
    mitigation: { summary: "restrict the admin panel", steps: ["put it behind SSO"] },
    priority: "fix_soon",
    ...over,
  };
}

const question: DeveloperQuestion = {
  id: "question-1",
  text: "Where is the admin panel reachable from?",
  whyAsking: "Nothing in the repository says who can reach /admin.",
  options: OPTIONS,
  allowsUnsure: true,
  affectedThreatIds: ["threat-admin"],
  unknownId: "unknown-admin-exposure",
  defaultAssumption: DEFAULT_ASSUMPTION,
  valueScore: 0.7,
};

function effects(): Map<string, QuestionEffects> {
  const options = effectsFor(["control_absent", "not_applicable", "control_present"], false);
  const def = defaultEffectFor(options);
  if (!def) throw new Error("fixture has no cautious default");
  return new Map([
    [
      question.id,
      {
        questionId: question.id,
        unknownId: question.unknownId,
        options,
        default: def,
        appliesToThreatIds: ["threat-admin"],
      },
    ],
  ]);
}

function state(threats: Threat[]) {
  const model: ThreatModel = {
    schemaVersion: "1.0",
    analysisLevel: 2,
    repo,
    components: [
      {
        id: "admin",
        name: "Admin panel",
        type: "frontend",
        description: "internal admin UI",
        technologies: ["next"],
        files: ["src/admin.ts"],
        assets: ["admin functions"],
      },
    ],
    dataFlows: [],
    trustBoundaries: [],
    unknowns: [],
    evidence: [codeEvidence],
    threats,
    questions: [question],
    assumptions: [],
    limitations: [],
  };
  return { model, effects: effects(), gaps: [] };
}

function adminOf(model: ThreatModel): Threat {
  const t = model.threats.find((x) => x.id === "threat-admin");
  if (!t) throw new Error("threat-admin missing");
  return t;
}

describe("applyAnswers (text answers)", () => {
  it('"Public on the internet" raises the admin threat to Critical and Fix Now', () => {
    const before = state([threat("threat-admin")]);
    const after = adminOf(applyAnswers(before, [{ questionId: "question-1", answer: OPTIONS[0] }]));

    expect(after.likelihood).toBe(5);
    expect(after.severity).toBe("critical");
    expect(after.priority).toBe("fix_now");
    expect(after.likelihoodReason).toContain("the developer confirmed the control is absent");
    expect(after.impactReason).toBe("Admin access exposes every account.");
  });

  it("records the answer as developer evidence and resolves the matching assumption", () => {
    const model = applyAnswers(state([threat("threat-admin")]), [
      { questionId: "question-1", answer: "  public on the INTERNET " },
    ]);
    const t = adminOf(model);
    const ev = model.evidence.find((e) => e.id === "ev-answer-question-1");

    expect(ev).toMatchObject({
      kind: "developer_answer",
      source: "developer",
      summary: `Developer: ${question.text} -> ${OPTIONS[0]}`,
    });
    expect(t.evidenceIds).toContain("ev-answer-question-1");
    expect(t.assumptions).toEqual([]);
  });

  it('"Only on VPN" lowers the admin threat', () => {
    const before = threat("threat-admin");
    const after = adminOf(applyAnswers(state([before]), [{ questionId: "question-1", answer: OPTIONS[1] }]));

    expect(after.likelihood).toBe(3);
    expect(after.impact).toBe(3);
    expect(after.severity).toBe("medium");
    expect(after.priority).not.toBe("fix_now");
    expect(after.likelihoodReason).toContain("does not apply");
    expect(after.impactReason).toContain("does not apply");
  });

  it.each(["skip", "unsure"])(
    '"%s" keeps the threat assumption-dependent with the default assumption shown',
    (answer) => {
      const s = state([threat("threat-admin", { evidenceIds: [], basis: "assumption_dependent" })]);
      const model = applyAnswers(s, [{ questionId: "question-1", answer }]);
      const t = adminOf(model);

      expect(t.basis).toBe("assumption_dependent");
      expect(t.assumptions).toContain(DEFAULT_ASSUMPTION);
      expect(t.evidenceIds).toEqual([]);
      expect(model.evidence.some((e) => e.kind === "developer_answer")).toBe(false);
    },
  );

  it("skip applies no answer evidence and leaves severity at the cautious default", () => {
    const t = adminOf(applyAnswers(state([threat("threat-admin")]), [{ questionId: "question-1", answer: "skip" }]));
    expect(t.evidenceIds).toEqual([codeEvidence.id]);
    expect(t.assumptions).toContain(DEFAULT_ASSUMPTION);
  });

  it("an answer matching no option throws instead of defaulting", () => {
    const s = state([threat("threat-admin")]);
    const run = () => applyAnswers(s, [{ questionId: "question-1", answer: "Somewhere else" }]);
    expect(run).toThrow(AnswerValidationError);
    expect(run).toThrow(/matches none of its options.*"Public on the internet"/);
  });

  it("an answer matching several options throws as ambiguous", () => {
    const s = state([threat("threat-admin")]);
    s.model.questions = [{ ...question, options: ["Only on VPN", "only on vpn ", "Behind SSO"] }];
    const run = () => applyAnswers(s, [{ questionId: "question-1", answer: "ONLY ON VPN" }]);
    expect(run).toThrow(AnswerValidationError);
    expect(run).toThrow(/ambiguous: options 0 and 1/);
  });

  it("an answer to a question that does not exist throws", () => {
    const s = state([threat("threat-admin")]);
    const run = () => applyAnswers(s, [{ questionId: "question-9", answer: "skip" }]);
    expect(run).toThrow(AnswerValidationError);
    expect(run).toThrow(/"question-9" names a question this model does not have/);
  });

  it.each(["Skip", " UNSURE "])('rejects a question whose option is the reserved value "%s"', (option) => {
    const s = state([threat("threat-admin")]);
    s.model.questions = [{ ...question, options: ["Public on the internet", option] }];
    for (const answer of ["skip", "Public on the internet"]) {
      const run = () => applyAnswers(s, [{ questionId: "question-1", answer }]);
      expect(run).toThrow(AnswerValidationError);
      expect(run).toThrow(/option 1 .* reserved answer value/);
    }
  });

  it("leaves unaffected threats deep-equal, and re-scores only the affected one", () => {
    const bystander = threat("threat-other", {
      componentIds: ["admin"],
      dependsOnUnknownIds: [],
      assumptions: ["Unrelated assumption."],
    });
    const before = state([threat("threat-admin"), bystander]);
    const snapshot = structuredClone(before.model.threats.find((t) => t.id === "threat-other"));
    const after = applyAnswers(before, [{ questionId: "question-1", answer: OPTIONS[0] }]);

    expect(after.threats.find((t) => t.id === "threat-other")).toEqual(snapshot);
    expect(adminOf(after).severity).toBe("critical");
  });

  it("does not mutate the input model and returns a schema-valid model", () => {
    const before = state([threat("threat-admin")]);
    const frozen = structuredClone(before.model);
    applyAnswers(before, [{ questionId: "question-1", answer: OPTIONS[0] }]);
    expect(before.model).toEqual(frozen);
  });
});
