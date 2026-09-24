import type Anthropic from "@anthropic-ai/sdk";
import { describe, expect, it } from "vitest";
import type { ClaudeDeps, MessagesApi } from "@/server/ai/claude";
import { UsageLedger } from "@/server/ai/usage";
import {
  MAX_QUESTIONS,
  MEANING_EFFECT,
  MIN_VALUE,
  QUESTIONS_MAX_TOKENS,
  QUESTIONS_THINKING,
  QuestionDraftSchema,
  QuestionsResponseSchema,
  SEVERITY_WEIGHT,
  answeredByFacts,
  combinedDelta,
  defaultEffectFor,
  effectsFor,
  gapFor,
  linkUnknowns,
  qualifiesForQuestion,
  questionsJsonSchema,
  rankCandidates,
  selectCandidates,
  selectQuestions,
  severityWeightOf,
  toStoredValueScore,
  uncertaintyWeightOf,
  valueOf,
  type OptionEffect,
  type OptionMeaning,
  type QuestionsResponse,
} from "@/server/questions";
import { severityOf } from "@/server/scoring";
import type { ControlGap, Deployment } from "@/server/detect/types";
import {
  CandidateQuestionSchema,
  DeveloperQuestionSchema,
  type Component,
  type Severity,
  type Threat,
  type Unknown,
} from "@/shared/schema";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function unknown(id: string, affects: string[] = ["comp-a"], description?: string): Unknown {
  return {
    id,
    description: description ?? `Is control X present for ${affects.join(", ")}?`,
    affectsComponentIds: affects,
  };
}

function gap(id: string, certainty = 0.5): ControlGap {
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

function component(id: string, name: string): Component {
  return {
    id,
    name,
    type: "backend",
    description: `The ${name} service`,
    technologies: [],
    files: [],
    assets: [],
  };
}

function composeDeployment(name: string, ports: number[] = []): Deployment {
  return { kind: "compose", name, ports, file: "docker-compose.yml", line: 1 };
}

function threat(
  id: string,
  over: Partial<Threat> & {
    dependsOnUnknownIds: string[];
    severity: Severity;
    confidence: number;
  },
): Threat {
  return {
    id,
    title: `Threat ${id}`,
    stride: ["E"],
    owasp: ["A01:2025"],
    cwe: [],
    // Empty by default, deliberately: linkUnknowns also links a threat to an unknown
    // by a SHARED component id, and unknown()'s default affects ["comp-a"] would
    // otherwise silently link every default threat() to every default unknown() in
    // tests that only mean to link them via dependsOnUnknownIds. Tests that want to
    // exercise the component-linking path set componentIds explicitly.
    componentIds: [],
    dataFlowIds: [],
    asset: "customer data",
    attackScenario: "an attacker does something bad",
    evidenceIds: [],
    assumptions: ["placeholder"],
    impact: 3,
    likelihood: 3,
    impactReason: "reason",
    likelihoodReason: "reason",
    confidenceLabel: "medium",
    basis: "assumption_dependent",
    mitigation: { summary: "fix it", steps: ["do the fix"], codeLocation: "src/routes/orders.ts" },
    priority: "monitor",
    ...over,
  };
}

function message(payload: QuestionsResponse): Anthropic.Message {
  return {
    id: "msg_test",
    type: "message",
    role: "assistant",
    model: "claude-sonnet-5",
    content: [{ type: "text", text: JSON.stringify(payload), citations: null }],
    stop_reason: "end_turn",
    stop_sequence: null,
    stop_details: null,
    usage: {
      input_tokens: 100,
      output_tokens: 50,
      cache_read_input_tokens: 0,
      cache_creation_input_tokens: 0,
    },
  } as Anthropic.Message;
}

function userTextOf(body: Anthropic.MessageCreateParamsNonStreaming): string {
  return body.messages
    .map((m) => (typeof m.content === "string" ? m.content : JSON.stringify(m.content)))
    .join("\n");
}

function offeredIdsIn(body: Anthropic.MessageCreateParamsNonStreaming): string[] {
  return [...userTextOf(body).matchAll(/### UNKNOWN (\S+)/g)].map((m) => m[1]);
}

/** A harness whose model writes one plausible question per offered unknown, with the given meanings. */
function harness(
  meaningsByUnknown: Record<string, OptionMeaning[]>,
): { deps: Partial<ClaudeDeps>; calls: Anthropic.MessageCreateParamsNonStreaming[] } {
  const calls: Anthropic.MessageCreateParamsNonStreaming[] = [];
  const client: MessagesApi = {
    async create(body) {
      calls.push(body);
      const ids = offeredIdsIn(body);
      const questions = ids.map((id) => {
        const meanings = meaningsByUnknown[id] ?? ["control_absent", "control_present"];
        return {
          text: `Question about ${id}?`,
          whyAsking: "it matters",
          options: meanings.map((_, j) => `Option ${j + 1} for ${id}`),
          allowsUnsure: true,
          unknownId: id,
          defaultAssumption: `assume the worst for ${id}`,
          optionMeanings: meanings,
        };
      });
      return message({ questions });
    },
  };
  return {
    calls,
    deps: {
      client,
      ledger: new UsageLedger(),
      sleep: async () => {},
      schedule: () => () => {},
      isDevelopment: false,
      writeDebug: () => {},
    },
  };
}

function fixedDraftHarness(
  respond: (ids: string[]) => QuestionsResponse,
): { deps: Partial<ClaudeDeps>; calls: Anthropic.MessageCreateParamsNonStreaming[] } {
  const calls: Anthropic.MessageCreateParamsNonStreaming[] = [];
  const client: MessagesApi = {
    async create(body) {
      calls.push(body);
      return message(respond(offeredIdsIn(body)));
    },
  };
  return {
    calls,
    deps: {
      client,
      ledger: new UsageLedger(),
      sleep: async () => {},
      schedule: () => () => {},
      isDevelopment: false,
      writeDebug: () => {},
    },
  };
}

// ---------------------------------------------------------------------------
// 1a. Ranking factors and weights, in isolation
// ---------------------------------------------------------------------------

describe("severityWeightOf", () => {
  it("maps every severity to its fixed weight and takes the max across threats", () => {
    expect(severityWeightOf([threat("t1", { dependsOnUnknownIds: [], severity: "critical", confidence: 0 })])).toBe(4);
    expect(severityWeightOf([threat("t1", { dependsOnUnknownIds: [], severity: "high", confidence: 0 })])).toBe(3);
    expect(severityWeightOf([threat("t1", { dependsOnUnknownIds: [], severity: "medium", confidence: 0 })])).toBe(2);
    expect(severityWeightOf([threat("t1", { dependsOnUnknownIds: [], severity: "low", confidence: 0 })])).toBe(1);
    expect(
      severityWeightOf([
        threat("t1", { dependsOnUnknownIds: [], severity: "low", confidence: 0 }),
        threat("t2", { dependsOnUnknownIds: [], severity: "critical", confidence: 0 }),
      ]),
    ).toBe(4);
  });

  it("is 0 for an empty threat list", () => {
    expect(severityWeightOf([])).toBe(0);
  });

  it("matches the SEVERITY_WEIGHT table exactly", () => {
    (Object.keys(SEVERITY_WEIGHT) as Severity[]).forEach((severity) => {
      expect(severityWeightOf([threat("t", { dependsOnUnknownIds: [], severity, confidence: 0 })])).toBe(
        SEVERITY_WEIGHT[severity],
      );
    });
  });
});

describe("uncertaintyWeightOf", () => {
  it("is 1 - mean confidence", () => {
    expect(
      uncertaintyWeightOf([
        threat("t1", { dependsOnUnknownIds: [], severity: "low", confidence: 0.2 }),
        threat("t2", { dependsOnUnknownIds: [], severity: "low", confidence: 0.4 }),
      ]),
    ).toBeCloseTo(1 - 0.3, 10);
  });

  it("is 0 for an empty threat list", () => {
    expect(uncertaintyWeightOf([])).toBe(0);
  });

  it("is 0 when every affected threat has confidence 1, and 1 when every one has confidence 0", () => {
    expect(uncertaintyWeightOf([threat("t1", { dependsOnUnknownIds: [], severity: "low", confidence: 1 })])).toBe(0);
    expect(uncertaintyWeightOf([threat("t1", { dependsOnUnknownIds: [], severity: "low", confidence: 0 })])).toBe(1);
  });
});

describe("valueOf", () => {
  it("multiplies maxSeverityWeight * uncertainty * log2(1 + affectedCount) exactly", () => {
    // critical (4) * uncertainty (1-0.5=0.5) * log2(1+1)=1 -> 2.0
    const critical1 = [threat("t1", { dependsOnUnknownIds: [], severity: "critical", confidence: 0.5 })];
    expect(valueOf(critical1)).toBeCloseTo(2.0, 10);

    // max(high=3, medium=2)=3 * uncertainty (1 - mean(0.2,0.4)=0.7) * log2(1+2)=log2(3)
    const highMedium = [
      threat("t1", { dependsOnUnknownIds: [], severity: "high", confidence: 0.2 }),
      threat("t2", { dependsOnUnknownIds: [], severity: "medium", confidence: 0.4 }),
    ];
    expect(valueOf(highMedium)).toBeCloseTo(3 * 0.7 * Math.log2(3), 10);

    // three low threats, confidence 0.5 each -> 1 * 0.5 * log2(4)=2 -> 1.0
    const threeLow = [
      threat("t1", { dependsOnUnknownIds: [], severity: "low", confidence: 0.5 }),
      threat("t2", { dependsOnUnknownIds: [], severity: "low", confidence: 0.5 }),
      threat("t3", { dependsOnUnknownIds: [], severity: "low", confidence: 0.5 }),
    ];
    expect(valueOf(threeLow)).toBeCloseTo(1.0, 10);
  });

  it("is 0 when nothing is affected", () => {
    expect(valueOf([])).toBe(0);
  });

  it("is unbounded above -- not clamped to 1, unlike the old formula", () => {
    const many = Array.from({ length: 20 }, (_, i) =>
      threat(`t${i}`, { dependsOnUnknownIds: [], severity: "critical", confidence: 0 }),
    );
    expect(valueOf(many)).toBeGreaterThan(1);
  });
});

describe("MIN_VALUE boundary (1.5)", () => {
  it("MIN_VALUE is exactly 1.5, per the spec", () => {
    expect(MIN_VALUE).toBe(1.5);
  });

  it("qualifiesForQuestion is >=, not >: exactly MIN_VALUE qualifies, and a hair below it does not", () => {
    expect(qualifiesForQuestion(MIN_VALUE)).toBe(true);
    expect(qualifiesForQuestion(MIN_VALUE - Number.EPSILON)).toBe(false);
    expect(qualifiesForQuestion(MIN_VALUE + Number.EPSILON)).toBe(true);
  });

  it("a low-value unknown (three low threats, raw 1.0) is below the 1.5 bar and a high one (raw 2.0) clears it", () => {
    const low = [
      threat("t1", { dependsOnUnknownIds: [], severity: "low", confidence: 0.5 }),
      threat("t2", { dependsOnUnknownIds: [], severity: "low", confidence: 0.5 }),
      threat("t3", { dependsOnUnknownIds: [], severity: "low", confidence: 0.5 }),
    ];
    expect(qualifiesForQuestion(valueOf(low))).toBe(false);

    const high = [threat("t1", { dependsOnUnknownIds: [], severity: "critical", confidence: 0.5 })];
    expect(qualifiesForQuestion(valueOf(high))).toBe(true);
  });
});

describe("toStoredValueScore", () => {
  it("fits a raw value into the frozen 0..1 valueScore field", () => {
    expect(toStoredValueScore(2.0)).toBeCloseTo(0.25, 10); // 2 / 8
    expect(toStoredValueScore(9)).toBe(1); // clamped
    expect(toStoredValueScore(0)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 1b. gapFor: exhaustive id-shape coverage, boost fails closed
// ---------------------------------------------------------------------------

describe("gapFor", () => {
  it("resolves an ordinary gap-derived unknown id", () => {
    const g = gap("gap-3");
    expect(gapFor("unknown-gap-3", [g])).toBe(g);
  });

  it("resolves a collision-suffixed gap-derived unknown id", () => {
    const g = gap("gap-3");
    expect(gapFor("unknown-gap-3-2", [g])).toBe(g);
    expect(gapFor("unknown-gap-3-7", [g])).toBe(g);
  });

  it("returns undefined for malformed ids that merely resemble the shape", () => {
    const gaps = [gap("gap-3")];
    expect(gapFor("unknown-gap", gaps)).toBeUndefined(); // no digits
    expect(gapFor("unknown-3-gap", gaps)).toBeUndefined(); // wrong order
    expect(gapFor("unknowngap-3", gaps)).toBeUndefined(); // missing hyphen after "unknown"
    expect(gapFor("unknown-gap-3x", gaps)).toBeUndefined(); // trailing non-digit
    expect(gapFor("unknown-gap--3", gaps)).toBeUndefined(); // double hyphen
    expect(gapFor("prefix-unknown-gap-3", gaps)).toBeUndefined(); // not anchored at start
  });

  it("returns undefined when the referenced gap is missing from ControlGap[]", () => {
    expect(gapFor("unknown-gap-99", [gap("gap-1"), gap("gap-2")])).toBeUndefined();
  });

  it("returns undefined for an ordinary unknown whose id merely contains the word 'gap'", () => {
    const gaps = [gap("gap-1")];
    expect(gapFor("unknown-mind-the-gap-1", gaps)).toBeUndefined();
    expect(gapFor("unknown-gap-in-coverage-1", gaps)).toBeUndefined();
  });

  it("is not fooled by 'gap' appearing only in the description, not the id", () => {
    const gaps = [gap("gap-1")];
    // gapFor only ever looks at the id; sanity-check that a description mentioning "gap"
    // does not somehow leak into the match.
    const u = unknown("unknown-model-7", ["comp-a"], "Is there a gap in our validation?");
    expect(gapFor(u.id, gaps)).toBeUndefined();
  });

  it("does not identify a gap for an id that merely resembles the shape (fails closed)", () => {
    const gaps = [gap("gap-1")];
    const idsThatShouldNotMatch = [
      "unknown-gap", // malformed
      "unknown-gap-99", // no matching gap
      "unknown-mind-the-gap-1", // contains "gap" but wrong shape
    ];
    for (const id of idsThatShouldNotMatch) {
      expect(gapFor(id, gaps)).toBeUndefined();
    }
  });
});

// ---------------------------------------------------------------------------
// 1d. Tie-break and order-independence
// ---------------------------------------------------------------------------

describe("ranking determinism", () => {
  it("breaks a valueScore tie by ascending unknown id", () => {
    const a = unknown("unknown-model-b");
    const b = unknown("unknown-model-a");
    const threats = [
      threat("t1", { dependsOnUnknownIds: ["unknown-model-b"], severity: "high", confidence: 0.5 }),
      threat("t2", { dependsOnUnknownIds: ["unknown-model-a"], severity: "high", confidence: 0.5 }),
    ];
    const ranked = rankCandidates([a, b], threats, []);
    expect(ranked[0].valueScore).toBeCloseTo(ranked[1].valueScore, 10);
    expect(ranked.map((c) => c.unknown.id)).toEqual(["unknown-model-a", "unknown-model-b"]);
  });

  it("produces identical order for reordered (but content-identical) inputs", () => {
    const unknowns = [unknown("unknown-model-1"), unknown("unknown-model-2"), unknown("unknown-model-3")];
    const threats = [
      threat("t1", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.1 }),
      threat("t2", { dependsOnUnknownIds: ["unknown-model-2"], severity: "high", confidence: 0.4 }),
      threat("t3", { dependsOnUnknownIds: ["unknown-model-3"], severity: "low", confidence: 0.9 }),
    ];

    const forward = rankCandidates(unknowns, threats, []);
    const reversed = rankCandidates([...unknowns].reverse(), [...threats].reverse(), []);
    expect(reversed.map((c) => c.unknown.id)).toEqual(forward.map((c) => c.unknown.id));
    reversed.forEach((c, i) => expect(c.valueScore).toBeCloseTo(forward[i].valueScore, 10));
  });
});

// ---------------------------------------------------------------------------
// 1c. linkUnknowns: dependsOnUnknownIds and component links
// ---------------------------------------------------------------------------

describe("linkUnknowns", () => {
  it("links a threat purely by a shared component id, with no dependsOnUnknownIds entry", () => {
    const u = unknown("unknown-model-1", ["comp-x"]);
    const t = threat("t1", { dependsOnUnknownIds: [], severity: "high", confidence: 0.3, componentIds: ["comp-x"] });
    const [linked] = linkUnknowns([u], [t]);
    expect(linked.dependentThreatIds).toEqual([]);
    expect(linked.affectedThreatIds).toEqual(["t1"]);
  });

  it("counts a threat linked both ways exactly once, and the result is sorted", () => {
    const u = unknown("unknown-model-1", ["comp-x"]);
    const both = threat("t-zeta", {
      dependsOnUnknownIds: ["unknown-model-1"],
      severity: "high",
      confidence: 0.3,
      componentIds: ["comp-x"],
    });
    const componentOnly = threat("t-alpha", {
      dependsOnUnknownIds: [],
      severity: "high",
      confidence: 0.3,
      componentIds: ["comp-x"],
    });
    const [linked] = linkUnknowns([u], [both, componentOnly]);
    expect(linked.dependentThreatIds).toEqual(["t-zeta"]);
    expect(linked.affectedThreatIds).toEqual(["t-alpha", "t-zeta"]);
  });

  it("does not link a threat sharing no component and no dependsOnUnknownIds entry", () => {
    const u = unknown("unknown-model-1", ["comp-x"]);
    const t = threat("t1", { dependsOnUnknownIds: [], severity: "high", confidence: 0.3, componentIds: ["comp-y"] });
    const [linked] = linkUnknowns([u], [t]);
    expect(linked.affectedThreatIds).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 1d. answeredByFacts: dropping an exposure unknown a Compose fact already answers
// ---------------------------------------------------------------------------

describe("answeredByFacts", () => {
  const exposureUnknown = unknown(
    "unknown-model-1",
    ["comp-api"],
    "Is the orders-api service exposed on the public internet?",
  );
  const components = [component("comp-api", "orders-api")];

  it("drops an exposure unknown when its component maps to a Compose service with no published ports", () => {
    expect(answeredByFacts(exposureUnknown, components, [composeDeployment("orders-api")])).toBe(true);
  });

  it("keeps the unknown when the Compose service publishes a port", () => {
    expect(answeredByFacts(exposureUnknown, components, [composeDeployment("orders-api", [8080])])).toBe(false);
  });

  it("keeps the unknown when the component cannot be matched to any deployment fact", () => {
    expect(answeredByFacts(exposureUnknown, components, [])).toBe(false);
  });

  it("keeps a non-exposure unknown regardless of deployment facts", () => {
    const nonExposure = unknown("unknown-model-2", ["comp-api"], "Does orders-api validate the order total?");
    expect(answeredByFacts(nonExposure, components, [composeDeployment("orders-api")])).toBe(false);
  });

  it("normalizes names when matching (case and punctuation insensitive)", () => {
    expect(answeredByFacts(exposureUnknown, components, [composeDeployment("Orders-API")])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 1e. selectCandidates: the full drop pipeline and its skipped reasons
// ---------------------------------------------------------------------------

describe("selectCandidates", () => {
  it("drops an unknown with zero affected threats as no_affected_threats", () => {
    const u = unknown("unknown-model-1");
    const { winners, skipped } = selectCandidates([u], [], [], [], []);
    expect(winners).toEqual([]);
    expect(skipped).toEqual([{ unknownId: "unknown-model-1", reason: "no_affected_threats" }]);
  });

  it("drops an unknown answered by facts before it ever reaches the value threshold", () => {
    const u = unknown("unknown-model-1", ["comp-api"], "Is orders-api exposed to the internet?");
    const t = threat("t1", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0 });
    const { winners, skipped } = selectCandidates(
      [u],
      [t],
      [],
      [component("comp-api", "orders-api")],
      [composeDeployment("orders-api")],
    );
    expect(winners).toEqual([]);
    expect(skipped).toEqual([{ unknownId: "unknown-model-1", reason: "answered_by_facts" }]);
  });

  it("marks anything past MAX_QUESTIONS as over_cap, in ranked order", () => {
    const unknowns = Array.from({ length: 5 }, (_, i) => unknown(`unknown-model-${i + 1}`));
    const severities: Severity[] = ["critical", "high", "high", "medium", "medium"];
    const threats = unknowns.map((u, i) =>
      threat(`t${i + 1}`, { dependsOnUnknownIds: [u.id], severity: severities[i], confidence: 0 }),
    );
    const { winners, skipped } = selectCandidates(unknowns, threats, [], [], []);
    expect(winners.length).toBe(MAX_QUESTIONS);
    expect(skipped.map((s) => s.reason)).toEqual(["over_cap", "over_cap"]);
  });
});

// ---------------------------------------------------------------------------
// 2. effectsFor: exact equality to the fixed meaning table
// ---------------------------------------------------------------------------

/**
 * Literal, hand-written expectations for the fixed meaning table -- deliberately NOT
 * read from the module's own MEANING_EFFECT export. Asserting effectsFor's output
 * against the very constant it is built from is a tautology that survives a mutation
 * to that constant; only a hardcoded expectation can catch one.
 */
const EXPECTED_MEANING_EFFECT: Record<OptionMeaning, { likelihoodDelta: number; impactDelta: number; resolution: "confirms_gap" | "clears_gap" | "no_change" }> = {
  control_absent: { likelihoodDelta: 1, impactDelta: 0, resolution: "confirms_gap" },
  control_present: { likelihoodDelta: -1, impactDelta: 0, resolution: "clears_gap" },
  partial: { likelihoodDelta: 0, impactDelta: 0, resolution: "no_change" },
  not_applicable: { likelihoodDelta: -1, impactDelta: -1, resolution: "clears_gap" },
};

describe("MEANING_EFFECT table", () => {
  it("matches the hand-written expectation exactly (guards against silently editing the table)", () => {
    const withoutReason = Object.fromEntries(
      Object.entries(MEANING_EFFECT).map(([meaning, { reason, ...numbers }]) => {
        expect(reason.length).toBeGreaterThan(0);
        return [meaning, numbers];
      }),
    );
    expect(withoutReason).toEqual(EXPECTED_MEANING_EFFECT);
  });
});

describe("effectsFor", () => {
  it("matches the fixed meaning table exactly for every meaning, gap-derived", () => {
    const meanings: OptionMeaning[] = ["control_absent", "control_present", "partial", "not_applicable"];
    const effects = effectsFor(meanings, true);
    effects.forEach((effect, i) => {
      const meaning = meanings[i];
      expect(effect.optionIndex).toBe(i);
      expect(effect.likelihoodDelta).toBe(EXPECTED_MEANING_EFFECT[meaning].likelihoodDelta);
      expect(effect.impactDelta).toBe(EXPECTED_MEANING_EFFECT[meaning].impactDelta);
      expect(effect.certaintyResolution).toBe(EXPECTED_MEANING_EFFECT[meaning].resolution);
      expect(effect.addsEvidenceKind).toBe("developer_answer");
    });
  });

  it("forces no_change for every option when the question is not gap-derived, regardless of the table", () => {
    const meanings: OptionMeaning[] = ["control_absent", "control_present", "partial", "not_applicable"];
    const effects = effectsFor(meanings, false);
    for (const effect of effects) {
      expect(effect.certaintyResolution).toBe("no_change");
    }
  });

  it("still uses the table's deltas even when not gap-derived", () => {
    const meanings: OptionMeaning[] = ["control_absent", "not_applicable"];
    const effects = effectsFor(meanings, false);
    expect(effects[0].likelihoodDelta).toBe(1);
    expect(effects[0].impactDelta).toBe(0);
    expect(effects[1].likelihoodDelta).toBe(-1);
    expect(effects[1].impactDelta).toBe(-1);
  });
});

// ---------------------------------------------------------------------------
// 3. defaultEffectFor: cautious-default rules, unit-level
// ---------------------------------------------------------------------------

function opt(over: Partial<OptionEffect>): OptionEffect {
  return {
    optionIndex: 0,
    likelihoodDelta: 0,
    impactDelta: 0,
    addsEvidenceKind: "developer_answer",
    certaintyResolution: "no_change",
    ...over,
  };
}

describe("defaultEffectFor", () => {
  it("never invents or zeros a delta: the returned effect's deltas equal a real input option's", () => {
    const options = [
      opt({ optionIndex: 0, likelihoodDelta: -1, impactDelta: 0 }),
      opt({ optionIndex: 1, likelihoodDelta: 1, impactDelta: 0 }),
    ];
    const def = defaultEffectFor(options)!;
    expect(def).toBeDefined();
    const matchesSomeOption = options.some(
      (o) => o.likelihoodDelta === def.likelihoodDelta && o.impactDelta === def.impactDelta,
    );
    expect(matchesSomeOption).toBe(true);
  });

  it("selects the eligible option with the greatest combined delta when none is confirms_gap", () => {
    const options = [
      opt({ optionIndex: 0, likelihoodDelta: 0, impactDelta: 0, certaintyResolution: "no_change" }),
      opt({ optionIndex: 1, likelihoodDelta: -1, impactDelta: 0, certaintyResolution: "clears_gap" }),
    ];
    const def = defaultEffectFor(options)!;
    expect(combinedDelta(def)).toBe(0);
    expect(def.certaintyResolution).toBe("no_change");
  });

  it("prefers a confirms_gap option over a higher-delta non-confirms_gap option", () => {
    // Hand-crafted: option B has a strictly greater combined delta than the confirms_gap
    // option A, but A must still win, because the gap standing is the conservative
    // reading even when another real option would raise risk more.
    const optionA = opt({ optionIndex: 0, likelihoodDelta: 1, impactDelta: 0, certaintyResolution: "confirms_gap" });
    const optionB = opt({ optionIndex: 1, likelihoodDelta: 2, impactDelta: 0, certaintyResolution: "no_change" });
    const def = defaultEffectFor([optionA, optionB])!;
    expect(def.certaintyResolution).toBe("confirms_gap");
    expect(def.likelihoodDelta).toBe(1);
    expect(def.impactDelta).toBe(0);
  });

  it("breaks ties within the eligible pool by lowest option index", () => {
    const optionA = opt({ optionIndex: 0, likelihoodDelta: 1, impactDelta: 0, certaintyResolution: "no_change" });
    const optionB = opt({ optionIndex: 1, likelihoodDelta: 1, impactDelta: 0, certaintyResolution: "no_change" });
    const def = defaultEffectFor([optionB, optionA])!;
    // Both have combinedDelta 1; the first one encountered wins deterministically.
    expect(def.optionIndex).toBe(-1);
    expect(def.likelihoodDelta).toBe(1);
  });

  it("returns undefined when every option's combined delta is negative", () => {
    const options = [
      opt({ optionIndex: 0, likelihoodDelta: -1, impactDelta: 0 }),
      opt({ optionIndex: 1, likelihoodDelta: -1, impactDelta: -1 }),
    ];
    expect(defaultEffectFor(options)).toBeUndefined();
  });

  it("always sets optionIndex -1 and addsEvidenceKind assumption on the returned default", () => {
    const options = [opt({ optionIndex: 0, likelihoodDelta: 0, impactDelta: 0 })];
    const def = defaultEffectFor(options)!;
    expect(def.optionIndex).toBe(-1);
    expect(def.addsEvidenceKind).toBe("assumption");
  });

  it("a lone zero-delta option is eligible and becomes the default (0 >= 0)", () => {
    const options = [opt({ optionIndex: 0, likelihoodDelta: 0, impactDelta: 0, certaintyResolution: "no_change" })];
    const def = defaultEffectFor(options)!;
    expect(def).toBeDefined();
    expect(combinedDelta(def)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 4. No default ever lowers a severity band (property test over severityOf)
// ---------------------------------------------------------------------------

describe("cautious defaults never lower severity", () => {
  it("holds across every meaning-table option in isolation, gap-derived and not", () => {
    const meanings: OptionMeaning[] = ["control_absent", "control_present", "partial", "not_applicable"];
    for (const isGapDerived of [true, false]) {
      const effects = effectsFor(meanings, isGapDerived);
      const def = defaultEffectFor(effects);
      if (!def) continue; // a legitimately empty default is covered by its own test
      for (const impact of [1, 3, 5]) {
        for (const likelihood of [1, 3, 5]) {
          const clamp = (n: number) => Math.min(5, Math.max(1, n));
          const before = severityOf(impact, likelihood);
          const after = severityOf(clamp(impact + def.impactDelta), clamp(likelihood + def.likelihoodDelta));
          const rank = { low: 0, medium: 1, high: 2, critical: 3 } as const;
          expect(rank[after]).toBeGreaterThanOrEqual(rank[before]);
        }
      }
    }
  });

  it("holds end to end through selectQuestions for a realistic gap-derived and model-authored pair", async () => {
    const g = gap("gap-1", 0.6);
    const unknowns = [unknown("unknown-gap-1"), unknown("unknown-model-1")];
    const threats = [
      threat("threat-1", {
        dependsOnUnknownIds: ["unknown-gap-1"],
        severity: "high",
        confidence: 0.3,
        impact: 4,
        likelihood: 4,
      }),
      threat("threat-2", {
        dependsOnUnknownIds: ["unknown-model-1"],
        severity: "high",
        confidence: 0.3,
        impact: 3,
        likelihood: 4,
      }),
    ];

    const { deps } = harness({
      "unknown-gap-1": ["control_present", "not_applicable", "control_absent"],
      "unknown-model-1": ["control_present", "not_applicable", "partial"],
    });
    const result = await selectQuestions({ unknowns, threats, gaps: [g], analysisId: "test", deps, promptDir: "prompts" });

    for (const question of result.questions) {
      const affected = threats.filter((t) => question.affectedThreatIds.includes(t.id));
      const def = result.effects.get(question.id)!.default;
      for (const t of affected) {
        const clamp = (n: number) => Math.min(5, Math.max(1, n));
        const before = severityOf(t.impact, t.likelihood);
        const after = severityOf(clamp(t.impact + def.impactDelta), clamp(t.likelihood + def.likelihoodDelta));
        const rank = { low: 0, medium: 1, high: 2, critical: 3 } as const;
        expect(rank[after]).toBeGreaterThanOrEqual(rank[before]);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 5. selectQuestions: drops a question when no cautious default exists
// ---------------------------------------------------------------------------

describe("selectQuestions drops a question with no cautious default", () => {
  it("drops it, records a limitation, and keeps ids sequential for the survivors", async () => {
    const unknowns = [unknown("unknown-model-1"), unknown("unknown-model-2")];
    const threats = [
      threat("t1", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.1 }),
      threat("t2", { dependsOnUnknownIds: ["unknown-model-2"], severity: "critical", confidence: 0.1 }),
    ];

    // unknown-model-1's only options are risk-lowering (no eligible default);
    // unknown-model-2 has a safe partial option.
    const { deps } = harness({
      "unknown-model-1": ["control_present", "not_applicable"],
      "unknown-model-2": ["partial", "control_present"],
    });
    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });

    expect(result.questions.length).toBe(1);
    expect(result.questions[0].unknownId).toBe("unknown-model-2");
    expect(result.questions[0].id).toBe("question-1"); // no gap left by the drop
    expect(
      result.limitations.some((l) => l.includes("unknown-model-1") && l.includes("no cautious default")),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 6. Ranking happens before wording
// ---------------------------------------------------------------------------

describe("ranking happens before wording", () => {
  it("makes no model call when every candidate is below MIN_VALUE", async () => {
    const unknowns = [unknown("unknown-model-1"), unknown("unknown-model-2")];
    const threats = unknowns.map((u, i) =>
      threat(`threat-${i + 1}`, { dependsOnUnknownIds: [u.id], severity: "low", confidence: 0.95 }),
    );
    const { deps, calls } = harness({});
    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });
    expect(result.questions).toEqual([]);
    expect(result.effects.size).toBe(0);
    expect(calls.length).toBe(0);
  });

  it("sends the model no more than MAX_QUESTIONS unknowns even when more qualify", async () => {
    const unknowns = Array.from({ length: 5 }, (_, i) => unknown(`unknown-model-${i + 1}`));
    const severities: Severity[] = ["critical", "high", "high", "medium", "medium"];
    const threats = unknowns.map((u, i) =>
      threat(`threat-${i + 1}`, { dependsOnUnknownIds: [u.id], severity: severities[i], confidence: 0 }),
    );
    const expectedTop3 = rankCandidates(unknowns, threats, [])
      .filter((c) => c.valueScore >= MIN_VALUE)
      .slice(0, MAX_QUESTIONS)
      .map((c) => c.unknown.id);
    expect(expectedTop3.length).toBe(3);

    const { deps, calls } = harness({});
    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });

    expect(calls.length).toBe(1);
    const offered = offeredIdsIn(calls[0]);
    expect(offered.length).toBe(MAX_QUESTIONS);
    expect(offered).toEqual(expectedTop3);
    expect(result.questions.map((q) => q.unknownId)).toEqual(expectedTop3);
  });

  it("selects identical ids and effects regardless of input order", async () => {
    const unknowns = [unknown("unknown-model-1"), unknown("unknown-model-2"), unknown("unknown-model-3")];
    const threats = [
      threat("t1", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.1 }),
      threat("t2", { dependsOnUnknownIds: ["unknown-model-2"], severity: "high", confidence: 0.2 }),
      threat("t3", { dependsOnUnknownIds: ["unknown-model-3"], severity: "high", confidence: 0.3 }),
    ];

    const run = async (u: Unknown[], t: Threat[]) => {
      const { deps } = harness({});
      return selectQuestions({ unknowns: u, threats: t, gaps: [], analysisId: "test", deps, promptDir: "prompts" });
    };

    const forward = await run(unknowns, threats);
    const reordered = await run([...unknowns].reverse(), [...threats].reverse());

    expect(reordered.questions.map((q) => q.unknownId)).toEqual(forward.questions.map((q) => q.unknownId));
    forward.questions.forEach((q, i) => {
      const a = forward.effects.get(q.id)!;
      const b = reordered.effects.get(reordered.questions[i].id)!;
      expect(b.unknownId).toBe(a.unknownId);
      expect(b.options).toEqual(a.options);
      expect(b.default).toEqual(a.default);
    });
  });

  it("resolves a valueScore tie by unknown id, end to end", async () => {
    const unknowns = [unknown("unknown-model-z"), unknown("unknown-model-a")];
    const threats = [
      threat("t1", { dependsOnUnknownIds: ["unknown-model-z"], severity: "high", confidence: 0.5 }),
      threat("t2", { dependsOnUnknownIds: ["unknown-model-a"], severity: "high", confidence: 0.5 }),
    ];
    const { deps, calls } = harness({});
    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });
    expect(offeredIdsIn(calls[0])).toEqual(["unknown-model-a", "unknown-model-z"]);
    expect(result.questions.map((q) => q.unknownId)).toEqual(["unknown-model-a", "unknown-model-z"]);
  });

  it("returns empty with no model call when there are no unknowns at all", async () => {
    const { deps, calls } = harness({});
    const result = await selectQuestions({ unknowns: [], threats: [], gaps: [], analysisId: "test", deps, promptDir: "prompts" });
    expect(result.questions).toEqual([]);
    expect(calls.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 7. Cap of 3, option-effect completeness, sidecar/id alignment
// ---------------------------------------------------------------------------

describe("selectQuestions: cap, completeness, and sidecar alignment", () => {
  it("caps at MAX_QUESTIONS and keeps the highest-value candidates", async () => {
    const unknowns = Array.from({ length: 6 }, (_, i) => unknown(`unknown-model-${i + 1}`));
    const severities: Severity[] = ["critical", "high", "high", "medium", "medium", "low"];
    const threats = unknowns.map((u, i) =>
      threat(`threat-${i + 1}`, { dependsOnUnknownIds: [u.id], severity: severities[i], confidence: 0.1 * i }),
    );

    const ranked = rankCandidates(unknowns, threats, []);
    const expectedTop3 = ranked.filter((c) => c.valueScore >= MIN_VALUE).slice(0, 3).map((c) => c.unknown.id);

    const { deps } = harness({});
    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });

    expect(result.questions.length).toBeLessThanOrEqual(MAX_QUESTIONS);
    expect(result.questions.map((q) => q.unknownId)).toEqual(expectedTop3);
  });

  it("returns a complete, index-aligned option effect for every option of every question, and the sidecar has exactly one entry per question", async () => {
    const g = gap("gap-1", 0.5);
    const unknowns = [unknown("unknown-gap-1"), unknown("unknown-model-1", ["comp-b"])];
    const threats = [
      threat("threat-1", { dependsOnUnknownIds: ["unknown-gap-1"], severity: "critical", confidence: 0.2 }),
      threat("threat-2", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.2 }),
    ];

    const { deps } = harness({
      "unknown-gap-1": ["control_absent", "control_present", "partial"],
      "unknown-model-1": ["partial", "control_present"],
    });
    const result = await selectQuestions({ unknowns, threats, gaps: [g], analysisId: "test", deps, promptDir: "prompts" });

    expect(result.questions.length).toBe(2);
    expect(result.effects.size).toBe(result.questions.length);
    for (const question of result.questions) {
      const effects = result.effects.get(question.id);
      expect(effects).toBeDefined();
      expect(effects!.questionId).toBe(question.id);
      expect(effects!.unknownId).toBe(question.unknownId);
      expect(effects!.options.length).toBe(question.options.length);
      effects!.options.forEach((effect, index) => {
        expect(effect.optionIndex).toBe(index);
        expect(typeof effect.likelihoodDelta).toBe("number");
        expect(typeof effect.impactDelta).toBe("number");
        expect(effect.addsEvidenceKind).toBe("developer_answer");
        expect(["confirms_gap", "clears_gap", "no_change"]).toContain(effect.certaintyResolution);
      });
      expect(effects!.default.optionIndex).toBe(-1);
      expect(effects!.default.addsEvidenceKind).toBe("assumption");
    }

    const gapQ = result.questions.find((q) => q.unknownId === "unknown-gap-1")!;
    const modelQ = result.questions.find((q) => q.unknownId === "unknown-model-1")!;
    expect(result.effects.get(gapQ.id)!.gapId).toBe("gap-1");
    expect(result.effects.get(modelQ.id)!.gapId).toBeUndefined();

    for (const effect of result.effects.get(modelQ.id)!.options) {
      expect(effect.certaintyResolution).toBe("no_change");
    }
    const gapOptions = result.effects.get(gapQ.id)!.options;
    expect(gapOptions[0].certaintyResolution).toBe("confirms_gap"); // control_absent
    expect(gapOptions[1].certaintyResolution).toBe("clears_gap"); // control_present
    expect(gapOptions[2].certaintyResolution).toBe("no_change"); // partial
  });

  it("sets affectedThreatIds from dependsOnUnknownIds, sorted, and every question validates against the contract schema", async () => {
    const unknowns = [unknown("unknown-model-1"), unknown("unknown-model-2")];
    // Deliberately out of lexicographic order in both array position and id spelling, so
    // a test that only ever sees already-sorted output cannot mask a missing .sort(cmp).
    const threats = [
      threat("threat-zeta", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.1 }),
      threat("threat-alpha", {
        dependsOnUnknownIds: ["unknown-model-1", "unknown-model-2"],
        severity: "critical",
        confidence: 0.1,
      }),
      threat("threat-mu", { dependsOnUnknownIds: [], severity: "critical", confidence: 0.1 }),
    ];

    const { deps } = harness({});
    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });

    const q1 = result.questions.find((q) => q.unknownId === "unknown-model-1")!;
    const q2 = result.questions.find((q) => q.unknownId === "unknown-model-2")!;
    expect(q1.affectedThreatIds).toEqual(["threat-alpha", "threat-zeta"]);
    expect(q2.affectedThreatIds).toEqual(["threat-alpha"]);

    for (const question of result.questions) {
      expect(() => DeveloperQuestionSchema.parse(question)).not.toThrow();
    }
  });
});

// ---------------------------------------------------------------------------
// 8. Dropped or invalid drafts
// ---------------------------------------------------------------------------

describe("dropped or invalid drafts", () => {
  it("drops a draft naming an unknown that was not offered, with a limitation, and keeps the rest", async () => {
    const unknowns = [unknown("unknown-model-1")];
    const threats = [threat("threat-1", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.1 })];

    const { deps } = fixedDraftHarness(() => ({
      questions: [
        {
          text: "A question about something never offered",
          whyAsking: "why",
          options: ["a", "b"],
          allowsUnsure: true,
          unknownId: "unknown-not-offered",
          defaultAssumption: "assume",
          optionMeanings: ["control_absent", "control_present"],
        },
      ],
    }));

    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });

    expect(result.questions).toEqual([]);
    expect(result.limitations.some((l) => l.includes("unknown-not-offered"))).toBe(true);
    expect(result.limitations.some((l) => l.includes("unknown-model-1"))).toBe(true);
  });

  it("drops a draft whose optionMeanings length does not match its options length", async () => {
    const unknowns = [unknown("unknown-model-1")];
    const threats = [threat("threat-1", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.1 })];

    const { deps } = fixedDraftHarness(() => ({
      questions: [
        {
          text: "mismatched",
          whyAsking: "why",
          options: ["a", "b", "c"],
          allowsUnsure: true,
          unknownId: "unknown-model-1",
          defaultAssumption: "assume",
          optionMeanings: ["control_absent", "control_present"],
        },
      ],
    }));

    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });

    expect(result.questions).toEqual([]);
    expect(result.limitations.some((l) => l.includes("optionMeanings"))).toBe(true);
  });

  it("drops a second draft for the same unknown and keeps the first", async () => {
    const unknowns = [unknown("unknown-model-1")];
    const threats = [threat("threat-1", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.1 })];

    const { deps } = fixedDraftHarness(() => ({
      questions: [
        {
          text: "first",
          whyAsking: "why",
          options: ["a", "b"],
          allowsUnsure: true,
          unknownId: "unknown-model-1",
          defaultAssumption: "assume",
          optionMeanings: ["control_absent", "control_present"],
        },
        {
          text: "second",
          whyAsking: "why",
          options: ["c", "d"],
          allowsUnsure: true,
          unknownId: "unknown-model-1",
          defaultAssumption: "assume",
          optionMeanings: ["control_absent", "control_present"],
        },
      ],
    }));

    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });

    expect(result.questions.length).toBe(1);
    expect(result.questions[0].text).toBe("first");
    expect(result.limitations.some((l) => l.includes("second question"))).toBe(true);
  });

  it("records a limitation and skips an offered unknown for which no draft came back at all", async () => {
    const unknowns = [unknown("unknown-model-1"), unknown("unknown-model-2")];
    const threats = [
      threat("t1", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.1 }),
      threat("t2", { dependsOnUnknownIds: ["unknown-model-2"], severity: "critical", confidence: 0.1 }),
    ];

    const { deps } = fixedDraftHarness(() => ({
      questions: [
        {
          text: "only for model-1",
          whyAsking: "why",
          options: ["a", "b"],
          allowsUnsure: true,
          unknownId: "unknown-model-1",
          defaultAssumption: "assume",
          optionMeanings: ["control_absent", "control_present"],
        },
      ],
    }));

    const result = await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });

    expect(result.questions.length).toBe(1);
    expect(result.questions[0].unknownId).toBe("unknown-model-1");
    expect(result.limitations.some((l) => l.includes("unknown-model-2"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Schema shape sanity
// ---------------------------------------------------------------------------

describe("QuestionDraftSchema", () => {
  it("extends CandidateQuestionSchema with only optionMeanings", () => {
    const draft = {
      text: "t",
      whyAsking: "w",
      options: ["a", "b"],
      allowsUnsure: true,
      unknownId: "unknown-1",
      defaultAssumption: "d",
      optionMeanings: ["control_absent", "control_present"],
    };
    expect(QuestionDraftSchema.safeParse(draft).success).toBe(true);
    const { optionMeanings: _drop, ...rest } = draft;
    void _drop;
    expect(CandidateQuestionSchema.safeParse(rest).success).toBe(true);
  });

  it("rejects a response object missing the questions key", () => {
    expect(QuestionsResponseSchema.safeParse({}).success).toBe(false);
  });

  it("rejects an optionMeanings entry outside the fixed enum", () => {
    const draft = {
      text: "t",
      whyAsking: "w",
      options: ["a", "b"],
      allowsUnsure: true,
      unknownId: "unknown-1",
      defaultAssumption: "d",
      optionMeanings: ["control_absent", "something_else"],
    };
    expect(QuestionDraftSchema.safeParse(draft).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The request on the wire
// ---------------------------------------------------------------------------

/** Every array-length keyword in a JSON Schema, as "path: keyword=value". Property names are not keywords. */
function arrayLimits(schema: unknown, path = "$"): string[] {
  if (Array.isArray(schema)) return schema.flatMap((s, i) => arrayLimits(s, `${path}[${i}]`));
  if (typeof schema !== "object" || schema === null) return [];
  return Object.entries(schema).flatMap(([key, value]) => {
    if (key === "properties" && typeof value === "object" && value !== null) {
      return Object.entries(value).flatMap(([name, sub]) => arrayLimits(sub, `${path}.${name}`));
    }
    if (key === "minItems" || key === "maxItems") return [`${path}: ${key}=${String(value)}`];
    return arrayLimits(value, `${path}.${key}`);
  });
}

describe("selectQuestions: the request on the wire", () => {
  const unknowns = [unknown("unknown-model-1")];
  const threats = [threat("threat-1", { dependsOnUnknownIds: ["unknown-model-1"], severity: "critical", confidence: 0.1 })];

  async function sentBody(): Promise<Anthropic.MessageCreateParamsNonStreaming> {
    const { deps, calls } = harness({});
    await selectQuestions({ unknowns, threats, gaps: [], analysisId: "test", deps, promptDir: "prompts" });
    expect(calls).toHaveLength(1);
    return calls[0];
  }

  it("disables extended thinking, so reasoning cannot spend the 4,000-token output budget", async () => {
    expect(QUESTIONS_THINKING).toEqual({ type: "disabled" });
    const body = await sentBody();
    expect(body.thinking).toEqual({ type: "disabled" });
    expect(body.max_tokens).toBe(QUESTIONS_MAX_TOKENS);
  });

  it("sends no maxItems and no minItems above 1, though the real schema carries both", async () => {
    // The contract's option count: 2 to 4 options and meanings, twice each.
    expect(arrayLimits(questionsJsonSchema).sort()).toEqual([
      "$.questions.items.optionMeanings: maxItems=4",
      "$.questions.items.optionMeanings: minItems=2",
      "$.questions.items.options: maxItems=4",
      "$.questions.items.options: minItems=2",
    ]);

    const body = await sentBody();
    const format = body.output_config?.format as { type: string; schema: unknown } | undefined;
    expect(format?.type).toBe("json_schema");
    expect(arrayLimits(format?.schema)).toEqual([]);
  });

  it("still enforces the option count with Zod after the reply", () => {
    const draft = {
      text: "t",
      whyAsking: "w",
      allowsUnsure: true,
      unknownId: "unknown-1",
      defaultAssumption: "d",
    };
    const withOptions = (n: number) => ({
      ...draft,
      options: Array.from({ length: n }, (_, i) => `o${i}`),
      optionMeanings: Array.from({ length: n }, () => "control_absent"),
    });
    expect(QuestionDraftSchema.safeParse(withOptions(1)).success).toBe(false);
    expect(QuestionDraftSchema.safeParse(withOptions(2)).success).toBe(true);
    expect(QuestionDraftSchema.safeParse(withOptions(4)).success).toBe(true);
    expect(QuestionDraftSchema.safeParse(withOptions(5)).success).toBe(false);
  });
});
