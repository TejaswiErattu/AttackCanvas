import { describe, expect, it } from "vitest";
import {
  toAnalysisError,
  toAnalysisStatus,
  toDashboardViewModel,
  toQuestionData,
} from "@/client/adapter";
import {
  AnalysisStageSchema,
  ErrorCodeSchema,
  validateThreatModel,
  type AnalysisLevel,
  type Evidence,
  type Threat,
  type ThreatModel,
} from "@/shared/schema";
import { BASIS_LABELS } from "@/shared/labels";
import { deepFreeze, findUndefined } from "./helpers";
import { exposureMap } from "@/client/exposure";

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

type ThreatSpec = {
  id: string;
  impact: number;
  likelihood: number;
  severity: Threat["severity"];
  priority: Threat["priority"];
  confidence: number;
  confidenceLabel: Threat["confidenceLabel"];
  stride: Threat["stride"];
  owasp: Threat["owasp"];
  componentIds: string[];
  dataFlowIds?: string[];
  evidenceIds?: string[];
};

function makeThreat(spec: ThreatSpec): Threat {
  return {
    id: spec.id,
    title: `Threat ${spec.id}`,
    stride: spec.stride,
    owasp: spec.owasp,
    cwe: ["CWE-89"],
    componentIds: spec.componentIds,
    dataFlowIds: spec.dataFlowIds ?? [],
    asset: "user records",
    attackScenario: `Attack scenario for ${spec.id}.`,
    evidenceIds: spec.evidenceIds ?? ["e-raw-query"],
    assumptions: [],
    dependsOnUnknownIds: [],
    impact: spec.impact,
    likelihood: spec.likelihood,
    impactReason: "Because.",
    likelihoodReason: "Because.",
    severity: spec.severity,
    confidence: spec.confidence,
    confidenceLabel: spec.confidenceLabel,
    basis: "evidence_backed",
    mitigation: { summary: `Fix ${spec.id}.`, steps: ["Do the thing."] },
    priority: spec.priority,
  };
}

const evidence: Evidence[] = [
  {
    id: "e-raw-query",
    kind: "code",
    source: "detector",
    summary: "String-concatenated SQL query.",
    filePath: "src/server/db.ts",
    lineStart: 42,
    lineEnd: 44,
    snippet: "db.query(`SELECT * FROM users WHERE id = ${id}`)",
  },
  {
    id: "e-semgrep",
    kind: "scanner",
    source: "semgrep",
    summary: "Semgrep flagged tainted SQL.",
    filePath: "src/server/db.ts",
    // Its own line: evidence sharing a file:line with e-raw-query would count once.
    lineStart: 44,
    ruleId: "javascript.sql-injection",
  },
  {
    id: "e-inferred",
    kind: "inference",
    source: "ai",
    summary: "Likely no per-user database credentials.",
  },
];

/**
 * Deliberately listed out of order. Expected sort (priority, then risk, then
 * confidence): sqli(25) secret(20) authz(16) xss(15) session(12,.9) errors(12,.6),
 * then fix_soon: rate-limit(16) cors(9), then monitor: debug(4).
 */
const threats: Threat[] = [
  makeThreat({
    id: "debug-logging", impact: 2, likelihood: 2, severity: "low", priority: "monitor",
    confidence: 0.3, confidenceLabel: "low", stride: ["R"], owasp: ["A09:2025"],
    componentIds: ["primary-database"],
  }),
  makeThreat({
    id: "verbose-errors", impact: 3, likelihood: 4, severity: "high", priority: "fix_now",
    confidence: 0.6, confidenceLabel: "medium", stride: ["I"], owasp: ["A10:2025"],
    componentIds: ["api-server"],
  }),
  makeThreat({
    id: "rate-limit-missing", impact: 4, likelihood: 4, severity: "high", priority: "fix_soon",
    confidence: 0.4, confidenceLabel: "medium", stride: ["D"], owasp: ["A06:2025"],
    componentIds: ["api-server"], dataFlowIds: ["frontend-to-api"],
  }),
  makeThreat({
    id: "sqli-users", impact: 5, likelihood: 5, severity: "critical", priority: "fix_now",
    confidence: 0.85, confidenceLabel: "high", stride: ["T", "I"], owasp: ["A05:2025"],
    componentIds: ["api-server", "primary-database"], dataFlowIds: ["api-to-database"],
    evidenceIds: ["e-raw-query", "e-semgrep", "e-inferred"],
  }),
  makeThreat({
    id: "cors-loose", impact: 3, likelihood: 3, severity: "medium", priority: "fix_soon",
    confidence: 0.6, confidenceLabel: "medium", stride: ["T"], owasp: ["A02:2025"],
    componentIds: ["web-frontend"],
  }),
  makeThreat({
    id: "weak-session", impact: 3, likelihood: 4, severity: "high", priority: "fix_now",
    confidence: 0.9, confidenceLabel: "high", stride: ["S"], owasp: ["A07:2025"],
    componentIds: ["api-server"],
  }),
  makeThreat({
    id: "hardcoded-secret", impact: 5, likelihood: 4, severity: "critical", priority: "fix_now",
    confidence: 0.7, confidenceLabel: "high", stride: ["I"], owasp: ["A02:2025"],
    componentIds: ["api-server"],
  }),
  makeThreat({
    id: "xss-profile", impact: 3, likelihood: 5, severity: "high", priority: "fix_now",
    confidence: 0.7, confidenceLabel: "high", stride: ["T"], owasp: ["A05:2025"],
    componentIds: ["web-frontend"],
  }),
  makeThreat({
    id: "missing-authz", impact: 4, likelihood: 4, severity: "high", priority: "fix_now",
    confidence: 0.8, confidenceLabel: "high", stride: ["E"], owasp: ["A01:2025"],
    componentIds: ["api-server"], dataFlowIds: ["frontend-to-api"],
  }),
];

function buildModel(): ThreatModel {
  return {
    schemaVersion: "1.0",
    analysisLevel: 2,
    repo: {
      owner: "acme",
      name: "widget-shop",
      ref: "main",
      languages: ["TypeScript"],
      frameworks: ["Next.js", "Express"],
      fileCountAnalyzed: 37,
      analyzedAt: "2026-09-19T12:00:00Z",
    },
    components: [
      {
        id: "web-frontend", name: "Web Frontend", type: "frontend",
        description: "Browser app.", technologies: ["Next.js"], files: ["src/app/page.tsx"],
        assets: ["session cookie"], position: { x: 120, y: 40 },
      },
      {
        id: "api-server", name: "API Server", type: "backend",
        description: "REST API.", technologies: ["Express"], files: ["src/server/index.ts"],
        assets: ["user records"],
      },
      {
        id: "primary-database", name: "Primary Database", type: "database",
        description: "Postgres.", technologies: ["PostgreSQL"], files: ["src/server/db.ts"],
        assets: ["user records"],
      },
      {
        id: "email-service", name: "Email Service", type: "external_service",
        description: "Transactional email.", technologies: [], files: [], assets: [],
      },
    ],
    dataFlows: [
      {
        id: "frontend-to-api", sourceId: "web-frontend", targetId: "api-server",
        label: "Submits forms", protocol: "HTTPS", dataClassification: "sensitive",
        crossesTrustBoundary: true, boundaryId: "internet-boundary",
      },
      {
        id: "api-to-database", sourceId: "api-server", targetId: "primary-database",
        label: "Reads and writes users", dataClassification: "sensitive",
        crossesTrustBoundary: false,
      },
    ],
    trustBoundaries: [
      {
        id: "internet-boundary", name: "Internet boundary",
        componentIds: ["web-frontend"], description: "Untrusted network.",
      },
    ],
    unknowns: [
      { id: "db-credentials", description: "Per-user DB credentials?", affectsComponentIds: ["primary-database"] },
    ],
    evidence,
    threats,
    questions: [
      {
        id: "database-credentials",
        text: "Does the database enforce per-user credentials?",
        whyAsking: "Determines how far injection reaches.",
        options: ["Yes", "No"],
        allowsUnsure: true,
        affectedThreatIds: ["sqli-users"],
        unknownId: "db-credentials",
        defaultAssumption: "A single shared account is used.",
        valueScore: 0.8,
      },
      {
        id: "session-storage",
        text: "Where are sessions stored?",
        whyAsking: "Affects session fixation risk.",
        options: ["Cookie", "Server", "Token"],
        allowsUnsure: false,
        affectedThreatIds: ["weak-session"],
        unknownId: "db-credentials",
        defaultAssumption: "Sessions live in a cookie.",
        valueScore: 0.5,
      },
    ],
    assumptions: ["The default branch reflects production."],
    limitations: ["Runtime configuration was not available."],
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("fixture", () => {
  it("is a valid ThreatModel", () => {
    expect(validateThreatModel(buildModel()).ok).toBe(true);
  });
});

describe("toDashboardViewModel", () => {
  const view = toDashboardViewModel(buildModel());

  it("summarises the repo", () => {
    expect(view.repo).toEqual({
      fullName: "acme/widget-shop",
      ref: "main",
      frameworks: ["Next.js", "Express"],
      fileCount: 37,
      analyzedAt: "2026-09-19T12:00:00Z",
    });
  });

  it("counts threats by severity", () => {
    expect(view.counts).toEqual({ critical: 2, high: 5, medium: 1, low: 1 });
    expect(Object.values(view.counts).reduce((a, b) => a + b, 0)).toBe(
      threats.length,
    );
  });

  it("sorts threats by priority, then risk, then confidence", () => {
    expect(view.threats.map((t) => t.id)).toEqual([
      "sqli-users",
      "hardcoded-secret",
      "missing-authz",
      "xss-profile",
      "weak-session", // risk 12, confidence 90
      "verbose-errors", // risk 12, confidence 60
      "rate-limit-missing", // risk 16 beats weak-session's 12, but fix_soon ranks below fix_now
      "cors-loose",
      "debug-logging",
    ]);
  });

  it("caps fixNow at 5, sorted by severity then confidence", () => {
    // critical: sqli (.85), secret (.7); high: session (.9), authz (.8), xss (.7).
    // verbose-errors (high, .6) is the sixth and is cut.
    expect(view.fixNow.map((t) => t.id)).toEqual([
      "sqli-users",
      "hardcoded-secret",
      "weak-session",
      "missing-authz",
      "xss-profile",
    ]);
    expect(view.fixNow.every((t) => t.priority === "fix_now")).toBe(true);
  });

  it("reports the full fix_now count in fixNowTotal, not the capped list length", () => {
    // 6 visible fix_now threats; fixNow shows 5 of them, the total still says 6.
    const fixNowIds = view.threats.filter((t) => t.priority === "fix_now").map((t) => t.id);
    expect(fixNowIds).toHaveLength(6);
    expect(view.fixNow).toHaveLength(5);
    expect(view.fixNowTotal).toBe(6);
  });

  it("excludes fix_soon threats from fixNow even when fix_now count is well under the cap", () => {
    // Unlike the fixture above (6 fix_now candidates already saturate the 5-slot cap),
    // this model has only one fix_now threat, so a fix_soon threat leaking into fixNow
    // would show up directly rather than being sliced away regardless.
    const model = buildModel();
    model.threats = [
      makeThreat({
        id: "solo-fix-now", impact: 5, likelihood: 5, severity: "critical", priority: "fix_now",
        confidence: 0.9, confidenceLabel: "high", stride: ["T"], owasp: ["A01:2025"],
        componentIds: ["api-server"],
      }),
      makeThreat({
        id: "solo-fix-soon", impact: 5, likelihood: 5, severity: "critical", priority: "fix_soon",
        confidence: 0.9, confidenceLabel: "high", stride: ["T"], owasp: ["A01:2025"],
        componentIds: ["api-server"],
      }),
    ];
    model.questions = [];

    const view = toDashboardViewModel(model);
    expect(view.fixNow.map((t) => t.id)).toEqual(["solo-fix-now"]);
  });

  it("keeps component ids and data-flow ids in separate fields", () => {
    const sqli = view.threats.find((t) => t.id === "sqli-users");
    expect(sqli?.componentIds).toEqual(["api-server", "primary-database"]);
    expect(sqli?.dataFlowIds).toEqual(["api-to-database"]);
    expect(sqli?.componentNames).toEqual(["API Server", "Primary Database"]);
  });

  it("converts confidence to a 0-100 integer", () => {
    const sqli = view.threats.find((t) => t.id === "sqli-users");
    expect(sqli?.confidence).toBe(85);
    expect(view.threats.every((t) => Number.isInteger(t.confidence))).toBe(true);
  });

  it("attaches human labels", () => {
    const sqli = view.threats.find((t) => t.id === "sqli-users");
    expect(sqli?.priorityLabel).toBe("Fix now");
    expect(sqli?.basisLabel).toBe("Confirmed by evidence");
    expect(sqli?.stride).toEqual([
      { code: "T", label: "Tampering" },
      { code: "I", label: "Information disclosure" },
    ]);
    expect(sqli?.owasp).toEqual([{ code: "A05:2025", label: "Injection" }]);
  });

  it("resolves evidence with locations, snippets and source labels", () => {
    const sqli = view.threats.find((t) => t.id === "sqli-users");
    expect(sqli?.evidence).toEqual([
      {
        kind: "code",
        kindLabel: "Code",
        summary: "String-concatenated SQL query.",
        location: "src/server/db.ts:42-44",
        snippet: "db.query(`SELECT * FROM users WHERE id = ${id}`)",
        sourceLabel: "Code analysis",
      },
      {
        kind: "scanner",
        kindLabel: "Scanner finding",
        summary: "Semgrep flagged tainted SQL.",
        location: "src/server/db.ts:44",
        snippet: null,
        sourceLabel: "Semgrep",
      },
      {
        kind: "inference",
        kindLabel: "Inference",
        summary: "Likely no per-user database credentials.",
        location: null,
        snippet: null,
        sourceLabel: "AI analysis",
      },
    ]);
  });

  it("defaults a missing mitigation codeLocation to null", () => {
    expect(view.threats[0].mitigation.codeLocation).toBeNull();
  });

  it("builds nodes with threat counts and max severity", () => {
    const byId = Object.fromEntries(view.nodes.map((n) => [n.id, n]));
    expect(byId["api-server"]).toMatchObject({
      label: "API Server",
      type: "backend",
      threatCount: 6,
      maxSeverity: "critical",
      technologies: ["Express"],
    });
    expect(byId["primary-database"]).toMatchObject({ threatCount: 2, maxSeverity: "critical" });
    expect(byId["web-frontend"]).toMatchObject({ threatCount: 2, maxSeverity: "high" });
    expect(byId["email-service"]).toMatchObject({ threatCount: 0, maxSeverity: null });
  });

  it("keeps a supplied position and defaults a missing one to {0,0}", () => {
    const byId = Object.fromEntries(view.nodes.map((n) => [n.id, n]));
    expect(byId["web-frontend"].position).toEqual({ x: 120, y: 40 });
    expect(byId["api-server"].position).toEqual({ x: 0, y: 0 });
  });

  it("builds edges", () => {
    expect(view.edges).toEqual([
      {
        id: "frontend-to-api",
        source: "web-frontend",
        target: "api-server",
        label: "Submits forms",
        crossesTrustBoundary: true,
        dataClassification: "sensitive",
      },
      {
        id: "api-to-database",
        source: "api-server",
        target: "primary-database",
        label: "Reads and writes users",
        crossesTrustBoundary: false,
        dataClassification: "sensitive",
      },
    ]);
  });

  it("lists only filter options that match a threat, in canonical order", () => {
    const { filterOptions } = view;
    expect(filterOptions.severities).toEqual(["critical", "high", "medium", "low"]);
    expect(filterOptions.stride.map((s) => s.code)).toEqual(["S", "T", "R", "I", "D", "E"]);
    expect(filterOptions.owasp.map((o) => o.code)).toEqual([
      "A01:2025",
      "A02:2025",
      "A05:2025",
      "A06:2025",
      "A07:2025",
      "A09:2025",
      "A10:2025",
    ]);
    expect(filterOptions.owasp[0]).toEqual({
      code: "A01:2025",
      label: "Broken Access Control",
    });
    expect(filterOptions.confidenceLabels).toEqual(["high", "medium", "low"]);
    // email-service has no threats, so it would filter to nothing.
    expect(filterOptions.components).toEqual([
      { id: "web-frontend", name: "Web Frontend" },
      { id: "api-server", name: "API Server" },
      { id: "primary-database", name: "Primary Database" },
    ]);
  });

  it("passes assumptions and limitations through", () => {
    expect(view.assumptions).toEqual(["The default branch reflects production."]);
    expect(view.limitations).toEqual(["Runtime configuration was not available."]);
  });

  it("leaves no field undefined", () => {
    expect(findUndefined(view)).toEqual([]);
  });

  it("does not mutate the model or reorder its threats", () => {
    const model = buildModel();
    const before = structuredClone(model);
    toDashboardViewModel(model);
    expect(model).toEqual(before);
    expect(model.threats.map((t) => t.id)).toEqual(before.threats.map((t) => t.id));
  });

  it("handles a model with no threats", () => {
    const model = buildModel();
    model.threats = [];
    model.questions = [];
    const empty = toDashboardViewModel(model);

    expect(empty.counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
    expect(empty.fixNow).toEqual([]);
    expect(empty.filterOptions.components).toEqual([]);
    expect(findUndefined(empty)).toEqual([]);
  });
});

describe("evidence ordering and basis labels", () => {
  const gapEvidence: Evidence = {
    id: "e-gap-authz",
    kind: "code",
    source: "detector",
    ruleId: "gap:authz_missing",
    summary: "No ownership check near the id lookup.",
  };

  /** Gap evidence listed FIRST in evidenceIds, to prove the adapter reorders it rather than echoing input order. */
  function modelWithGapEvidence(basis: Threat["basis"]): ThreatModel {
    const model = buildModel();
    model.evidence = [...evidence, gapEvidence];
    const threat = makeThreat({
      id: "gap-ordered",
      impact: 3, likelihood: 3, severity: "medium", priority: "monitor",
      confidence: 0.5, confidenceLabel: "medium", stride: ["E"], owasp: ["A01:2025"],
      componentIds: ["api-server"],
      evidenceIds: ["e-gap-authz", "e-raw-query"],
    });
    model.threats = [{ ...threat, basis }];
    model.questions = [];
    return model;
  }

  it("renders the evidence_backed basis label", () => {
    const view = toDashboardViewModel(modelWithGapEvidence("evidence_backed"));
    expect(view.threats[0].basisLabel).toBe("Confirmed by evidence");
  });

  it("renders the assumption_dependent basis label", () => {
    const view = toDashboardViewModel(modelWithGapEvidence("assumption_dependent"));
    expect(view.threats[0].basisLabel).toBe("Predicted from a missing control");
  });

  it("sorts gap evidence last on the card, positive findings first", () => {
    const view = toDashboardViewModel(modelWithGapEvidence("evidence_backed"));
    expect(view.threats[0].evidence.map((e) => e.summary)).toEqual([
      "String-concatenated SQL query.",
      "No ownership check near the id lookup.",
    ]);
  });

  it("keeps relative order stable within each group when there are several of each", () => {
    const model = buildModel();
    const secondGap: Evidence = {
      id: "e-gap-csrf",
      kind: "config",
      source: "detector",
      ruleId: "gap:csrf_missing",
      summary: "No CSRF token check on state-changing routes.",
    };
    model.evidence = [...evidence, gapEvidence, secondGap];
    const threat = makeThreat({
      id: "gap-ordered-multi",
      impact: 3, likelihood: 3, severity: "medium", priority: "monitor",
      confidence: 0.5, confidenceLabel: "medium", stride: ["E"], owasp: ["A01:2025"],
      componentIds: ["api-server"],
      // Interleaved: gap, positive, gap, positive -- expect both positives first (in
      // this order), then both gaps (in this order).
      evidenceIds: ["e-gap-authz", "e-raw-query", "e-gap-csrf", "e-semgrep"],
    });
    model.threats = [threat];
    model.questions = [];

    const view = toDashboardViewModel(model);
    expect(view.threats[0].evidence.map((e) => e.summary)).toEqual([
      "String-concatenated SQL query.",
      "Semgrep flagged tainted SQL.",
      "No ownership check near the id lookup.",
      "No CSRF token check on state-changing routes.",
    ]);
  });

  it("preserves original relative order among positive-only evidence (no gaps involved)", () => {
    const model = buildModel();
    const threat = makeThreat({
      id: "positive-only-order",
      impact: 3, likelihood: 3, severity: "medium", priority: "monitor",
      confidence: 0.5, confidenceLabel: "medium", stride: ["E"], owasp: ["A01:2025"],
      componentIds: ["api-server"],
      // Deliberately not the array's declaration order: semgrep, then inference, then code.
      evidenceIds: ["e-semgrep", "e-inferred", "e-raw-query"],
    });
    model.threats = [threat];
    model.questions = [];

    const view = toDashboardViewModel(model);
    expect(view.threats[0].evidence.map((e) => e.summary)).toEqual([
      "Semgrep flagged tainted SQL.",
      "Likely no per-user database credentials.",
      "String-concatenated SQL query.",
    ]);
  });

  it("treats evidence as a gap only via an exact 'gap:' ruleId prefix, never via summary text or a near-miss ruleId", () => {
    const looksLikeGapInSummaryOnly: Evidence = {
      id: "e-fake-gap-text",
      kind: "code",
      source: "detector",
      summary: "There may be a gap in validation here, but this is a code finding, not a control gap.",
    };
    const nearMissRuleId: Evidence = {
      id: "e-near-miss-ruleid",
      kind: "code",
      source: "detector",
      // Starts with "gap" but is not the "gap:" prefix isGapEvidence checks for.
      ruleId: "gapminder-heuristic",
      summary: "Unrelated rule id that happens to start with the letters gap.",
    };
    const realGap: Evidence = {
      id: "e-real-gap",
      kind: "code",
      source: "detector",
      ruleId: "gap:authz_missing",
      summary: "No ownership check near the id lookup.",
    };
    const model = buildModel();
    model.evidence = [...evidence, looksLikeGapInSummaryOnly, nearMissRuleId, realGap];
    const threat = makeThreat({
      id: "gap-detection-precision",
      impact: 3, likelihood: 3, severity: "medium", priority: "monitor",
      confidence: 0.5, confidenceLabel: "medium", stride: ["E"], owasp: ["A01:2025"],
      componentIds: ["api-server"],
      evidenceIds: ["e-real-gap", "e-fake-gap-text", "e-near-miss-ruleid"],
    });
    model.threats = [threat];
    model.questions = [];

    const view = toDashboardViewModel(model);
    // Only the real "gap:"-prefixed item moves to the end; the other two, despite the
    // word "gap" appearing in their text or ruleId, are treated as ordinary positive
    // findings and keep their relative (non-gap) position.
    expect(view.threats[0].evidence.map((e) => e.summary)).toEqual([
      "There may be a gap in validation here, but this is a code finding, not a control gap.",
      "Unrelated rule id that happens to start with the letters gap.",
      "No ownership check near the id lookup.",
    ]);
  });

  it("silently omits an evidenceId that does not resolve to any evidence item", () => {
    const model = buildModel();
    const threat = makeThreat({
      id: "missing-evidence-ref",
      impact: 3, likelihood: 3, severity: "medium", priority: "monitor",
      confidence: 0.5, confidenceLabel: "medium", stride: ["E"], owasp: ["A01:2025"],
      componentIds: ["api-server"],
      evidenceIds: ["e-raw-query", "e-does-not-exist"],
    });
    model.threats = [threat];
    model.questions = [];

    const view = toDashboardViewModel(model);
    expect(view.threats[0].evidence).toHaveLength(1);
    expect(view.threats[0].evidence[0].summary).toBe("String-concatenated SQL query.");
  });

  it("maps only evidence_backed and assumption_dependent, to distinct, non-overlapping labels", () => {
    expect(Object.keys(BASIS_LABELS).sort()).toEqual([
      "assumption_dependent",
      "evidence_backed",
    ]);
    expect(BASIS_LABELS.evidence_backed).toBe("Confirmed by evidence");
    expect(BASIS_LABELS.assumption_dependent).toBe("Predicted from a missing control");
    expect(BASIS_LABELS.evidence_backed).not.toBe(BASIS_LABELS.assumption_dependent);
  });

  it("does not mutate a frozen input model or a threat's evidenceIds", () => {
    const model = buildModel();
    const gapOrderedModel: ThreatModel = {
      ...model,
      evidence: [...evidence, gapEvidence],
      threats: [
        makeThreat({
          id: "frozen-gap-ordered",
          impact: 3, likelihood: 3, severity: "medium", priority: "monitor",
          confidence: 0.5, confidenceLabel: "medium", stride: ["E"], owasp: ["A01:2025"],
          componentIds: ["api-server"],
          evidenceIds: ["e-gap-authz", "e-raw-query", "e-semgrep"],
        }),
      ],
      questions: [],
    };
    const frozen = deepFreeze(gapOrderedModel);

    expect(() => toDashboardViewModel(frozen)).not.toThrow();

    const view = toDashboardViewModel(gapOrderedModel);
    expect(view.threats[0].evidence.map((e) => e.summary)).toEqual([
      "String-concatenated SQL query.",
      "Semgrep flagged tainted SQL.",
      "No ownership check near the id lookup.",
    ]);
  });
});

describe("analysis level", () => {
  const levels: [AnalysisLevel, string][] = [
    [0, "Snapshot"],
    [1, "Basic"],
    [2, "Standard"],
    [3, "Deep"],
    [4, "Exhaustive"],
  ];

  it.each(levels)("copies level %i and labels it %s", (level, label) => {
    const model = buildModel();
    model.analysisLevel = level;
    const view = toDashboardViewModel(model);

    expect(view.analysisLevel).toBe(level);
    expect(view.analysisLevelLabel).toBe(label);
    expect(findUndefined(view)).toEqual([]);
  });

  it("does not change the level on the input model", () => {
    const model = buildModel();
    model.analysisLevel = 4;
    toDashboardViewModel(model);
    expect(model.analysisLevel).toBe(4);
  });
});

describe("hiding low-confidence threats (CLAUDE.md rule 2)", () => {
  /**
   * One visible threat and one hidden threat that would change every output if it
   * leaked: it would add a `low` count, rank first in fixNow (risk 25), give
   * email-service a threat, and add D / A03 / low to the filter options.
   */
  const visibleThreat = makeThreat({
    id: "visible-one", impact: 4, likelihood: 4, severity: "high", priority: "fix_now",
    confidence: 0.9, confidenceLabel: "high", stride: ["T"], owasp: ["A01:2025"],
    componentIds: ["api-server"],
  });

  function hiddenThreat(confidence: number): Threat {
    return makeThreat({
      id: "hidden-one", impact: 5, likelihood: 5, severity: "low", priority: "fix_now",
      confidence, confidenceLabel: "low", stride: ["D"], owasp: ["A03:2025"],
      componentIds: ["email-service"],
    });
  }

  function modelWith(...extra: Threat[]): ThreatModel {
    const model = buildModel();
    model.threats = [visibleThreat, ...extra];
    model.questions = [];
    return model;
  }

  it("builds a valid model for these tests", () => {
    expect(validateThreatModel(modelWith(hiddenThreat(0.1))).ok).toBe(true);
  });

  it.each([
    [0, false],
    [0.1, false],
    [0.249, false],
    [0.24999, false],
    [0.25, true],
    [0.250001, true],
    [1, true],
  ])("confidence %f visible=%s", (confidence, visible) => {
    const view = toDashboardViewModel(modelWith(hiddenThreat(confidence)));
    const ids = view.threats.map((t) => t.id);

    expect(ids.includes("hidden-one")).toBe(visible);
    expect(ids.includes("visible-one")).toBe(true);
  });

  describe("with a hidden threat present", () => {
    const withHidden = toDashboardViewModel(modelWith(hiddenThreat(0.249)));
    const withoutHidden = toDashboardViewModel(modelWith());

    it("gives the same view as if the threat did not exist, apart from the hidden list", () => {
      const { hiddenThreats, hiddenCounts, ...rest } = withHidden;
      const { hiddenThreats: none, hiddenCounts: zero, ...restWithout } = withoutHidden;
      // Filter options also cover it (the list shows it); see "adds filter options for it".
      expect({ ...rest, filterOptions: null }).toEqual({ ...restWithout, filterOptions: null });
      expect(hiddenThreats.map((t) => t.id)).toEqual(["hidden-one"]);
      expect(hiddenCounts).toEqual({ critical: 0, high: 0, medium: 0, low: 1 });
      expect(none).toEqual([]);
      expect(zero).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
    });

    it("keeps it as a full card flagged belowCutoff, without touching visible cards", () => {
      const [hidden] = withHidden.hiddenThreats;
      expect(hidden.belowCutoff).toBe(true);
      expect(hidden).toMatchObject({
        id: "hidden-one", severity: "low", confidence: 25, priority: "fix_now",
        componentNames: ["Email Service"],
      });
      expect(hidden.confidenceReasons.length).toBeGreaterThan(0);
      expect("belowCutoff" in withHidden.threats[0]).toBe(false);
    });

    it("excludes it from counts", () => {
      expect(withHidden.counts).toEqual({ critical: 0, high: 1, medium: 0, low: 0 });
    });

    it("excludes it from fixNow and fixNowTotal, even at risk 25", () => {
      expect(withHidden.fixNow.map((t) => t.id)).toEqual(["visible-one"]);
      expect(withHidden.fixNowTotal).toBe(1);
      expect(withHidden.threats.map((t) => t.id)).toEqual(["visible-one"]);
    });

    it("excludes it from node threatCount and maxSeverity", () => {
      const email = withHidden.nodes.find((n) => n.id === "email-service");
      expect(email).toMatchObject({ threatCount: 0, maxSeverity: null });
    });

    it("adds filter options for it, since the list shows it", () => {
      expect(withHidden.filterOptions).toEqual({
        severities: ["high", "low"],
        stride: [
          { code: "T", label: "Tampering" },
          { code: "D", label: "Denial of service" },
        ],
        owasp: [
          { code: "A01:2025", label: "Broken Access Control" },
          { code: "A03:2025", label: "Software Supply Chain Failures" },
        ],
        components: [
          { id: "api-server", name: "API Server" },
          { id: "email-service", name: "Email Service" },
        ],
        confidenceLabels: ["high", "low"],
      });
    });
  });

  it("counts a threat exactly at the boundary", () => {
    const view = toDashboardViewModel(modelWith(hiddenThreat(0.25)));
    expect(view.hiddenThreats).toEqual([]);

    expect(view.counts).toEqual({ critical: 0, high: 1, medium: 0, low: 1 });
    expect(view.fixNow.map((t) => t.id)).toEqual(["visible-one", "hidden-one"]); // high before low, whatever the risk
    expect(view.fixNowTotal).toBe(2);
    expect(view.nodes.find((n) => n.id === "email-service")).toMatchObject({
      threatCount: 1,
      maxSeverity: "low",
    });
    expect(view.filterOptions.severities).toEqual(["high", "low"]);
    expect(view.filterOptions.stride.map((s) => s.code)).toEqual(["T", "D"]);
    expect(view.filterOptions.owasp.map((o) => o.code)).toEqual(["A01:2025", "A03:2025"]);
    expect(view.filterOptions.components.map((c) => c.id)).toEqual([
      "api-server",
      "email-service",
    ]);
    expect(view.filterOptions.confidenceLabels).toEqual(["high", "low"]);
  });

  it("leaves the input ThreatModel unchanged, hidden threats included", () => {
    const model = modelWith(hiddenThreat(0.249));
    const before = structuredClone(model);

    toDashboardViewModel(model);

    expect(model).toEqual(before);
    expect(model.threats.map((t) => t.id)).toEqual(["visible-one", "hidden-one"]);
  });

  it("returns an empty dashboard when every threat is hidden", () => {
    const model = buildModel();
    model.threats = [hiddenThreat(0.1)];
    model.questions = [];
    const view = toDashboardViewModel(model);

    expect(view.threats).toEqual([]);
    expect(view.fixNow).toEqual([]);
    expect(view.fixNowTotal).toBe(0);
    expect(view.counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
    expect(view.hiddenThreats.map((t) => t.id)).toEqual(["hidden-one"]);
    expect(view.filterOptions.components).toEqual([{ id: "email-service", name: "Email Service" }]);
    expect(findUndefined(view)).toEqual([]);
  });
});

describe("fixNow ordering", () => {
  const fixNow = (id: string, severity: Threat["severity"], confidence: number) =>
    makeThreat({
      id, impact: severity === "critical" ? 5 : 4, likelihood: severity === "critical" ? 5 : 4,
      severity, priority: "fix_now", confidence,
      confidenceLabel: confidence >= 0.7 ? "high" : "medium",
      stride: ["T"], owasp: ["A01:2025"], componentIds: ["api-server"],
    });

  function viewOf(...ts: Threat[]) {
    const model = buildModel();
    model.threats = ts;
    model.questions = [];
    return toDashboardViewModel(model);
  }

  it("ranks severity first, then confidence, then id", () => {
    const view = viewOf(
      fixNow("d-high-low", "high", 0.5),
      fixNow("c-high-top", "high", 1),
      fixNow("a-crit-low", "critical", 0.3),
      fixNow("b-crit-top", "critical", 0.9),
      fixNow("f-tie", "high", 0.5),
    );
    expect(view.fixNow.map((t) => t.id)).toEqual([
      "b-crit-top",
      "a-crit-low", // a lower-confidence critical still outranks any high
      "c-high-top",
      "d-high-low", // ties on severity and confidence fall back to id
      "f-tie",
    ]);
  });

  it("does not depend on the input order", () => {
    const list = [
      fixNow("x", "high", 0.6), fixNow("y", "critical", 0.4), fixNow("z", "high", 0.9),
    ];
    const forward = viewOf(...list).fixNow.map((t) => t.id);
    const backward = viewOf(...[...list].reverse()).fixNow.map((t) => t.id);
    expect(forward).toEqual(["y", "z", "x"]);
    expect(backward).toEqual(forward);
  });
});

describe("confidenceReasons", () => {
  const gapEvidence: Evidence = {
    id: "e-gap", kind: "code", source: "detector", ruleId: "gap:authz_missing",
    summary: "No ownership check near the id lookup.",
  };

  function reasonsFor(over: Partial<Threat>): string[] {
    const model = buildModel();
    model.evidence = [...model.evidence, gapEvidence];
    model.threats = [
      {
        ...makeThreat({
          id: "t", impact: 4, likelihood: 4, severity: "high", priority: "fix_now",
          confidence: 0.7, confidenceLabel: "high", stride: ["T"], owasp: ["A01:2025"],
          componentIds: ["api-server"],
        }),
        ...over,
      },
    ];
    model.questions = [];
    return toDashboardViewModel(model).threats[0].confidenceReasons;
  }

  it("lists one line per contribution and ends with the total", () => {
    expect(reasonsFor({ evidenceIds: ["e-raw-query"], confidence: 0.35, confidenceLabel: "low" })).toEqual([
      "+0.35 code evidence",
      "Confidence 35% (low)",
    ]);
  });

  it("adds the second-source line when two kinds of evidence agree", () => {
    expect(reasonsFor({ evidenceIds: ["e-raw-query", "e-semgrep"], confidence: 0.7 })).toEqual([
      "+0.35 code evidence",
      "+0.25 Semgrep finding",
      "+0.10 second independent source (2 kinds)",
      "Confidence 70% (high)",
    ]);
  });

  it("is qualitative, with no point values, when a missing control backs the threat", () => {
    const lines = reasonsFor({ evidenceIds: ["e-gap"], confidence: 0.4, confidenceLabel: "medium" });
    expect(lines[0]).toContain("a security control the code checks could not find");
    expect(lines.join("\n")).not.toMatch(/[+-]\d\.\d\d/);
    expect(lines.at(-1)).toBe(
      "Confidence 40% (medium). These are reasons, not scores that add up to it.",
    );
  });

  it("explains a missing-control finding in plain words and keeps every uncertainty", () => {
    const lines = reasonsFor({ evidenceIds: ["e-gap"], confidence: 0.4, confidenceLabel: "medium", assumptions: ["The victim has an active session."] });
    const text = lines.join("\n");
    // Plain wording: no talk of how much the analysis "counts", no "surer".
    expect(text).not.toMatch(/counts for more|surer|missing-control finding|figure/);
    // The uncertainty is still there, in three places.
    expect(lines[0]).toContain("prediction, not a confirmed flaw");
    expect(lines).toContain("Lowered by an unconfirmed assumption: The victim has an active session.");
    expect(lines.at(-1)).toContain("reasons, not scores that add up");
  });

  it("stays qualitative when gap evidence sits beside other evidence", () => {
    const lines = reasonsFor({ evidenceIds: ["e-raw-query", "e-gap"], confidence: 0.6 });
    expect(lines.join("\n")).not.toMatch(/[+-]\d\.\d\d/);
    expect(lines).toContain("Backed by code or configuration evidence");
  });

  it("falls back to qualitative when the stored confidence is not what the evidence gives", () => {
    const lines = reasonsFor({ evidenceIds: ["e-raw-query"], confidence: 0.9, confidenceLabel: "high" });
    expect(lines.join("\n")).not.toMatch(/[+-]\d\.\d\d/);
    expect(lines.at(-1)).toContain("not scores that add up");
  });

  it("does not count an inference beside other evidence", () => {
    const lines = reasonsFor({ evidenceIds: ["e-raw-query", "e-inferred"], confidence: 0.35, confidenceLabel: "low" });
    expect(lines).toEqual(["+0.35 code evidence", "Confidence 35% (low)"]);
  });

  it("lists each unconfirmed assumption as a deduction", () => {
    const lines = reasonsFor({
      evidenceIds: ["e-raw-query", "e-semgrep"],
      assumptions: ["The panel is public.", "No WAF is in front."],
      confidence: 0.4,
      confidenceLabel: "medium",
    });
    expect(lines).toContain("-0.15 unconfirmed assumption: The panel is public.");
    expect(lines).toContain("-0.15 unconfirmed assumption: No WAF is in front.");
  });

  it("ignores evidence ids the model cannot resolve", () => {
    const lines = reasonsFor({ evidenceIds: ["e-raw-query", "missing"], confidence: 0.35, confidenceLabel: "low" });
    expect(lines[0]).toBe("+0.35 code evidence");
  });
});

describe("toQuestionData", () => {
  const questions = toQuestionData(buildModel().questions);

  it("numbers questions from 1 with a total", () => {
    expect(questions.map((q) => [q.index, q.total])).toEqual([
      [1, 2],
      [2, 2],
    ]);
  });

  it("carries the display fields and drops internal ones", () => {
    expect(questions[0]).toEqual({
      id: "database-credentials",
      text: "Does the database enforce per-user credentials?",
      whyAsking: "Determines how far injection reaches.",
      options: ["Yes", "No"],
      allowsUnsure: true,
      defaultAssumption: "A single shared account is used.",
      index: 1,
      total: 2,
    });
  });

  it("returns an empty list for no questions", () => {
    expect(toQuestionData([])).toEqual([]);
  });

  it("leaves no field undefined", () => {
    expect(findUndefined(questions)).toEqual([]);
  });
});

describe("toAnalysisStatus", () => {
  it("numbers steps from 1 out of 8", () => {
    expect(toAnalysisStatus("queued")).toEqual({
      stage: "queued",
      stageLabel: "Queued",
      stageIndex: 1,
      stageCount: 8,
    });
    expect(toAnalysisStatus("complete")).toMatchObject({ stageIndex: 8, stageCount: 8 });
  });

  it("labels scanning for the gap detection that now runs inside it (Prompt V)", () => {
    expect(toAnalysisStatus("scanning").stageLabel).toBe(
      "Scanning code, dependencies and missing controls",
    );
  });

  it("gives failed no step", () => {
    expect(toAnalysisStatus("failed")).toEqual({
      stage: "failed",
      stageLabel: "Failed",
      stageIndex: 0,
      stageCount: 8,
    });
  });

  it("covers every stage with a label and no undefined field", () => {
    for (const stage of AnalysisStageSchema.options) {
      const status = toAnalysisStatus(stage);
      expect(status.stageLabel.length).toBeGreaterThan(0);
      expect(findUndefined(status)).toEqual([]);
    }
  });
});

describe("toAnalysisError", () => {
  it("uses default copy", () => {
    expect(toAnalysisError("REPO_NOT_FOUND")).toMatchObject({
      code: "REPO_NOT_FOUND",
      title: "Repository not found",
      canRetry: false,
    });
  });

  it("marks transient failures retryable and permanent ones not", () => {
    const retryable = ErrorCodeSchema.options.filter((c) => toAnalysisError(c).canRetry);
    expect(retryable).toEqual([
      "RATE_LIMITED",
      "AI_FAILURE",
      "TIMEOUT",
      "SERVER_BUSY",
      "UPSTREAM_RATE_LIMITED",
      "GITHUB_UNAVAILABLE",
      "MODEL_OUTPUT_INVALID",
      "NETWORK_ERROR",
    ]);
  });

  it("gives every code its own title and message, so a code alone says what went wrong", () => {
    const errors = ErrorCodeSchema.options.map((code) => toAnalysisError(code));
    expect(new Set(errors.map((e) => e.title)).size).toBe(errors.length);
    expect(new Set(errors.map((e) => e.message)).size).toBe(errors.length);
    for (const error of errors) {
      expect(error.title.trim(), error.code).not.toBe("");
      expect(error.message.trim(), error.code).not.toBe("");
    }
  });

  it("no longer blames an upstream rate limit for our own limits", () => {
    expect(toAnalysisError("RATE_LIMITED").message).not.toMatch(/being rate limited/i);
    expect(toAnalysisError("SERVER_BUSY").message).not.toMatch(/rate/i);
    expect(toAnalysisError("UPSTREAM_RATE_LIMITED").message).toMatch(/GitHub or the Claude API/);
  });

  it("uses a supplied message, but falls back when it is blank", () => {
    expect(toAnalysisError("TIMEOUT", "Took 60s.").message).toBe("Took 60s.");
    expect(toAnalysisError("TIMEOUT", "   ").message).toBe(
      toAnalysisError("TIMEOUT").message,
    );
  });

  it("covers every code with no undefined field", () => {
    for (const code of ErrorCodeSchema.options) {
      expect(findUndefined(toAnalysisError(code))).toEqual([]);
    }
  });
});

describe("toDashboardViewModel: trust boundaries", () => {
  it("carries every boundary with its name and component ids, in the model's order", () => {
    const model = buildModel();
    const view = toDashboardViewModel(model);
    expect(view.boundaries).toEqual(
      model.trustBoundaries.map((b) => ({ id: b.id, name: b.name, componentIds: b.componentIds })),
    );
  });
});

describe("toDashboardViewModel: node assets and exposure", () => {
  it("copies assets and rates exposure from the full flow list", () => {
    const model = buildModel();
    const view = toDashboardViewModel(model);
    const expected = exposureMap(
      model.components,
      model.dataFlows.map((f) => ({ source: f.sourceId, target: f.targetId })),
    );
    for (const component of model.components) {
      const node = view.nodes.find((n) => n.id === component.id)!;
      expect(node.assets).toEqual(component.assets);
      expect(node.exposure).toBe(expected.get(component.id));
    }
  });
});

describe("toDashboardViewModel: a finding names what it affects", () => {
  it("names a threat's data flows as Source → Target when it names no component", () => {
    const model = buildModel();
    const flow = model.dataFlows[0];
    const flowOnly = { ...model.threats[0], id: "threat-flow-only", componentIds: [], dataFlowIds: [flow.id] };
    const view = toDashboardViewModel({ ...model, threats: [...model.threats, flowOnly] });
    const card = view.threats.find((t) => t.id === "threat-flow-only");
    const name = (id: string) => model.components.find((c) => c.id === id)!.name;
    expect(card?.componentNames).toEqual([]);
    expect(card?.affectedNames).toEqual([`${name(flow.sourceId)} → ${name(flow.targetId)}`]);
  });

  it("lists components first, then flows, each once, and never an internal id", () => {
    const view = toDashboardViewModel(buildModel());
    for (const card of view.threats) {
      expect(card.affectedNames.slice(0, card.componentNames.length)).toEqual(card.componentNames);
      expect(new Set(card.affectedNames).size).toBe(card.affectedNames.length);
      for (const id of card.dataFlowIds) expect(card.affectedNames).not.toContain(id);
    }
  });
});
