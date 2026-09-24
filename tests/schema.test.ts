import { describe, expect, it } from "vitest";
import {
  ANALYSIS_LEVEL_LABELS,
  AnalysisLevelSchema,
  AnalysisRequestSchema,
  ArchitectureDraftSchema,
  CandidateQuestionSchema,
  DraftThreatSchema,
  OWASP_LABELS,
  Owasp2025Schema,
  ThreatModelSchema,
  architectureDraftJsonSchema,
  candidateQuestionJsonSchema,
  draftThreatJsonSchema,
  validateThreatModel,
  type AnalysisLevel,
  type ThreatModel,
} from "@/shared/schema";

/**
 * The smallest model that satisfies every cross-reference rule: a frontend talking
 * to a database, one piece of evidence, one threat citing both, one question.
 * Each test clones this and breaks exactly one thing.
 */
function minimalModel(): ThreatModel {
  return {
    schemaVersion: "1.0",
    analysisLevel: 2,
    repo: {
      owner: "acme",
      name: "widget-shop",
      ref: "main",
      languages: ["TypeScript"],
      frameworks: ["Next.js"],
      fileCountAnalyzed: 12,
      analyzedAt: "2026-09-19T12:00:00Z",
    },
    components: [
      {
        id: "web-frontend",
        name: "Web Frontend",
        type: "frontend",
        description: "Next.js app the user interacts with.",
        technologies: ["Next.js"],
        files: ["src/app/page.tsx"],
        assets: ["session cookie"],
      },
      {
        id: "primary-database",
        name: "Primary Database",
        type: "database",
        description: "Postgres instance holding user records.",
        technologies: ["PostgreSQL"],
        files: ["src/server/db.ts"],
        assets: ["user records"],
      },
    ],
    dataFlows: [
      {
        id: "frontend-to-database",
        sourceId: "web-frontend",
        targetId: "primary-database",
        label: "Reads user profile",
        protocol: "TCP",
        dataClassification: "sensitive",
        crossesTrustBoundary: true,
        boundaryId: "app-boundary",
      },
    ],
    trustBoundaries: [
      {
        id: "app-boundary",
        name: "Application Boundary",
        componentIds: ["web-frontend"],
        description: "Separates the browser from server-side infrastructure.",
      },
    ],
    unknowns: [
      {
        id: "auth-mechanism",
        description: "Whether database access requires per-user credentials.",
        affectsComponentIds: ["primary-database"],
      },
    ],
    evidence: [
      {
        id: "raw-query-call",
        kind: "code",
        source: "detector",
        summary: "String-concatenated SQL query.",
        filePath: "src/server/db.ts",
        lineStart: 42,
        lineEnd: 44,
      },
    ],
    threats: [
      {
        id: "sql-injection-profile",
        title: "SQL injection in profile lookup",
        stride: ["T", "I"],
        owasp: ["A05:2025"],
        cwe: ["CWE-89"],
        componentIds: ["primary-database"],
        dataFlowIds: ["frontend-to-database"],
        asset: "user records",
        attackScenario: "An attacker supplies a crafted id to read arbitrary rows.",
        evidenceIds: ["raw-query-call"],
        assumptions: [],
        dependsOnUnknownIds: ["auth-mechanism"],
        impact: 5,
        likelihood: 4,
        impactReason: "Full read access to user records.",
        likelihoodReason: "The endpoint is unauthenticated and reachable.",
        severity: "critical",
        confidence: 0.85,
        confidenceLabel: "high",
        basis: "evidence_backed",
        mitigation: {
          summary: "Use parameterised queries.",
          steps: ["Replace concatenation with bound parameters."],
          codeLocation: "src/server/db.ts",
        },
        priority: "fix_now",
      },
    ],
    questions: [
      {
        id: "database-credentials",
        text: "Does the database enforce per-user credentials?",
        whyAsking: "Determines whether injection yields full table access.",
        options: ["Yes, per-user", "No, one shared account"],
        allowsUnsure: true,
        affectedThreatIds: ["sql-injection-profile"],
        unknownId: "auth-mechanism",
        defaultAssumption: "A single shared account is used.",
        valueScore: 0.8,
      },
    ],
    assumptions: ["The default branch reflects production."],
    limitations: ["Runtime configuration was not available."],
  };
}

/** Structured clone keeps each test's mutation isolated from the factory output. */
function brokenModel(mutate: (model: ThreatModel) => void): unknown {
  const model = structuredClone(minimalModel());
  mutate(model);
  return model;
}

describe("validateThreatModel", () => {
  it("accepts a minimal well-formed model", () => {
    const result = validateThreatModel(minimalModel());
    expect(result.ok).toBe(true);
  });

  it("rejects a data flow pointing at a missing component", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        model.dataFlows[0].targetId = "ghost-service";
      }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues).toContainEqual({
      path: "dataFlows.0.targetId",
      message: 'targetId "ghost-service" does not match any component id',
    });
  });

  it("rejects a threat referencing a missing component", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        model.threats[0].componentIds = ["ghost-service"];
      }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues.map((issue) => issue.path)).toContain(
      "threats.0.componentIds.0",
    );
  });

  it("rejects a threat referencing a missing data flow", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        model.threats[0].dataFlowIds = ["ghost-flow"];
      }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues.map((issue) => issue.path)).toContain(
      "threats.0.dataFlowIds.0",
    );
  });

  it("rejects a threat referencing missing evidence", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        model.threats[0].evidenceIds = ["ghost-evidence"];
      }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues.map((issue) => issue.path)).toContain(
      "threats.0.evidenceIds.0",
    );
  });

  it("rejects a threat with neither evidence nor assumptions", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        model.threats[0].evidenceIds = [];
        model.threats[0].assumptions = [];
      }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues).toContainEqual({
      path: "threats.0.evidenceIds",
      message: "threat needs at least one evidenceId or one assumption",
    });
  });

  it("accepts a threat backed by an assumption instead of evidence", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        model.threats[0].evidenceIds = [];
        model.threats[0].assumptions = ["Assumes a shared database account."];
      }),
    );

    expect(result.ok).toBe(true);
  });

  it("rejects a question referencing a missing threat", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        model.questions[0].affectedThreatIds = ["ghost-threat"];
      }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues).toContainEqual({
      path: "questions.0.affectedThreatIds.0",
      message: '"ghost-threat" does not match any threat id',
    });
  });

  it("rejects duplicate component ids", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        model.components[1].id = "web-frontend";
      }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues).toContainEqual({
      path: "components.1.id",
      message: 'duplicate id "web-frontend" in components',
    });
  });

  it("reports issues rather than throwing on non-object input", () => {
    const result = validateThreatModel(null);
    expect(result.ok).toBe(false);
  });

  it("rejects ids that are not kebab-case", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        model.components[0].id = "Web_Frontend";
      }),
    );

    expect(result.ok).toBe(false);
  });
});

describe("draft schemas", () => {
  it("strips scored fields a model tries to supply", () => {
    const [threat] = minimalModel().threats;
    const parsed = DraftThreatSchema.parse(threat);

    expect(parsed).not.toHaveProperty("severity");
    expect(parsed).not.toHaveProperty("confidence");
    expect(parsed).not.toHaveProperty("priority");
    expect(parsed).not.toHaveProperty("id");
    expect(parsed.title).toBe("SQL injection in profile lookup");
  });
});

describe("AnalysisLevel", () => {
  const validLevels: AnalysisLevel[] = [0, 1, 2, 3, 4];

  it.each(validLevels)("accepts level %i", (level) => {
    expect(AnalysisLevelSchema.safeParse(level).success).toBe(true);
  });

  // Out of range, fractional, wrong type, and the boundary values just outside 0..4.
  it.each([-1, 5, 2.5, 0.5, 10, Number.NaN, "2", null, undefined, true])(
    "rejects %p",
    (level) => {
      expect(AnalysisLevelSchema.safeParse(level).success).toBe(false);
    },
  );

  it("labels every level", () => {
    expect(ANALYSIS_LEVEL_LABELS).toEqual({
      0: "Snapshot",
      1: "Basic",
      2: "Standard",
      3: "Deep",
      4: "Exhaustive",
    });
  });

  it.each(validLevels)("carries level %i onto the ThreatModel", (level) => {
    const model = structuredClone(minimalModel());
    model.analysisLevel = level;
    const result = validateThreatModel(model);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.analysisLevel).toBe(level);
  });

  it("rejects a ThreatModel with an out-of-range level", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        (model as { analysisLevel: number }).analysisLevel = 5;
      }),
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.issues.map((issue) => issue.path)).toContain("analysisLevel");
  });

  it("rejects a ThreatModel with no level at all", () => {
    const result = validateThreatModel(
      brokenModel((model) => {
        delete (model as Partial<ThreatModel>).analysisLevel;
      }),
    );

    expect(result.ok).toBe(false);
  });
});

describe("AnalysisRequest", () => {
  it("accepts a repo url with a user-selected level", () => {
    const result = AnalysisRequestSchema.safeParse({
      repoUrl: "https://github.com/acme/widget-shop",
      analysisLevel: 3,
    });

    expect(result.success).toBe(true);
  });

  it("rejects a malformed repo url", () => {
    const result = AnalysisRequestSchema.safeParse({
      repoUrl: "not-a-url",
      analysisLevel: 3,
    });

    expect(result.success).toBe(false);
  });

  it("rejects a level outside 0..4", () => {
    const result = AnalysisRequestSchema.safeParse({
      repoUrl: "https://github.com/acme/widget-shop",
      analysisLevel: 7,
    });

    expect(result.success).toBe(false);
  });
});

describe("analysisLevel is not model-selectable", () => {
  it("is absent from every draft schema's parsed output", () => {
    const [threat] = minimalModel().threats;
    const draftThreat = DraftThreatSchema.parse({ ...threat, analysisLevel: 4 });
    expect(draftThreat).not.toHaveProperty("analysisLevel");

    const architecture = ArchitectureDraftSchema.parse({
      components: [],
      dataFlows: [],
      trustBoundaries: [],
      unknowns: [],
      analysisLevel: 4,
    });
    expect(architecture).not.toHaveProperty("analysisLevel");

    const [question] = minimalModel().questions;
    const candidate = CandidateQuestionSchema.parse({ ...question, analysisLevel: 4 });
    expect(candidate).not.toHaveProperty("analysisLevel");
  });

  it("is absent from the JSON Schemas handed to the model", () => {
    for (const schema of [
      architectureDraftJsonSchema,
      draftThreatJsonSchema,
      candidateQuestionJsonSchema,
    ]) {
      expect(JSON.stringify(schema)).not.toContain("analysisLevel");
    }
  });
});

describe("OWASP labels", () => {
  it("covers every code with its official 2025 name", () => {
    expect(Object.keys(OWASP_LABELS).sort()).toEqual(
      [...Owasp2025Schema.options].sort(),
    );
    expect(OWASP_LABELS["A09:2025"]).toBe("Security Logging and Alerting Failures");
  });
});

describe("ThreatModelSchema", () => {
  it("is the schema validateThreatModel wraps", () => {
    expect(ThreatModelSchema.safeParse(minimalModel()).success).toBe(true);
  });
});
