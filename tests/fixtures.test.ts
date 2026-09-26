import { describe, expect, it } from "vitest";
import { toDashboardViewModel } from "@/client/adapter";
import {
  validateThreatModel,
  type Evidence,
  type Threat,
  type ThreatModel,
} from "@/shared/schema";
import demoJson from "../fixtures/demo-analysis.json";
import emptyJson from "../fixtures/empty-analysis.json";
import { findUndefined } from "./helpers";

function load(input: unknown): ThreatModel {
  const result = validateThreatModel(input);
  if (!result.ok) {
    throw new Error(`fixture is invalid: ${JSON.stringify(result.issues)}`);
  }
  return result.data;
}

// ---------------------------------------------------------------------------
// Reference scoring
//
// A stand-in for the CLAUDE.md rule 2 scoring rules, as interpreted by the playbook's
// Prompt O, used only to check the numbers hand-written into the demo fixture.
// src/server/scoring does not exist yet; once it does, replace this with that module.
// fixtures/demo-analysis.notes.md walks through every threat.
//
// Points are integer hundredths so rounding to two decimals is exact.
// ---------------------------------------------------------------------------

type Kind = Evidence["kind"];
type Source = Evidence["source"];

/** Evidence that is neither inference nor assumption. */
function isDirect(e: Evidence): boolean {
  return e.kind !== "inference" && e.kind !== "assumption";
}

/** Distinct EvidenceSource values behind a threat's direct evidence. */
function corroboratingSources(cited: Evidence[]): Source[] {
  return [...new Set(cited.filter(isDirect).map((e) => e.source))].sort();
}

/** Each contribution applies once per evidence kind, however many items there are. */
function scoreConfidence(cited: Evidence[], assumptionCount: number): number {
  const has = (kind: Kind, source?: Source) =>
    cited.some((e) => e.kind === kind && (source === undefined || e.source === source));

  let points = 0;
  if (has("code")) points += 35; // "config" earns no code points
  if (has("scanner", "semgrep")) points += 25;
  if (has("dependency", "osv")) points += 30;
  if (has("developer_answer")) points += 30;
  if (corroboratingSources(cited).length >= 2) points += 10; // once, never per source

  const directKinds: Kind[] = ["code", "scanner", "dependency", "developer_answer"];
  if (has("inference") && !directKinds.some((kind) => has(kind))) points += 20;

  if (assumptionCount > 0) points -= 15; // once, never per assumption
  return Math.min(100, Math.max(0, points)) / 100;
}

function basisOf(cited: Evidence[]): Threat["basis"] {
  return cited.some(isDirect) ? "evidence_backed" : "assumption_dependent";
}

function expectedScoring(threat: Threat, allEvidence: Evidence[]) {
  const cited = allEvidence.filter((e) => threat.evidenceIds.includes(e.id));
  const risk = threat.impact * threat.likelihood;
  const confidence = scoreConfidence(cited, threat.assumptions.length);
  const severity =
    risk >= 20 ? "critical" : risk >= 12 ? "high" : risk >= 6 ? "medium" : "low";
  const priority =
    severity === "critical" || (severity === "high" && confidence >= 0.5)
      ? "fix_now"
      : (severity === "high" && confidence < 0.5) ||
          (severity === "medium" && confidence >= 0.5)
        ? "fix_soon"
        : "monitor";

  return {
    risk,
    severity,
    confidence,
    confidenceLabel: confidence >= 0.7 ? "high" : confidence >= 0.4 ? "medium" : "low",
    priority,
    basis: basisOf(cited),
  };
}

function item(kind: Kind, source: Source): Evidence {
  return { id: `${kind}-${source}`, kind, source, summary: "synthetic" };
}

describe("reference scoring rules", () => {
  it("adds code points once, however many code items", () => {
    expect(scoreConfidence([item("code", "detector")], 0)).toBe(0.35);
    const two = [item("code", "detector"), { ...item("code", "detector"), id: "again" }];
    expect(scoreConfidence(two, 0)).toBe(0.35);
  });

  it("gives config evidence no code points, but it is still direct evidence", () => {
    const config = [item("config", "detector")];
    expect(scoreConfidence(config, 0)).toBe(0);
    expect(basisOf(config)).toBe("evidence_backed");
  });

  it("adds semgrep points only for scanner evidence from Semgrep, once", () => {
    expect(scoreConfidence([item("scanner", "semgrep")], 0)).toBe(0.25);
    const two = [item("scanner", "semgrep"), { ...item("scanner", "semgrep"), id: "again" }];
    expect(scoreConfidence(two, 0)).toBe(0.25);
    expect(scoreConfidence([item("scanner", "detector")], 0)).toBe(0);
  });

  it("adds osv points only for dependency evidence from OSV, once", () => {
    expect(scoreConfidence([item("dependency", "osv")], 0)).toBe(0.3);
    expect(scoreConfidence([item("dependency", "detector")], 0)).toBe(0);
  });

  it("adds developer-answer points once", () => {
    expect(scoreConfidence([item("developer_answer", "developer")], 0)).toBe(0.3);
  });

  it("adds the second-source bonus once, for two distinct direct sources", () => {
    const codeAndSemgrep = [item("code", "detector"), item("scanner", "semgrep")];
    expect(scoreConfidence(codeAndSemgrep, 0)).toBe(0.7); // .35 + .25 + .10
    expect(corroboratingSources(codeAndSemgrep)).toEqual(["detector", "semgrep"]);
  });

  it("does not stack the bonus with a third source", () => {
    // Three distinct sources but no code points: .25 + .30 + .10, not .25 + .30 + .20.
    const three = [
      item("config", "detector"),
      item("scanner", "semgrep"),
      item("dependency", "osv"),
    ];
    expect(corroboratingSources(three)).toEqual(["detector", "osv", "semgrep"]);
    expect(scoreConfidence(three, 0)).toBe(0.65);
  });

  it("needs two distinct sources, not two items", () => {
    const sameSource = [item("code", "detector"), item("config", "detector")];
    expect(corroboratingSources(sameSource)).toEqual(["detector"]);
    expect(scoreConfidence(sameSource, 0)).toBe(0.35);
  });

  it("does not treat AI inference or assumptions as a second source", () => {
    const withInference = [item("code", "detector"), item("inference", "ai")];
    expect(corroboratingSources(withInference)).toEqual(["detector"]);
    expect(scoreConfidence(withInference, 0)).toBe(0.35);
  });

  it("adds the inference-only bonus only without code, scanner, dependency or developer evidence", () => {
    expect(scoreConfidence([item("inference", "ai")], 0)).toBe(0.2);
    expect(scoreConfidence([item("inference", "ai"), item("code", "detector")], 0)).toBe(0.35);
    expect(scoreConfidence([item("inference", "ai"), item("scanner", "semgrep")], 0)).toBe(0.25);
    expect(scoreConfidence([item("inference", "ai"), item("dependency", "osv")], 0)).toBe(0.3);
    // As written, config and assumption evidence do not switch the bonus off.
    expect(scoreConfidence([item("inference", "ai"), item("config", "detector")], 0)).toBe(0.2);
    expect(scoreConfidence([item("inference", "ai"), item("assumption", "ai")], 0)).toBe(0.2);
  });

  it("subtracts the assumption penalty once, not per assumption", () => {
    const code = [item("code", "detector")];
    expect(scoreConfidence(code, 0)).toBe(0.35);
    expect(scoreConfidence(code, 1)).toBe(0.2);
    expect(scoreConfidence(code, 3)).toBe(0.2);
  });

  it("clamps to 0..1", () => {
    expect(scoreConfidence([], 2)).toBe(0);
    const everything = [
      item("code", "detector"),
      item("scanner", "semgrep"),
      item("dependency", "osv"),
      item("developer_answer", "developer"),
    ];
    expect(scoreConfidence(everything, 0)).toBe(1); // 1.30 before the clamp
  });

  it("derives basis from the evidence, never from assumptions", () => {
    expect(basisOf([item("code", "detector")])).toBe("evidence_backed");
    expect(basisOf([item("inference", "ai"), item("code", "detector")])).toBe("evidence_backed");
    expect(basisOf([item("inference", "ai")])).toBe("assumption_dependent");
    expect(basisOf([item("inference", "ai"), item("assumption", "ai")])).toBe("assumption_dependent");
    expect(basisOf([])).toBe("assumption_dependent");
  });
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

describe("fixtures validate", () => {
  it.each([
    ["demo-analysis.json", demoJson],
    ["empty-analysis.json", emptyJson],
  ])("%s passes validateThreatModel", (_name, json) => {
    const result = validateThreatModel(json);
    expect(result.ok, result.ok ? "" : JSON.stringify(result.issues)).toBe(true);
  });
});

describe("demo-analysis.json", () => {
  const model = load(demoJson);
  const byId = <T extends { id: string }>(items: T[], id: string) =>
    items.find((entry) => entry.id === id);

  it("has the components, in a left-to-right layout", () => {
    expect(model.components.map((c) => [c.id, c.type])).toEqual([
      ["user", "actor"],
      ["web-frontend", "frontend"],
      ["api-server", "api"],
      ["admin-panel", "frontend"],
      ["postgres-db", "database"],
      ["s3-attachments", "storage"],
      ["stripe", "external_service"],
    ]);
    for (const component of model.components) {
      expect(component.position, component.id).toBeDefined();
      expect(component.position!.x % 250, component.id).toBe(0);
    }
  });

  it("has 8 flows, at least 4 crossing a boundary, including the two required", () => {
    expect(model.dataFlows).toHaveLength(8);
    expect(model.dataFlows.filter((f) => f.crossesTrustBoundary).length).toBeGreaterThanOrEqual(4);

    const webhook = model.dataFlows.find((f) => f.sourceId === "stripe" && f.targetId === "api-server");
    const upload = model.dataFlows.find((f) => f.sourceId === "api-server" && f.targetId === "s3-attachments");
    expect(webhook?.crossesTrustBoundary).toBe(true);
    expect(upload?.crossesTrustBoundary).toBe(true);
  });

  it("has 3 trust boundaries and 2 unknowns", () => {
    expect(model.trustBoundaries.map((b) => b.id)).toEqual([
      "internet-boundary",
      "application-boundary",
      "data-boundary",
    ]);
    expect(model.unknowns.map((u) => u.id)).toEqual([
      "admin-panel-exposure",
      "s3-bucket-access-policy",
    ]);
  });

  it("has 14 evidence items covering every kind except developer_answer", () => {
    expect(model.evidence).toHaveLength(14);
    expect(new Set(model.evidence.map((e) => e.kind))).toEqual(
      new Set(["code", "config", "scanner", "dependency", "inference", "assumption"]),
    );
  });

  it("cites every evidence item from at least one threat", () => {
    const cited = new Set(model.threats.flatMap((t) => t.evidenceIds));
    expect(model.evidence.filter((e) => !cited.has(e.id)).map((e) => e.id)).toEqual([]);
  });

  describe("threats", () => {
    const { threats } = model;

    it("has 9, covering every STRIDE letter, severity and priority", () => {
      expect(threats).toHaveLength(9);
      expect(new Set(threats.flatMap((t) => t.stride))).toEqual(
        new Set(["S", "T", "R", "I", "D", "E"]),
      );
      expect(new Set(threats.map((t) => t.severity))).toEqual(
        new Set(["critical", "high", "medium", "low"]),
      );
      expect(new Set(threats.map((t) => t.priority))).toEqual(
        new Set(["fix_now", "fix_soon", "monitor"]),
      );
    });

    it("includes the required shapes", () => {
      expect(threats.some((t) => t.attackScenario.length > 600)).toBe(true);
      expect(threats.some((t) => t.cwe.length === 0)).toBe(true);
      expect(threats.some((t) => t.stride.length === 2 && t.owasp.length === 2)).toBe(true);
    });

    it("has exactly two assumption_dependent threats, both resting on inference", () => {
      const dependent = threats.filter((t) => t.basis === "assumption_dependent");
      expect(dependent.map((t) => t.id)).toEqual([
        "admin-panel-exposed",
        "note-search-resource-exhaustion",
      ]);
      for (const threat of dependent) {
        const cited = model.evidence.filter((e) => threat.evidenceIds.includes(e.id));
        expect(cited.every((e) => !isDirect(e)), threat.id).toBe(true);
      }
    });

    it("has an evidence_backed threat that still lists an assumption", () => {
      const s3 = byId(threats, "s3-attachments-public-read");
      expect(s3?.assumptions.length).toBeGreaterThan(0);
      expect(s3?.basis).toBe("evidence_backed");
    });

    it.each(threats.map((t) => [t.id, t] as const))(
      "%s carries scores that match the rules",
      (_id, threat) => {
        const expected = expectedScoring(threat, model.evidence);

        expect({
          severity: threat.severity,
          confidence: threat.confidence,
          confidenceLabel: threat.confidenceLabel,
          priority: threat.priority,
          basis: threat.basis,
        }).toEqual({
          severity: expected.severity,
          confidence: expected.confidence,
          confidenceLabel: expected.confidenceLabel,
          priority: expected.priority,
          basis: expected.basis,
        });
      },
    );

    it("lists the EvidenceSource values behind each second-source bonus", () => {
      const sources = Object.fromEntries(
        threats.map((t) => [
          t.id,
          corroboratingSources(model.evidence.filter((e) => t.evidenceIds.includes(e.id))),
        ]),
      );

      expect(sources).toEqual({
        "admin-routes-missing-authz": ["detector", "semgrep"],
        "jwt-hardcoded-secret": ["detector", "osv", "semgrep"],
        "stripe-webhook-unverified": ["detector"],
        "s3-attachments-public-read": ["detector"],
        "sql-injection-note-search": ["detector", "semgrep"],
        "vulnerable-jsonwebtoken-dependency": ["osv"],
        "admin-actions-unaudited": ["detector"],
        "admin-panel-exposed": [],
        "note-search-resource-exhaustion": [],
      });
    });

    it("has exactly the three low-confidence threats below the 0.25 threshold", () => {
      expect(threats.filter((t) => t.confidence < 0.25).map((t) => t.id)).toEqual([
        "s3-attachments-public-read",
        "admin-panel-exposed",
        "note-search-resource-exhaustion",
      ]);
    });
  });

  it("links both questions to unknowns, and to threats that depend on them", () => {
    expect(model.questions).toHaveLength(2);
    for (const question of model.questions) {
      expect(byId(model.unknowns, question.unknownId), question.id).toBeDefined();
      for (const threatId of question.affectedThreatIds) {
        expect(
          byId(model.threats, threatId)?.dependsOnUnknownIds,
          `${question.id} -> ${threatId}`,
        ).toContain(question.unknownId);
      }
    }
  });
});

describe("empty-analysis.json", () => {
  const model = load(emptyJson);

  it("has zero threats and exactly one limitation", () => {
    expect(model.threats).toEqual([]);
    expect(model.limitations).toHaveLength(1);
  });
});

describe("fixtures through toDashboardViewModel", () => {
  it("builds the demo dashboard without errors or undefined fields", () => {
    const model = load(demoJson);
    const view = toDashboardViewModel(model);

    expect(findUndefined(view)).toEqual([]);
    expect(view.repo.fullName).toBe("acme/acme-notes");
    expect(view.analysisLevelLabel).toBe("Standard");
    expect(view.nodes).toHaveLength(7);
    expect(view.edges).toHaveLength(8);
  });

  it("shows the 6 visible threats and hides the 3 below 0.25", () => {
    const model = load(demoJson);
    const view = toDashboardViewModel(model);

    expect(view.threats.map((t) => t.id)).toEqual([
      "admin-routes-missing-authz", // fix_now, risk 20
      "sql-injection-note-search", // fix_now, risk 16
      "jwt-hardcoded-secret", // fix_now, risk 15
      "stripe-webhook-unverified", // fix_soon, risk 12
      "vulnerable-jsonwebtoken-dependency", // monitor, risk 6
      "admin-actions-unaudited", // monitor, risk 4
    ]);
    expect(view.counts).toEqual({ critical: 1, high: 3, medium: 1, low: 1 });
    expect(view.fixNow.map((t) => t.id)).toEqual([
      "admin-routes-missing-authz", // critical
      "jwt-hardcoded-secret", // high, confidence 1
      "sql-injection-note-search", // high, confidence 0.7
    ]);

    // Hiding is display-only: the stored model keeps all 9.
    expect(model.threats).toHaveLength(9);
    const shown = new Set(view.threats.map((t) => t.id));
    expect(model.threats.filter((t) => !shown.has(t.id)).map((t) => t.id).sort()).toEqual([
      "admin-panel-exposed",
      "note-search-resource-exhaustion",
      "s3-attachments-public-read",
    ]);
  });

  it("builds an empty dashboard for the empty fixture", () => {
    const view = toDashboardViewModel(load(emptyJson));

    expect(findUndefined(view)).toEqual([]);
    expect(view.threats).toEqual([]);
    expect(view.fixNow).toEqual([]);
    expect(view.nodes).toEqual([]);
    expect(view.edges).toEqual([]);
    expect(view.counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
    expect(view.limitations).toHaveLength(1);
    expect(view.analysisLevelLabel).toBe("Basic");
  });
});

describe("confidenceReasons on the fixtures", () => {
  /** Signed hundredths from a "+0.35 ..." / "-0.15 ..." line; undefined for other lines. */
  function points(line: string): number | undefined {
    const match = /^([+-]\d\.\d\d) /.exec(line);
    return match ? Math.round(parseFloat(match[1]) * 100) : undefined;
  }

  it("sums to each visible threat's confidence when no control gap is involved", () => {
    const model = load(demoJson);
    const view = toDashboardViewModel(model);
    const byId = new Map(model.threats.map((t) => [t.id, t]));
    let checked = 0;

    for (const card of view.threats) {
      const threat = byId.get(card.id)!;
      const cited = threat.evidenceIds.map((id) => model.evidence.find((e) => e.id === id)!);
      // A gap line is a maximum (scaled by detector certainty the model does not carry).
      if (cited.some((e) => e.ruleId?.startsWith("gap:"))) continue;

      const total = card.confidenceReasons.reduce((sum, line) => sum + (points(line) ?? 0), 0);
      expect(Math.min(100, Math.max(0, total)), card.id).toBe(card.confidence);
      expect(card.confidenceReasons.at(-1)).toMatch(/^Confidence \d+% \(/);
      checked += 1;
    }
    expect(checked).toBeGreaterThan(0);
  });

  it("is a list of strings on every card, including the empty fixture", () => {
    for (const json of [demoJson, emptyJson]) {
      const view = toDashboardViewModel(load(json));
      for (const card of view.threats) {
        expect(card.confidenceReasons.length).toBeGreaterThan(0);
        expect(card.confidenceReasons.every((l) => typeof l === "string")).toBe(true);
      }
    }
  });
});

describe("a gap-backed threat on the demo fixture", () => {
  function withGapThreat() {
    const model = structuredClone(load(demoJson));
    const template = model.threats.find((t) => t.id === "stripe-webhook-unverified")!;
    model.evidence.push({
      id: "ev-gap-demo", kind: "code", source: "detector", ruleId: "gap:webhook_signature",
      summary: "No signature check near the webhook handler.",
    });
    model.threats.push({
      ...template,
      id: "gap-backed",
      evidenceIds: ["ev-gap-demo"],
      confidence: 0.6,
      confidenceLabel: "medium",
      priority: "fix_soon",
    });
    return load(model);
  }

  it("gets qualitative reasons that do not claim to add up, while the rest stay exact", () => {
    const view = toDashboardViewModel(withGapThreat());
    const card = view.threats.find((t) => t.id === "gap-backed")!;

    expect(card.confidenceReasons[0]).toContain("a security control is missing");
    expect(card.confidenceReasons.join("\n")).not.toMatch(/[+-]\d\.\d\d/);
    expect(card.confidenceReasons.at(-1)).toMatch(/^Confidence 60% \(medium\)\. .*not separate scores that add up/);

    const sql = view.threats.find((t) => t.id === "sql-injection-note-search")!;
    expect(sql.confidenceReasons).toContain("+0.35 code evidence");
    expect(sql.confidenceReasons.join("\n")).not.toContain("not separate scores");
  });
});

