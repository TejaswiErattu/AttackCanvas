/**
 * drift: the "Since last run" diff over hand-built models. Plain Node. Run storage is in
 * tests/runHistory.test.ts.
 */

import { describe, expect, it } from "vitest";
import {
  diffThreatModels,
  newThreatKeys,
  threatKey,
  type DriftModel,
} from "@/client/drift";
import type { GraphEdge, GraphNode, ThreatCardData } from "@/shared/viewModel";
import { deepFreeze } from "./helpers";

function node(id: string, label: string, type: GraphNode["type"] = "backend"): GraphNode {
  return {
    id, type, label, position: { x: 0, y: 0 }, threatCount: 0, lowConfidenceThreatCount: 0, maxSeverity: null,
    technologies: [], assets: [], exposure: "internal",
  };
}

function edge(id: string, source: string, target: string, label: string): GraphEdge {
  return { id, source, target, label, crossesTrustBoundary: false, dataClassification: "internal" } as GraphEdge;
}

function threat(
  id: string,
  title: string,
  componentNames: string[],
  owasp: string[],
  confidence = 60,
): ThreatCardData {
  return {
    id, title, componentNames, severity: "high", confidence,
    owasp: owasp.map((code) => ({ code, label: code })),
  } as unknown as ThreatCardData;
}

const A = ["A01:2025"];
const model = (
  nodes: GraphNode[],
  edges: GraphEdge[],
  threats: ThreatCardData[],
  analyzedAt = "2026-01-01T00:00:00.000Z",
) => ({ nodes, edges, threats, repo: { analyzedAt } }) as DriftModel & { repo: { analyzedAt: string } };

const prev = model(
  [node("c1", "API"), node("c2", "Database", "database"), node("c3", "Legacy queue", "queue")],
  [edge("f1", "c1", "c2", "SQL"), edge("f2", "c1", "c3", "jobs")],
  [
    threat("t1", "SQL injection in login", ["API", "Database"], A),
    threat("t2", "Weak session cookie", ["API"], ["A07:2025"]),
  ],
);

// Ids are re-minted between runs on purpose: only names may be compared.
const next = model(
  [node("x1", "API"), node("x2", "Database", "database"), node("x9", "Cache", "database")],
  [edge("g1", "x1", "x2", "SQL"), edge("g2", "x1", "x9", "reads")],
  [
    threat("n1", "  SQL Injection in login! ", ["Database", "API"], A),
    threat("n2", "Open redirect", ["API"], ["A01:2025"]),
  ],
  "2026-02-01T00:00:00.000Z",
);

describe("diffThreatModels", () => {
  const diff = diffThreatModels(prev, next);

  it("finds components added and removed by name and type", () => {
    expect(diff.components.added).toEqual([{ name: "Cache", type: "database" }]);
    expect(diff.components.removed).toEqual([{ name: "Legacy queue", type: "queue" }]);
  });

  it("treats a same-named component of another type as a different one", () => {
    const d = diffThreatModels(
      model([node("a", "Store", "database")], [], []),
      model([node("b", "Store", "backend")], [], []),
    );
    expect(d.components.added).toHaveLength(1);
    expect(d.components.removed).toHaveLength(1);
  });

  it("finds flows by source name, target name and label, ignoring ids", () => {
    expect(diff.flows.added).toEqual([{ source: "API", target: "Cache", label: "reads" }]);
    expect(diff.flows.removed).toEqual([{ source: "API", target: "Legacy queue", label: "jobs" }]);
  });

  it("treats a changed flow label as one removed and one added", () => {
    const d = diffThreatModels(
      model([node("a", "A"), node("b", "B")], [edge("f", "a", "b", "old")], []),
      model([node("a", "A"), node("b", "B")], [edge("f", "a", "b", "new")], []),
    );
    expect(d.flows.added.map((f) => f.label)).toEqual(["new"]);
    expect(d.flows.removed.map((f) => f.label)).toEqual(["old"]);
  });

  it("classifies threats as new, persisting and not found this run", () => {
    expect(diff.threats.new.map((t) => t.title)).toEqual(["Open redirect"]);
    expect(diff.threats.notFound.map((t) => t.title)).toEqual(["Weak session cookie"]);
    expect(diff.threats.droppedBelowCutoff).toEqual([]);
    expect(diff.threats.persisting).toHaveLength(1);
  });

  it("has no resolved group: absence is never reported as resolved or fixed", () => {
    expect(Object.keys(diff.threats).sort()).toEqual(
      ["droppedBelowCutoff", "new", "notFound", "persisting"],
    );
  });

  it("matches a threat despite title case, punctuation, spacing and component order", () => {
    expect(diff.threats.persisting[0].title).toContain("SQL Injection");
  });

  it("does not match the same title with a different component or OWASP set", () => {
    const base = model([], [], [threat("a", "Same", ["API"], A)]);
    const otherComponent = model([], [], [threat("b", "Same", ["Worker"], A)]);
    const otherOwasp = model([], [], [threat("c", "Same", ["API"], ["A02:2025"])]);
    expect(diffThreatModels(base, otherComponent).threats.persisting).toHaveLength(0);
    expect(diffThreatModels(base, otherOwasp).threats.persisting).toHaveLength(0);
  });

  it("reports nothing for identical models", () => {
    const d = diffThreatModels(prev, prev);
    expect(d.components).toEqual({ added: [], removed: [] });
    expect(d.flows).toEqual({ added: [], removed: [] });
    expect(d.threats.new).toEqual([]);
    expect(d.threats.notFound).toEqual([]);
    expect(d.threats.persisting).toHaveLength(2);
  });

  it("does not mutate either model", () => {
    expect(() => diffThreatModels(deepFreeze(structuredClone(prev)), deepFreeze(structuredClone(next)))).not.toThrow();
  });

  it("tolerates a partial model", () => {
    expect(() => diffThreatModels({} as DriftModel, {} as DriftModel)).not.toThrow();
  });
});

describe("diffThreatModels over visible and below-25% threats", () => {
  const sqli = threat("t1", "SQL injection in login", ["API"], A, 70);
  const cookie = threat("t2", "Weak session cookie", ["API"], ["A07:2025"], 55);
  const csrf = threat("t3", "Missing CSRF token", ["API"], ["A01:2025"], 40);
  const before = { nodes: [], edges: [], threats: [sqli, cookie, csrf], hiddenThreats: [] };

  it("reports a threat now below 25% as dropped, not as not found", () => {
    const after = {
      nodes: [], edges: [],
      threats: [threat("n1", "SQL injection in login", ["API"], A, 70)],
      hiddenThreats: [threat("n2", "Weak session cookie", ["API"], ["A07:2025"], 12)],
    };
    const d = diffThreatModels(before, after);
    expect(d.threats.droppedBelowCutoff.map((t) => [t.title, t.confidence])).toEqual([
      ["Weak session cookie", 12],
    ]);
    expect(d.threats.notFound.map((t) => t.title)).toEqual(["Missing CSRF token"]);
    expect(d.threats.persisting.map((t) => t.title)).toEqual(["SQL injection in login"]);
    expect(d.threats.new).toEqual([]);
  });

  it("reproduces the AltoroJ case: every threat below 25% is dropped, none not found", () => {
    const after = {
      nodes: [], edges: [], threats: [],
      hiddenThreats: [
        threat("n1", "SQL injection in login", ["API"], A, 20),
        threat("n2", "Weak session cookie", ["API"], ["A07:2025"], 20),
        threat("n3", "Missing CSRF token", ["API"], ["A01:2025"], 20),
        threat("n4", "Something else", ["API"], ["A05:2025"], 10),
      ],
    };
    const d = diffThreatModels(before, after);
    expect(d.threats.droppedBelowCutoff).toHaveLength(3);
    expect(d.threats.notFound).toEqual([]);
    // A threat new this run but below 25% is not listed as new.
    expect(d.threats.new).toEqual([]);
  });

  it("counts a threat hidden last run and visible now as persisting", () => {
    const d = diffThreatModels(
      { nodes: [], edges: [], threats: [], hiddenThreats: [threat("h", "Weak session cookie", ["API"], ["A07:2025"], 10)] },
      { nodes: [], edges: [], threats: [cookie] },
    );
    expect(d.threats.persisting.map((t) => t.title)).toEqual(["Weak session cookie"]);
    expect(d.threats.new).toEqual([]);
  });

  it("lists a threat hidden last run and gone now as not found, flagged below cutoff", () => {
    const d = diffThreatModels(
      { nodes: [], edges: [], threats: [], hiddenThreats: [threat("h", "Old", ["API"], A, 10)] },
      { nodes: [], edges: [], threats: [] },
    );
    expect(d.threats.notFound.map((t) => [t.title, t.belowCutoff])).toEqual([["Old", true]]);
  });

  it("does not list a threat hidden in both runs in any group", () => {
    const h = threat("h", "Quiet", ["API"], A, 10);
    const d = diffThreatModels(
      { nodes: [], edges: [], threats: [], hiddenThreats: [h] },
      { nodes: [], edges: [], threats: [], hiddenThreats: [h] },
    );
    expect(d.threats).toEqual({ new: [], persisting: [], notFound: [], droppedBelowCutoff: [] });
  });

  it("reads an old snapshot without hiddenThreats as having none", () => {
    const oldSnapshot = { nodes: [], edges: [], threats: [sqli, cookie] } as DriftModel;
    const d = diffThreatModels(oldSnapshot, {
      nodes: [], edges: [], threats: [sqli],
      hiddenThreats: [threat("n2", "Weak session cookie", ["API"], ["A07:2025"], 12)],
    });
    expect(d.threats.droppedBelowCutoff.map((t) => t.title)).toEqual(["Weak session cookie"]);
    expect(d.threats.notFound).toEqual([]);
  });

  it("carries severity and confidence on each ref", () => {
    const d = diffThreatModels(before, { nodes: [], edges: [], threats: [] });
    expect(d.threats.notFound[0]).toMatchObject({
      title: "SQL injection in login", severity: "high", confidence: 70, belowCutoff: false,
      key: threatKey(sqli),
    });
  });
});

describe("newThreatKeys", () => {
  it("returns the keys of threats absent from the previous run", () => {
    const keys = newThreatKeys(prev, next);
    expect([...keys]).toEqual([threatKey(next.threats[1])]);
  });

  it("does not badge a threat that was below 25% last run as new", () => {
    const h = threat("h", "Quiet", ["API"], A, 10);
    const keys = newThreatKeys(
      { nodes: [], edges: [], threats: [], hiddenThreats: [h] },
      { nodes: [], edges: [], threats: [threat("v", "Quiet", ["API"], A, 50)] },
    );
    expect(keys.size).toBe(0);
  });
});
