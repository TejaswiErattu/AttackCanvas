/**
 * drift: "Since last run" diff and run storage, over hand-built models. Plain Node.
 */

import { describe, expect, it } from "vitest";
import {
  diffThreatModels,
  lastRunKey,
  newThreatKeys,
  prevRunKey,
  recordRun,
  threatKey,
  type DriftModel,
} from "@/client/drift";
import type { StatusStorage } from "@/client/findingStatus";
import type { GraphEdge, GraphNode, ThreatCardData } from "@/shared/viewModel";
import { deepFreeze } from "./helpers";

function node(id: string, label: string, type: GraphNode["type"] = "backend"): GraphNode {
  return {
    id, type, label, position: { x: 0, y: 0 }, threatCount: 0, maxSeverity: null,
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
): ThreatCardData {
  return {
    id, title, componentNames,
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

  it("classifies threats as new, persisting and resolved", () => {
    expect(diff.threats.new.map((t) => t.title)).toEqual(["Open redirect"]);
    expect(diff.threats.resolved.map((t) => t.title)).toEqual(["Weak session cookie"]);
    expect(diff.threats.persisting).toHaveLength(1);
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
    expect(d.threats.resolved).toEqual([]);
    expect(d.threats.persisting).toHaveLength(2);
  });

  it("does not mutate either model", () => {
    expect(() => diffThreatModels(deepFreeze(structuredClone(prev)), deepFreeze(structuredClone(next)))).not.toThrow();
  });

  it("tolerates a partial model", () => {
    expect(() => diffThreatModels({} as DriftModel, {} as DriftModel)).not.toThrow();
  });
});

describe("newThreatKeys", () => {
  it("returns the keys of threats absent from the previous run", () => {
    const keys = newThreatKeys(prev, next);
    expect([...keys]).toEqual([threatKey(next.threats[1])]);
  });
});

function memoryStorage(): StatusStorage & { data: Record<string, string> } {
  const data: Record<string, string> = {};
  return {
    data,
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => {
      data[k] = v;
    },
  };
}

describe("recordRun", () => {
  it("has no previous run the first time", () => {
    const storage = memoryStorage();
    expect(recordRun(storage, "acme", "shop", prev)).toBeNull();
    expect(JSON.parse(storage.data[lastRunKey("acme", "shop")]).threats).toHaveLength(2);
    expect(storage.data[prevRunKey("acme", "shop")]).toBeUndefined();
  });

  it("moves the old run to prev and returns it", () => {
    const storage = memoryStorage();
    recordRun(storage, "acme", "shop", prev);
    const before = recordRun(storage, "acme", "shop", next);
    expect(before?.threats).toHaveLength(2);
    expect(JSON.parse(storage.data[prevRunKey("acme", "shop")]).nodes[0].id).toBe("c1");
    expect(JSON.parse(storage.data[lastRunKey("acme", "shop")]).nodes[0].id).toBe("x1");
  });

  it("does not rotate when the same run is recorded again (a reload)", () => {
    const storage = memoryStorage();
    recordRun(storage, "acme", "shop", prev);
    recordRun(storage, "acme", "shop", next);
    const again = recordRun(storage, "acme", "shop", next);
    expect(again?.nodes[0].id).toBe("c1");
    expect(JSON.parse(storage.data[prevRunKey("acme", "shop")]).nodes[0].id).toBe("c1");
  });

  it("keeps repositories apart", () => {
    const storage = memoryStorage();
    recordRun(storage, "acme", "shop", prev);
    expect(recordRun(storage, "acme", "other", next)).toBeNull();
  });

  it("survives storage that throws or holds junk", () => {
    const throwing: StatusStorage = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("quota");
      },
    };
    expect(recordRun(throwing, "acme", "shop", prev)).toBeNull();
    expect(recordRun(null, "acme", "shop", prev)).toBeNull();
    const junk = memoryStorage();
    junk.data[lastRunKey("acme", "shop")] = "{not json";
    expect(recordRun(junk, "acme", "shop", prev)).toBeNull();
  });
});
