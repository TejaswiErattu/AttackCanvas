/**
 * layoutGraph: deterministic architecture layout.
 *
 * The layout is what makes a demo reproducible and what lets a diagram be compared between
 * runs, so the properties worth pinning are: the same input always produces the same
 * coordinates, the input is never mutated, server node order survives, and malformed graph
 * data degrades instead of throwing.
 *
 * Plain Node environment on purpose -- src/client/layoutGraph.ts must not need a DOM.
 */

import { describe, expect, it } from "vitest";
import { assignBoundaries, layoutGraph, NODE_HEIGHT, NODE_WIDTH } from "@/client/layoutGraph";
import type { GraphEdge, GraphNode, TrustBoundaryView } from "@/shared/viewModel";
import { deepFreeze } from "./helpers";

function node(id: string, overrides: Partial<GraphNode> = {}): GraphNode {
  return {
    id,
    type: "backend",
    label: id,
    position: { x: 0, y: 0 },
    threatCount: 0,
    maxSeverity: null,
    technologies: [],
    ...overrides,
  };
}

function edge(id: string, source: string, target: string): GraphEdge {
  return {
    id,
    source,
    target,
    label: `${source} to ${target}`,
    crossesTrustBoundary: false,
    dataClassification: "internal",
  };
}

const NODES: readonly GraphNode[] = [
  node("user", { type: "actor" }),
  node("web", { type: "frontend" }),
  node("api", { type: "api" }),
  node("db", { type: "database" }),
];

const EDGES: readonly GraphEdge[] = [
  edge("user-web", "user", "web"),
  edge("web-api", "web", "api"),
  edge("api-db", "api", "db"),
];

describe("layoutGraph", () => {
  it("produces identical coordinates for identical input", () => {
    const first = layoutGraph(NODES, EDGES);
    const second = layoutGraph(NODES, EDGES);

    expect(second.nodes.map((n) => n.position)).toEqual(
      first.nodes.map((n) => n.position),
    );
    expect(second.width).toBe(first.width);
    expect(second.height).toBe(first.height);
  });

  it("does not mutate the nodes or edges it is given", () => {
    const frozenNodes = deepFreeze(NODES.map((n) => ({ ...n, position: { ...n.position } })));
    const frozenEdges = deepFreeze(EDGES.map((e) => ({ ...e })));

    expect(() => layoutGraph(frozenNodes, frozenEdges)).not.toThrow();
    // The originals still carry the un-laid-out {0,0} the adapter hands over.
    expect(frozenNodes.every((n) => n.position.x === 0 && n.position.y === 0)).toBe(true);
  });

  it("returns fresh node objects rather than the inputs", () => {
    const result = layoutGraph(NODES, EDGES);
    result.nodes.forEach((laidOut, index) => {
      expect(laidOut).not.toBe(NODES[index]);
      expect(laidOut.position).not.toBe(NODES[index].position);
    });
  });

  it("preserves the server's node order", () => {
    const result = layoutGraph(NODES, EDGES);
    expect(result.nodes.map((n) => n.id)).toEqual(["user", "web", "api", "db"]);
  });

  it("carries every view-model field through unchanged", () => {
    const decorated = [
      node("api", { threatCount: 3, maxSeverity: "critical", technologies: ["next"] }),
    ];
    const [result] = layoutGraph(decorated, []).nodes;

    expect(result.threatCount).toBe(3);
    expect(result.maxSeverity).toBe("critical");
    expect(result.technologies).toEqual(["next"]);
    expect(result.width).toBe(NODE_WIDTH);
    expect(result.height).toBe(NODE_HEIGHT);
  });

  it("separates connected nodes into different ranks", () => {
    const result = layoutGraph(NODES, EDGES);
    const byId = new Map(result.nodes.map((n) => [n.id, n.position]));

    // Default rankdir is top-to-bottom, so a downstream node sits strictly lower.
    expect(byId.get("web")!.y).toBeGreaterThan(byId.get("user")!.y);
    expect(byId.get("api")!.y).toBeGreaterThan(byId.get("web")!.y);
    expect(byId.get("db")!.y).toBeGreaterThan(byId.get("api")!.y);
  });

  it("gives every node a distinct position", () => {
    const result = layoutGraph(NODES, EDGES);
    const seen = new Set(result.nodes.map((n) => `${n.position.x},${n.position.y}`));
    expect(seen.size).toBe(result.nodes.length);
  });

  it("returns integer coordinates so positions compare exactly", () => {
    const result = layoutGraph(NODES, EDGES);
    result.nodes.forEach((n) => {
      expect(Number.isInteger(n.position.x)).toBe(true);
      expect(Number.isInteger(n.position.y)).toBe(true);
    });
  });

  it("drops edges whose endpoints are missing instead of throwing", () => {
    const dangling = [...EDGES, edge("ghost", "api", "does-not-exist")];
    const result = layoutGraph(NODES, dangling);

    expect(result.edges.map((e) => e.id)).toEqual(["user-web", "web-api", "api-db"]);
  });

  it("keeps two flows between the same pair of components distinct", () => {
    const pair = [node("a"), node("b")];
    const both = [edge("a-b-read", "a", "b"), edge("a-b-write", "a", "b")];

    expect(layoutGraph(pair, both).edges.map((e) => e.id)).toEqual([
      "a-b-read",
      "a-b-write",
    ]);
  });

  it("de-duplicates repeated node ids", () => {
    const result = layoutGraph([node("api"), node("api"), node("db")], []);
    expect(result.nodes.map((n) => n.id)).toEqual(["api", "db"]);
  });

  it("handles an empty graph", () => {
    const result = layoutGraph([], []);
    expect(result.nodes).toEqual([]);
    expect(result.edges).toEqual([]);
  });

  it("survives partial API data without throwing", () => {
    const malformed = [
      node("ok"),
      { id: "" } as unknown as GraphNode,
      null as unknown as GraphNode,
    ];
    const badEdges = [
      { id: "x" } as unknown as GraphEdge,
      null as unknown as GraphEdge,
    ];

    const result = layoutGraph(malformed, badEdges);
    expect(result.nodes.map((n) => n.id)).toEqual(["ok"]);
    expect(result.edges).toEqual([]);
  });
});

describe("assignBoundaries", () => {
  const b = (id: string, componentIds: string[]): TrustBoundaryView => ({ id, name: `${id} zone`, componentIds });

  it("puts a component in the first boundary that lists it and notes the second", () => {
    const result = assignBoundaries([b("edge", ["user", "web"]), b("app", ["web", "api"])], NODES);
    expect(Object.fromEntries(result.boundaryOf)).toEqual({ user: "edge", web: "edge", api: "app" });
    expect(result.notes).toEqual(['web is also in the trust boundary "app zone"; it is drawn inside "edge zone".']);
  });

  it("leaves a component in no boundary top-level, and drops a boundary with no shown member", () => {
    const result = assignBoundaries([b("edge", ["user"]), b("ghost", ["not-a-node"])], NODES);
    expect(result.boundaryOf.has("db")).toBe(false);
    expect(result.used.map((u) => u.id)).toEqual(["edge"]);
  });
});

describe("layoutGraph: boundary groups", () => {
  const boundaries: TrustBoundaryView[] = [
    { id: "edge", name: "Internet", componentIds: ["user", "web"] },
    { id: "data", name: "Data", componentIds: ["db"] },
  ];

  it("draws one group per used boundary around its children, and keeps others top-level", () => {
    const { nodes, groups } = layoutGraph(NODES, EDGES, { boundaries });
    expect(groups.map((g) => [g.id, g.childIds])).toEqual([
      ["edge", ["user", "web"]],
      ["data", ["db"]],
    ]);
    expect(nodes.find((n) => n.id === "api")?.boundaryId).toBeNull();
    for (const group of groups) {
      for (const id of group.childIds) {
        const child = nodes.find((n) => n.id === id)!;
        expect(child.position.x).toBeGreaterThan(group.position.x);
        expect(child.position.y).toBeGreaterThan(group.position.y);
        expect(child.position.x + child.width).toBeLessThan(group.position.x + group.width);
        expect(child.position.y + child.height).toBeLessThan(group.position.y + group.height);
      }
    }
  });
});
