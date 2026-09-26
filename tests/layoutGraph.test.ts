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

  it("reads left to right: actors, frontends, api and backend, data, external", () => {
    const result = layoutGraph(NODES, EDGES);
    const x = new Map(result.nodes.map((n) => [n.id, n.position.x]));
    expect(x.get("web")!).toBeGreaterThan(x.get("user")!);
    expect(x.get("api")!).toBeGreaterThan(x.get("web")!);
    expect(x.get("db")!).toBeGreaterThan(x.get("api")!);
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

describe("layoutGraph: fixed columns by type", () => {
  const MIXED: readonly GraphNode[] = [
    node("stripe", { type: "external_service" }),
    node("admin", { type: "frontend" }),
    node("user", { type: "actor" }),
    node("web", { type: "frontend" }),
    node("api", { type: "api" }),
    node("jobs", { type: "backend" }),
    node("db", { type: "database" }),
    node("files", { type: "storage" }),
    node("idp", { type: "auth_provider" }),
    node("queue", { type: "queue" }),
  ];
  const FLOWS: readonly GraphEdge[] = [
    edge("u-w", "user", "web"),
    edge("u-a", "user", "admin"),
    edge("w-api", "web", "api"),
    edge("a-api", "admin", "api"),
    edge("s-api", "stripe", "api"),
    edge("api-db", "api", "db"),
    edge("jobs-files", "jobs", "files"),
    edge("api-idp", "api", "idp"),
    edge("db-api", "db", "api"),
  ];
  const BOUNDARIES: TrustBoundaryView[] = [
    { id: "internet", name: "Internet", componentIds: ["user", "web", "stripe"] },
    { id: "app", name: "Application", componentIds: ["api", "admin", "jobs", "queue"] },
    { id: "data", name: "Data", componentIds: ["db", "files"] },
  ];

  it("gives identical positions for the same input twice, groups included", () => {
    const first = layoutGraph(MIXED, FLOWS, { boundaries: BOUNDARIES });
    const second = layoutGraph(MIXED, FLOWS, { boundaries: BOUNDARIES });
    expect(second.nodes.map((n) => [n.id, n.position])).toEqual(first.nodes.map((n) => [n.id, n.position]));
    expect(second.groups).toEqual(first.groups);
  });

  it("never puts two components of one type in different columns", () => {
    const { nodes } = layoutGraph(MIXED, FLOWS, { boundaries: BOUNDARIES });
    const xsByType = new Map<string, Set<number>>();
    for (const n of nodes) xsByType.set(n.type, (xsByType.get(n.type) ?? new Set()).add(n.position.x));
    for (const [, xs] of xsByType) expect(xs.size).toBe(1);
  });

  it("orders the columns actor, frontend, api/backend, data, external, with others by the backends", () => {
    const { nodes } = layoutGraph(MIXED, FLOWS, { boundaries: BOUNDARIES });
    const x = (id: string) => nodes.find((n) => n.id === id)!.position.x;
    expect(x("user")).toBeLessThan(x("web"));
    expect(x("web")).toBe(x("admin"));
    expect(x("web")).toBeLessThan(x("api"));
    expect(x("api")).toBe(x("jobs"));
    expect(x("queue")).toBe(x("api"));
    expect(x("api")).toBeLessThan(x("db"));
    expect(x("db")).toBe(x("files"));
    expect(x("db")).toBeLessThan(x("stripe"));
    expect(x("stripe")).toBe(x("idp"));
  });

  it("never overlaps two boundary groups, or a component and a group it is not in", () => {
    const { nodes, groups } = layoutGraph(MIXED, FLOWS, { boundaries: BOUNDARIES });
    const overlap = (a: { x: number; y: number; w: number; h: number }, b: typeof a) =>
      a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
    const box = (g: { position: { x: number; y: number }; width: number; height: number }) => ({
      x: g.position.x, y: g.position.y, w: g.width, h: g.height,
    });
    for (let i = 0; i < groups.length; i++) {
      for (let j = i + 1; j < groups.length; j++) expect(overlap(box(groups[i]), box(groups[j]))).toBe(false);
    }
    for (const n of nodes) {
      for (const g of groups) {
        if (n.boundaryId === g.id) continue;
        expect(overlap(box(n), box(g))).toBe(false);
      }
    }
  });
});
