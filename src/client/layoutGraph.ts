/**
 * Deterministic architecture layout.
 *
 * The API hands back GraphNode.position as {0,0} for every node (src/client/adapter.ts
 * leaves laying the graph out to the dashboard). This module is that layout step: it runs
 * dagre over the nodes/edges of the existing view model and returns positioned copies.
 *
 * Deliberately free of React, React Flow and the DOM so it can be unit-tested in the plain
 * Node environment. ArchitectureGraph.tsx turns the result into React Flow nodes; nothing
 * here imports `reactflow`.
 *
 * Determinism matters for two reasons: a demo must look identical on every run, and the
 * layout test can only assert exact coordinates if the same input always produces the same
 * output. dagre itself is deterministic for a fixed insertion order, so this module fixes
 * that order (input order, after de-duplication) and rounds the final coordinates.
 *
 * Nothing here recomputes analysis: positions are presentation only. Severity, confidence,
 * priority and basis are read straight from the server view model (CLAUDE.md rule 2).
 */

import dagre from "dagre";
import type { GraphEdge, GraphNode } from "@/shared/viewModel";

/** Must match the rendered node box in ArchitectureGraph.tsx, or edges will not meet it. */
export const NODE_WIDTH = 220;
export const NODE_HEIGHT = 76;

export type LayoutOptions = {
  nodeWidth?: number;
  nodeHeight?: number;
  /** Top-to-bottom by default; data flows read downward. */
  rankdir?: "TB" | "LR" | "BT" | "RL";
  /** Gap between nodes in the same rank. */
  nodesep?: number;
  /** Gap between ranks. */
  ranksep?: number;
};

export type PositionedNode = GraphNode & {
  position: { x: number; y: number };
  width: number;
  height: number;
};

export type LayoutResult = {
  /** Input order is preserved, so the server's node ordering survives layout. */
  nodes: PositionedNode[];
  /** Only edges whose endpoints both exist; a dangling edge is dropped, not crashed on. */
  edges: GraphEdge[];
  width: number;
  height: number;
};

const DEFAULTS = {
  rankdir: "TB",
  nodesep: 60,
  ranksep: 90,
  marginx: 24,
  marginy: 24,
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Fail-safe id read. A partial API response can hand us a node without a usable id; such a
 * node is skipped rather than allowed to poison the graph (dagre would throw on it).
 */
function usableId(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function finiteOr(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

/**
 * Lays the graph out with dagre and returns positioned copies. Pure: neither `nodes` nor
 * `edges` (nor anything they contain) is mutated; every returned node is a fresh object.
 */
export function layoutGraph(
  nodes: readonly GraphNode[],
  edges: readonly GraphEdge[],
  options: LayoutOptions = {},
): LayoutResult {
  const nodeWidth = options.nodeWidth ?? NODE_WIDTH;
  const nodeHeight = options.nodeHeight ?? NODE_HEIGHT;

  const safeNodes = Array.isArray(nodes) ? nodes : [];
  const safeEdges = Array.isArray(edges) ? edges : [];

  // De-duplicate by id, keeping first occurrence, so a repeated id cannot make dagre's
  // output depend on which copy was inserted last.
  const seen = new Set<string>();
  const laidOut: GraphNode[] = [];
  for (const node of safeNodes) {
    // Read through a widened view: a partial API response can hand us null or an object
    // with no usable id, neither of which dagre would survive.
    const id = usableId((node as { id?: unknown } | null)?.id);
    if (id === null || seen.has(id)) continue;
    seen.add(id);
    laidOut.push(node);
  }

  const known = seen;
  const validEdges = safeEdges.filter((edge) => {
    const source = usableId((edge as { source?: unknown } | null)?.source);
    const target = usableId((edge as { target?: unknown } | null)?.target);
    return source !== null && target !== null && known.has(source) && known.has(target);
  });

  const graph = new dagre.graphlib.Graph({ directed: true, multigraph: true });
  graph.setGraph({
    rankdir: options.rankdir ?? DEFAULTS.rankdir,
    nodesep: options.nodesep ?? DEFAULTS.nodesep,
    ranksep: options.ranksep ?? DEFAULTS.ranksep,
    marginx: DEFAULTS.marginx,
    marginy: DEFAULTS.marginy,
  });
  graph.setDefaultEdgeLabel(() => ({}));

  for (const node of laidOut) {
    graph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
  }
  for (const edge of validEdges) {
    // The edge id is passed as dagre's `name` so two flows between the same pair of
    // components stay distinct instead of collapsing into one.
    graph.setEdge(edge.source, edge.target, {}, edge.id);
  }

  dagre.layout(graph);

  const positioned: PositionedNode[] = laidOut.map((node) => {
    const placed: unknown = graph.node(node.id);
    // dagre reports the node centre; React Flow positions from the top-left corner.
    const centreX = isRecord(placed) ? finiteOr(placed.x, 0) : 0;
    const centreY = isRecord(placed) ? finiteOr(placed.y, 0) : 0;
    return {
      ...node,
      position: {
        x: Math.round(centreX - nodeWidth / 2),
        y: Math.round(centreY - nodeHeight / 2),
      },
      width: nodeWidth,
      height: nodeHeight,
    };
  });

  const size: unknown = graph.graph();
  return {
    nodes: positioned,
    edges: validEdges.map((edge) => ({ ...edge })),
    width: Math.round(isRecord(size) ? finiteOr(size.width, 0) : 0),
    height: Math.round(isRecord(size) ? finiteOr(size.height, 0) : 0),
  };
}
