/**
 * Pure edge presentation for the architecture diagram.
 *
 * Every flow gets an arrowhead at its target, whatever its style: a trust-boundary
 * crossing stays dotted and animated, an internal flow stays solid, and both point the
 * way the data moves. Two flows that run in opposite directions between the same pair of
 * components would otherwise be drawn along one line with both arrowheads on it, so the
 * later one of such a pair is drawn as its own offset curve.
 *
 * Free of React and React Flow imports so it runs in plain Node tests. The marker type is
 * the string React Flow's MarkerType.ArrowClosed stands for.
 */

import type { GraphEdge } from "@/shared/viewModel";

export const ARROW_CLOSED = "arrowclosed";

/** Pixels the reverse edge of a pair is pushed away from the forward one. */
export const REVERSE_OFFSET = 36;

export type EdgeRoute = {
  id: string;
  /** True for the later edge of an opposite-direction pair. */
  reverse: boolean;
};

/**
 * One route per edge, in input order. An edge is `reverse` when an earlier edge runs from
 * its target to its source.
 */
export function edgeRoutes(
  edges: readonly Pick<GraphEdge, "id" | "source" | "target">[],
): EdgeRoute[] {
  const seen = new Set<string>();
  return edges.map((edge) => {
    const reverse = seen.has(`${edge.target}\u0000${edge.source}`);
    seen.add(`${edge.source}\u0000${edge.target}`);
    return { id: edge.id, reverse };
  });
}

export type EdgeLook = { on: boolean; dimming: boolean };

/** The stroke colour of a flow: highlighted, a trust-boundary crossing, or internal. */
export function edgeColor(edge: Pick<GraphEdge, "crossesTrustBoundary">, on: boolean): string {
  if (on) return "var(--color-mint)";
  return edge.crossesTrustBoundary ? "var(--color-boundary)" : "var(--color-flow)";
}

/**
 * The arrowhead, coloured like the stroke so a highlighted flow's arrow is highlighted
 * too. Present on every edge.
 */
export function edgeMarker(
  edge: Pick<GraphEdge, "crossesTrustBoundary">,
  look: EdgeLook,
): { type: string; color: string; width: number; height: number } {
  return { type: ARROW_CLOSED, color: edgeColor(edge, look.on), width: 18, height: 18 };
}

/** How the reverse edge of a pair is drawn apart from its partner. */
export function reverseEdgeShape(route: EdgeRoute): { type?: string; pathOptions?: { offset: number } } {
  return route.reverse ? { type: "smoothstep", pathOptions: { offset: REVERSE_OFFSET } } : {};
}

/** Handle ids the custom node exposes: the usual right-out/left-in pair, and its mirror. */
export const HANDLES = {
  out: "out",
  in: "in",
  outLeft: "out-left",
  inRight: "in-right",
} as const;

/**
 * Which sides a flow leaves and enters by. The diagram reads left to right, so a flow
 * that runs right to left (a webhook from an external service back into the api) leaves
 * its source on the left and enters its target on the right, instead of looping around
 * both nodes. Same-column flows keep the usual pair.
 */
export function handlesFor(sourceX: number, targetX: number): { sourceHandle: string; targetHandle: string } {
  return targetX < sourceX
    ? { sourceHandle: HANDLES.outLeft, targetHandle: HANDLES.inRight }
    : { sourceHandle: HANDLES.out, targetHandle: HANDLES.in };
}

// ---------------------------------------------------------------------------
// Labels and weight
// ---------------------------------------------------------------------------

/**
 * Where a label sits along its edge, from the source: 0.35, not the midpoint. Two flows
 * that share a node leave it on different paths, so their labels land on different
 * points; at the midpoint of edges that fan out of one node they would stack.
 */
export const LABEL_FRACTION = 0.35;

/** A diagram with more flows than this labels only the ones the reader points at. */
export const LABEL_EDGE_LIMIT = 12;

export type LabelContext = {
  edgeCount: number;
  /** The edge is highlighted by the selected threat. */
  on: boolean;
  hovered: boolean;
  /** The edge touches the selected node. */
  touchesSelected: boolean;
};

/**
 * Whether an edge's label is drawn. Every label shows on a small diagram; on a larger one
 * (more than LABEL_EDGE_LIMIT flows) only a hovered or highlighted edge, and an edge
 * touching the selected node, keeps its label.
 */
export function labelVisible(ctx: LabelContext): boolean {
  return ctx.edgeCount <= LABEL_EDGE_LIMIT || ctx.on || ctx.hovered || ctx.touchesSelected;
}

/** True when `edge` has `nodeId` at either end. */
export function touchesNode(edge: Pick<GraphEdge, "source" | "target">, nodeId: string | null): boolean {
  return nodeId !== null && (edge.source === nodeId || edge.target === nodeId);
}

/**
 * The stroke width of a flow: a trust-boundary crossing is heavier than an internal flow
 * and a highlighted one heavier still. The hovered edge is drawn thicker than any of those
 * so the reader can tell which line the label they are reading belongs to.
 */
export function edgeStrokeWidth(
  edge: Pick<GraphEdge, "crossesTrustBoundary">,
  look: { on: boolean; hovered: boolean },
): number {
  const base = look.on ? 3 : edge.crossesTrustBoundary ? 2 : 1.5;
  return look.hovered ? base + 2 : base;
}

/** The part of an SVG path this module reads, so tests need no DOM. */
export type PathMeasure = {
  getTotalLength(): number;
  getPointAtLength(length: number): { x: number; y: number };
};

/**
 * The point `fraction` of the way along a path, or `fallback` when the path cannot be
 * measured (no element yet, or an environment without SVG geometry).
 */
export function pointAlong(
  path: PathMeasure | null | undefined,
  fraction: number,
  fallback: { x: number; y: number },
): { x: number; y: number } {
  try {
    if (!path || typeof path.getTotalLength !== "function") return fallback;
    const length = path.getTotalLength();
    if (!Number.isFinite(length) || length <= 0) return fallback;
    const point = path.getPointAtLength(length * fraction);
    return Number.isFinite(point.x) && Number.isFinite(point.y) ? { x: point.x, y: point.y } : fallback;
  } catch {
    return fallback;
  }
}
