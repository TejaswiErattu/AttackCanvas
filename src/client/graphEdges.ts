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
