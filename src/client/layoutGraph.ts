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
 * The diagram reads left to right in fixed columns chosen by component type before dagre
 * runs: actors; frontends; api and backend; database and storage; external services and
 * auth providers. Worker, queue and any type added later sit with the backends. Two
 * components of one type are therefore always in one column.
 *
 * dagre (rankdir LR, trust boundaries passed as compound nodes) decides only the order of
 * components within a column, which keeps edge crossings down. The final placement then
 * stacks each boundary in its own horizontal band, so two boundary groups never overlap
 * however their members spread across columns. Components in no boundary share one band.
 *
 * Determinism matters for two reasons: a demo must look identical on every run, and the
 * layout test can only assert exact coordinates if the same input always produces the same
 * output. dagre itself is deterministic for a fixed insertion order, so this module fixes
 * that order (input order, after de-duplication), breaks every tie by input order, and
 * rounds the final coordinates.
 *
 * Nothing here recomputes analysis: positions are presentation only. Severity, confidence,
 * priority and basis are read straight from the server view model (CLAUDE.md rule 2).
 */

import dagre from "dagre";
import type { GraphEdge, GraphNode, TrustBoundaryView } from "@/shared/viewModel";

/** Must match the rendered node box in ArchitectureGraph.tsx, or edges will not meet it. */
export const NODE_WIDTH = 220;
export const NODE_HEIGHT = 76;

/** Room a boundary group leaves around its children, and above them for its label. */
export const GROUP_PADDING = 20;
export const GROUP_LABEL_HEIGHT = 28;

export type BoundaryAssignment = {
  /** Component id -> the one boundary it is drawn inside. Absent: top-level. */
  boundaryOf: Map<string, string>;
  /** Boundaries that received at least one of `nodeIds`, in the model's order. */
  used: TrustBoundaryView[];
  /** One line per extra boundary membership that could not be drawn. */
  notes: string[];
};

/**
 * Which boundary each component is drawn inside. A group node can hold a child only
 * once, so a component the model put in two boundaries goes in the first that lists it,
 * and every later membership becomes a note. Only ids in `nodeIds` count, so a boundary
 * whose members are all off the current view is not drawn. Pure and order-preserving.
 */
export function assignBoundaries(
  boundaries: readonly TrustBoundaryView[],
  nodes: readonly Pick<GraphNode, "id" | "label">[],
): BoundaryAssignment {
  const labels = new Map(nodes.map((node) => [node.id, node.label]));
  const boundaryOf = new Map<string, string>();
  const names = new Map<string, string>();
  const notes: string[] = [];
  for (const boundary of Array.isArray(boundaries) ? boundaries : []) {
    names.set(boundary.id, boundary.name);
    for (const id of new Set<string>(boundary.componentIds ?? [])) {
      if (!labels.has(id)) continue;
      const first = boundaryOf.get(id);
      if (first === undefined) {
        boundaryOf.set(id, boundary.id);
      } else if (first !== boundary.id) {
        notes.push(
          `${labels.get(id)} is also in the trust boundary "${boundary.name}"; it is drawn inside "${names.get(first)}".`,
        );
      }
    }
  }
  const usedIds = new Set(boundaryOf.values());
  return {
    boundaryOf,
    used: (Array.isArray(boundaries) ? boundaries : []).filter((b) => usedIds.has(b.id)),
    notes,
  };
}

export type LayoutOptions = {
  nodeWidth?: number;
  nodeHeight?: number;
  /** Left-to-right by default, matching the fixed type columns. */
  rankdir?: "TB" | "LR" | "BT" | "RL";
  /** Gap between nodes in the same rank. */
  nodesep?: number;
  /** Gap between ranks. */
  ranksep?: number;
  /** Trust boundaries to draw as groups around their components. */
  boundaries?: readonly TrustBoundaryView[];
};

export type PositionedNode = GraphNode & {
  /** Absolute, top-left. */
  position: { x: number; y: number };
  width: number;
  height: number;
  /** The boundary group it is drawn inside, or null when top-level. */
  boundaryId: string | null;
};

export type PositionedGroup = {
  id: string;
  label: string;
  /** Absolute, top-left. */
  position: { x: number; y: number };
  width: number;
  height: number;
  childIds: string[];
};

export type LayoutResult = {
  /** Input order is preserved, so the server's node ordering survives layout. */
  nodes: PositionedNode[];
  /** One per boundary with at least one child, in the model's order. */
  groups: PositionedGroup[];
  /** Extra boundary memberships that could not be drawn (see assignBoundaries). */
  notes: string[];
  /** Only edges whose endpoints both exist; a dangling edge is dropped, not crashed on. */
  edges: GraphEdge[];
  width: number;
  height: number;
};

const DEFAULTS = {
  rankdir: "LR",
  /** Vertical gap between components in one column. */
  nodesep: 48,
  /** Horizontal gap between columns: room for an edge label between them. */
  ranksep: 170,
  /** Vertical gap between boundary bands. */
  bandsep: 40,
  marginx: 24,
  marginy: 24,
} as const;

/**
 * The fixed column of each component type, left to right. A type not listed (worker,
 * queue, or a value added to the schema later) goes with the backends.
 */
export const COLUMN_OF_TYPE: Readonly<Record<string, number>> = {
  actor: 0,
  frontend: 1,
  api: 2,
  backend: 2,
  database: 3,
  storage: 3,
  external_service: 4,
  auth_provider: 4,
};
const DEFAULT_COLUMN = 2;

export function columnOf(type: string): number {
  return COLUMN_OF_TYPE[type] ?? DEFAULT_COLUMN;
}

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

  const assignment = assignBoundaries(options.boundaries ?? [], laidOut);
  const order = dagreOrder(laidOut, validEdges, assignment, options, nodeWidth, nodeHeight);
  const nodesep = options.nodesep ?? DEFAULTS.nodesep;
  const ranksep = options.ranksep ?? DEFAULTS.ranksep;

  // Only columns someone occupies are drawn, so an app with no actor does not start with
  // an empty column; the left-to-right order of the columns is unchanged.
  const columns = [...new Set(laidOut.map((node) => columnOf(node.type)))].sort((a, b) => a - b);
  const xOfColumn = new Map(
    columns.map((column, index) => [
      column,
      DEFAULTS.marginx + GROUP_PADDING + index * (nodeWidth + ranksep),
    ]),
  );

  // Bands: one per used boundary, in the model's order, then one for top-level nodes.
  const inputIndex = new Map(laidOut.map((node, index) => [node.id, index]));
  const bands: { boundaryId: string | null; members: GraphNode[] }[] = [
    ...assignment.used.map((boundary) => ({
      boundaryId: boundary.id as string | null,
      members: laidOut.filter((node) => assignment.boundaryOf.get(node.id) === boundary.id),
    })),
    { boundaryId: null, members: laidOut.filter((node) => !assignment.boundaryOf.has(node.id)) },
  ].filter((band) => band.members.length > 0);
  // A band's place follows dagre's ordering of its members, so connected groups sit near
  // each other; ties go to the model's order.
  const bandKey = (band: (typeof bands)[number]) =>
    Math.min(...band.members.map((node) => order.get(node.id) ?? 0));
  const ordered = bands
    .map((band, index) => ({ band, index }))
    .sort((a, b) => bandKey(a.band) - bandKey(b.band) || a.index - b.index)
    .map(({ band }) => band);

  const position = new Map<string, { x: number; y: number }>();
  let top = DEFAULTS.marginy;
  for (const band of ordered) {
    const grouped = band.boundaryId !== null;
    const inner = top + (grouped ? GROUP_PADDING + GROUP_LABEL_HEIGHT : 0);
    let rows = 0;
    for (const column of columns) {
      const inColumn = band.members
        .filter((node) => columnOf(node.type) === column)
        .sort(
          (a, b) =>
            (order.get(a.id) ?? 0) - (order.get(b.id) ?? 0) ||
            (inputIndex.get(a.id) ?? 0) - (inputIndex.get(b.id) ?? 0),
        );
      inColumn.forEach((node, row) => {
        position.set(node.id, {
          x: xOfColumn.get(column) ?? 0,
          y: inner + row * (nodeHeight + nodesep),
        });
      });
      rows = Math.max(rows, inColumn.length);
    }
    const content = rows * nodeHeight + (rows - 1) * nodesep;
    top += content + (grouped ? 2 * GROUP_PADDING + GROUP_LABEL_HEIGHT : 0) + DEFAULTS.bandsep;
  }

  const positioned: PositionedNode[] = laidOut.map((node) => ({
    ...node,
    position: { ...(position.get(node.id) ?? { x: 0, y: 0 }) },
    width: nodeWidth,
    height: nodeHeight,
    boundaryId: assignment.boundaryOf.get(node.id) ?? null,
  }));

  const groups = assignment.used.map((boundary) => groupAround(boundary, positioned));
  const right = Math.max(
    0,
    ...positioned.map((n) => n.position.x + n.width),
    ...groups.map((g) => g.position.x + g.width),
  );
  const bottom = Math.max(
    0,
    ...positioned.map((n) => n.position.y + n.height),
    ...groups.map((g) => g.position.y + g.height),
  );

  return {
    nodes: positioned,
    groups,
    notes: assignment.notes,
    edges: validEdges.map((edge) => ({ ...edge })),
    width: positioned.length ? Math.round(right + DEFAULTS.marginx) : 0,
    height: positioned.length ? Math.round(bottom + DEFAULTS.marginy) : 0,
  };
}

/**
 * dagre's placement, reduced to one number per node: its order within a rank (rankdir LR
 * puts that order on the y axis). Boundaries are compound nodes, so dagre keeps each
 * group's members together while it minimises crossings.
 */
function dagreOrder(
  nodes: readonly GraphNode[],
  edges: readonly GraphEdge[],
  assignment: BoundaryAssignment,
  options: LayoutOptions,
  nodeWidth: number,
  nodeHeight: number,
): Map<string, number> {
  const graph = new dagre.graphlib.Graph({ directed: true, multigraph: true, compound: true });
  graph.setGraph({
    rankdir: options.rankdir ?? DEFAULTS.rankdir,
    nodesep: options.nodesep ?? DEFAULTS.nodesep,
    ranksep: options.ranksep ?? DEFAULTS.ranksep,
    marginx: DEFAULTS.marginx,
    marginy: DEFAULTS.marginy,
  });
  graph.setDefaultEdgeLabel(() => ({}));

  // A cluster id cannot collide with a component id: component ids are kebab-case.
  const clusterId = (id: string) => `cluster:${id}`;
  for (const boundary of assignment.used) graph.setNode(clusterId(boundary.id), {});
  for (const node of nodes) {
    graph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
    const boundaryId = assignment.boundaryOf.get(node.id);
    if (boundaryId !== undefined) graph.setParent(node.id, clusterId(boundaryId));
  }
  for (const edge of edges) {
    // The edge id is passed as dagre's `name` so two flows between the same pair of
    // components stay distinct instead of collapsing into one.
    graph.setEdge(edge.source, edge.target, {}, edge.id);
  }

  dagre.layout(graph);

  const order = new Map<string, number>();
  for (const node of nodes) {
    const placed: unknown = graph.node(node.id);
    order.set(node.id, isRecord(placed) ? finiteOr(placed.y, 0) : 0);
  }
  return order;
}

/** A boundary's box: its children's bounding box, padded, with room for the label on top. */
function groupAround(boundary: TrustBoundaryView, nodes: readonly PositionedNode[]): PositionedGroup {
  const children = nodes.filter((node) => node.boundaryId === boundary.id);
  const left = Math.min(...children.map((n) => n.position.x)) - GROUP_PADDING;
  const top = Math.min(...children.map((n) => n.position.y)) - GROUP_PADDING - GROUP_LABEL_HEIGHT;
  const right = Math.max(...children.map((n) => n.position.x + n.width)) + GROUP_PADDING;
  const bottom = Math.max(...children.map((n) => n.position.y + n.height)) + GROUP_PADDING;
  return {
    id: boundary.id,
    label: boundary.name,
    position: { x: left, y: top },
    width: right - left,
    height: bottom - top,
    childIds: children.map((n) => n.id),
  };
}
