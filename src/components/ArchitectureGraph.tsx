"use client";

/**
 * The architecture diagram.
 *
 * Nodes and edges are the server's GraphNode/GraphEdge lists rendered as-is; the only
 * thing computed here is where to draw them, via the deterministic dagre pass in
 * src/client/layoutGraph.ts. Threat counts and max severity per node come from the view
 * model — this component never looks at the threat list to work them out.
 *
 * Highlighting is presentation state: when a threat is selected the parent passes that
 * threat's component ids as `highlightNodeIds` and its data-flow ids as
 * `highlightEdgeIds` (straight from the adapter), and everything else is dimmed. The two
 * stay separate because a flow may share an id with a component. Clicking a node reports
 * it back so the list can filter. Keyboard users get the same filtering from the
 * component buttons Dashboard renders beside the map and from the filter bar.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  Background,
  ControlButton,
  Controls,
  MarkerType,
  MiniMap,
  useReactFlow,
  useStore,
  type Edge,
  type Node,
} from "reactflow";
import "reactflow/dist/style.css";
import type { GraphEdge, GraphNode, TrustBoundaryView } from "@/shared/viewModel";
import { layoutGraph, NODE_HEIGHT, NODE_WIDTH } from "@/client/layoutGraph";
import {
  edgeColor,
  edgeMarker,
  edgeRoutes,
  edgeStrokeWidth,
  handlesFor,
  labelVisible,
  reverseEdgeShape,
  touchesNode,
} from "@/client/graphEdges";
import FlowEdge, { type FlowEdgeData } from "@/components/FlowEdge";
import { useFullscreen, type FullscreenMode } from "@/client/useFullscreen";
import ArchitectureNode, {
  BoundaryGroup,
  STUB_HEIGHT,
  STUB_WIDTH,
  type ArchitectureNodeData,
  type BoundaryGroupData,
} from "@/components/ArchitectureNode";

/**
 * The gap between type columns. Edge labels sit at edge midpoints between columns and
 * dagre reserves no room for them; 150 (up from the old 130 between ranks) keeps labels
 * apart while five columns still fit a laptop-width diagram at a readable zoom.
 */
const LAYOUT_OPTIONS = { ranksep: 150 } as const;

/** Unselected flow labels are clipped so they do not run into each other. */
const LABEL_MAX = 24;

function shortLabel(label: string | undefined, full: boolean): string | undefined {
  if (!label || full || label.length <= LABEL_MAX) return label;
  return `${label.slice(0, LABEL_MAX - 1).trimEnd()}\u2026`;
}

type ArchitectureGraphProps = {
  nodes: readonly GraphNode[];
  /**
   * Ids in `nodes` that are drawn as small greyed "outside this view" stubs instead of
   * components: top-level (in no boundary), not selectable, with no threat counts.
   */
  stubIds?: readonly string[];
  edges: readonly GraphEdge[];
  /** Shown instead of the diagram when there are no nodes; a default covers "no diagram". */
  emptyMessage?: string;
  /** Drawn as groups around their components; a component in none stays top-level. */
  boundaries?: readonly TrustBoundaryView[];
  /**
   * Component ids (nodes) and data-flow ids (edges) to emphasise. When both are empty
   * nothing is dimmed.
   */
  highlightNodeIds: readonly string[];
  highlightEdgeIds: readonly string[];
  selectedNodeId: string | null;
  onSelectNode: (id: string | null) => void;
  /** The unverified switch: nodes also count threats below 25% confidence. Display only. */
  includeUnverified?: boolean;
};

/** The fit the diagram gets on mount, reused after it changes size. */
const FIT_VIEW_OPTIONS = { padding: 0.15, maxZoom: 1 } as const;

/**
 * The full-screen button, inside Controls so it sits with the zoom buttons. It also refits
 * the diagram after entering and leaving full screen: React Flow keeps its zoom and pan
 * when its container changes size, so without this the diagram would sit in one corner.
 * The refit waits for the browser to finish resizing, which takes a few frames.
 */
function FullscreenButton({ mode, onToggle }: { mode: FullscreenMode; onToggle: () => void }) {
  const { fitView } = useReactFlow();
  // React Flow's own measure of its container: it changes once the browser has resized it.
  const width = useStore((state) => state.width);
  const height = useStore((state) => state.height);
  const previous = useRef<FullscreenMode>(mode);
  const pending = useRef(false);

  // The mode changed: refit as soon as the new size is known, or after 400 ms if it never
  // changes (the same size on both sides).
  useEffect(() => {
    if (previous.current === mode) return;
    previous.current = mode;
    pending.current = true;
    const timer = setTimeout(() => {
      if (!pending.current) return;
      pending.current = false;
      fitView(FIT_VIEW_OPTIONS);
    }, 400);
    return () => clearTimeout(timer);
  }, [mode, fitView]);
  useEffect(() => {
    if (!pending.current) return;
    // `pending` clears only when the refit runs, so a second size change that cancels this
    // frame schedules another instead of losing the refit.
    const frame = requestAnimationFrame(() => {
      pending.current = false;
      fitView(FIT_VIEW_OPTIONS);
    });
    return () => cancelAnimationFrame(frame);
  }, [width, height, fitView]);

  const full = mode !== "off";
  const label = full ? "Exit full screen" : "Enter full screen";
  return (
    <ControlButton onClick={onToggle} title={label} aria-label={label} aria-pressed={full}>
      <svg aria-hidden="true" viewBox="0 0 16 16" width={14} height={14} fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
        {full ? (
          <path d="M6 1.5v3.5a1 1 0 0 1-1 1H1.5M10 1.5v3.5a1 1 0 0 0 1 1h3.5M6 14.5V11a1 1 0 0 0-1-1H1.5M10 14.5V11a1 1 0 0 1 1-1h3.5" />
        ) : (
          <path d="M1.5 5.5v-3a1 1 0 0 1 1-1h3M10.5 1.5h3a1 1 0 0 1 1 1v3M14.5 10.5v3a1 1 0 0 1-1 1h-3M5.5 14.5h-3a1 1 0 0 1-1-1v-3" />
        )}
      </svg>
    </ControlButton>
  );
}

/** Defined once, outside render: React Flow warns when nodeTypes or edgeTypes change identity. */
const NODE_TYPES = { component: ArchitectureNode, boundary: BoundaryGroup };
const EDGE_TYPES = { flow: FlowEdge };

export default function ArchitectureGraph({
  nodes,
  stubIds = [],
  edges,
  emptyMessage,
  boundaries = [],
  highlightNodeIds,
  highlightEdgeIds,
  selectedNodeId,
  onSelectNode,
  includeUnverified = false,
}: ArchitectureGraphProps) {
  // Layout depends only on the graph itself, so it is not recomputed when the selection
  // changes — which also keeps node positions stable while a user clicks around.
  const stubs = useMemo(() => new Set(stubIds), [stubIds]);
  // A stub belongs to no boundary: it is only a marker for something outside this view.
  const layoutBoundaries = useMemo(
    () =>
      stubs.size === 0
        ? boundaries
        : boundaries.map((b) => ({ ...b, componentIds: b.componentIds.filter((id) => !stubs.has(id)) })),
    [boundaries, stubs],
  );
  const layout = useMemo(
    () => layoutGraph(nodes, edges, { ...LAYOUT_OPTIONS, boundaries: layoutBoundaries }),
    [nodes, edges, layoutBoundaries],
  );

  const highlightedNodes = useMemo(
    () => new Set(Array.isArray(highlightNodeIds) ? highlightNodeIds : []),
    [highlightNodeIds],
  );
  const highlightedEdges = useMemo(
    () => new Set(Array.isArray(highlightEdgeIds) ? highlightEdgeIds : []),
    [highlightEdgeIds],
  );
  const dimming = highlightedNodes.size > 0 || highlightedEdges.size > 0;
  const containerRef = useRef<HTMLDivElement>(null);
  const { mode: fullscreen, toggle: toggleFullscreen } = useFullscreen(containerRef);
  // The edge under the pointer: drawn thicker, labelled in full and brought to the front.
  const [hoveredEdgeId, setHoveredEdgeId] = useState<string | null>(null);

  const flowNodes = useMemo<Node<ArchitectureNodeData | BoundaryGroupData>[]>(() => {
    const groupAt = new Map(layout.groups.map((group) => [group.id, group.position]));
    // Groups first: React Flow needs a parent before its children.
    const groups: Node<BoundaryGroupData>[] = layout.groups.map((group) => ({
      id: `boundary:${group.id}`,
      type: "boundary",
      position: group.position,
      data: { label: group.label },
      style: { width: group.width, height: group.height, background: "transparent", border: 0, padding: 0 },
      selectable: false,
      draggable: false,
      focusable: false,
      zIndex: -1,
    }));
    const components: Node<ArchitectureNodeData>[] = layout.nodes.map((node) => {
        const stub = stubs.has(node.id);
        const on = !stub && highlightedNodes.has(node.id);
        const parent = node.boundaryId ? groupAt.get(node.boundaryId) : undefined;
        // A stub is smaller than the box the layout reserved; centre it on that box so the
        // flows to and from it meet the same line a full node's would.
        const slack = stub ? { x: 0, y: (NODE_HEIGHT - STUB_HEIGHT) / 2 } : { x: 0, y: 0 };
        return {
          id: node.id,
          type: "component",
          // A child is positioned relative to its group.
          position: parent
            ? { x: node.position.x - parent.x, y: node.position.y - parent.y + slack.y }
            : { x: node.position.x, y: node.position.y + slack.y },
          selectable: !stub,
          ...(parent ? { parentNode: `boundary:${node.boundaryId}` } : {}),
          data: {
            node,
            stub,
            on,
            selected: !stub && selectedNodeId === node.id,
            dimmed: dimming && !on,
            includeUnverified,
          },
          // The custom node draws its own outline; the wrapper adds no box of its own.
          style: {
            width: stub ? STUB_WIDTH : NODE_WIDTH,
            height: stub ? STUB_HEIGHT : NODE_HEIGHT,
            background: "transparent",
            border: 0,
            padding: 0,
          },
        };
      });
    return [...groups, ...components];
  }, [layout.nodes, layout.groups, highlightedNodes, dimming, selectedNodeId, includeUnverified, stubs]);

  const routes = useMemo(() => edgeRoutes(layout.edges), [layout.edges]);
  const xOf = useMemo(
    () => new Map(layout.nodes.map((node) => [node.id, node.position.x])),
    [layout.nodes],
  );

  const flowEdges = useMemo<Edge[]>(
    () =>
      layout.edges.map((edge, index) => {
        const on = highlightedEdges.has(edge.id);
        const hovered = hoveredEdgeId === edge.id;
        // Labels are the clutter on a big diagram: past LABEL_EDGE_LIMIT flows only the
        // ones the reader points at or selects keep theirs.
        const labelled = labelVisible({
          edgeCount: layout.edges.length,
          on,
          hovered,
          touchesSelected: touchesNode(edge, selectedNodeId),
        });
        const route = reverseEdgeShape(routes[index]);
        return {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          ...handlesFor(xOf.get(edge.source) ?? 0, xOf.get(edge.target) ?? 0),
          type: "flow",
          data: { reverse: routes[index].reverse, offset: route.pathOptions?.offset } satisfies FlowEdgeData,
          // Every flow points the way its data moves, dotted crossings included.
          markerEnd: { ...edgeMarker(edge, { on, dimming }), type: MarkerType.ArrowClosed },
          label: labelled ? shortLabel(edge.label, on || hovered) : undefined,
          animated: edge.crossesTrustBoundary,
          zIndex: hovered ? 1000 : on ? 500 : 0,
          labelShowBg: true,
          labelStyle: {
            fill: on || hovered ? "var(--color-fg)" : "var(--color-muted)",
            fontSize: 10,
            fontWeight: on || hovered ? 600 : 500,
            opacity: dimming && !on && !hovered ? 0.6 : 1,
          },
          // Opaque, so a label never lets the line behind it show through its text. Only
          // the text fades when something else is highlighted.
          labelBgStyle: {
            fill: on || hovered ? "var(--color-mint-deep)" : "var(--color-surface)",
            fillOpacity: 1,
            stroke: "var(--color-line-strong)",
            strokeWidth: 1,
          },
          labelBgPadding: [8, 5] as [number, number],
          labelBgBorderRadius: 8,
          style: {
            // A trust-boundary crossing is drawn heavier because it is where most
            // threats live; the flag itself comes from the model, not from us.
            strokeWidth: edgeStrokeWidth(edge, { on, hovered }),
            stroke: edgeColor(edge, on || hovered),
            opacity: dimming && !on && !hovered ? 0.25 : 1,
          },
        } as Edge;
      }),
    [layout.edges, routes, xOf, highlightedEdges, dimming, hoveredEdgeId, selectedNodeId],
  );

  if (layout.nodes.length === 0) {
    return (
      <p className="rounded-2xl border border-dashed border-line-strong p-8 text-center text-sm text-muted">
        {emptyMessage ?? "This analysis did not produce an architecture diagram."}
      </p>
    );
  }

  return (
    <div
      ref={containerRef}
      data-fullscreen={fullscreen}
      // Native full screen sizes this element to the screen; the overlay does the same by hand.
      className={
        fullscreen === "off"
          ? "h-[380px] w-full overflow-hidden rounded-2xl border border-line bg-surface sm:h-[560px]"
          : `h-screen w-screen overflow-hidden bg-surface ${fullscreen === "overlay" ? "fixed inset-0 z-[100]" : ""}`
      }
      aria-label="Architecture diagram"
      role="group"
    >
      <ReactFlow
        // fitView runs only when React Flow mounts, so a new node set (a sub-view) remounts
        // it to fit the diagram that is now shown.
        key={layout.nodes.map((node) => node.id).join("|")}
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={NODE_TYPES}
        edgeTypes={EDGE_TYPES}
        onEdgeMouseEnter={(_event, edge) => setHoveredEdgeId(edge.id)}
        onEdgeMouseLeave={() => setHoveredEdgeId(null)}
        onNodeClick={(_event, node) => {
          // A stub is only a marker for something outside this view: nothing to select.
          if (node.type === "component" && !stubs.has(node.id)) onSelectNode(node.id);
        }}
        onPaneClick={() => onSelectNode(null)}
        fitView
        fitViewOptions={FIT_VIEW_OPTIONS}
        minZoom={0.2}
        // The wheel scrolls the page, not the diagram: the map sits mid-page, and hijacking
        // the wheel there traps people reading the results. Zoom with the controls or pinch.
        zoomOnScroll={false}
        preventScrolling={false}
        nodesDraggable={false}
        nodesConnectable={false}
        edgesFocusable={false}
        proOptions={{ hideAttribution: false }}
      >
        <Background color="var(--color-line-strong)" gap={18} size={1} />
        <Controls showInteractive={false}>
          <FullscreenButton mode={fullscreen} onToggle={toggleFullscreen} />
        </Controls>
        <MiniMap
          pannable
          zoomable
          nodeColor="var(--color-surface-3)"
          nodeStrokeColor="var(--color-mint)"
          nodeBorderRadius={4}
          maskColor="rgba(243, 237, 221, 0.7)"
          style={{ width: 150, height: 96, background: "var(--color-surface)" }}
          className="!hidden xl:!block"
        />
      </ReactFlow>
    </div>
  );
}
