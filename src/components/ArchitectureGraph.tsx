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

import { useMemo } from "react";
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  type Edge,
  type Node,
} from "reactflow";
import "reactflow/dist/style.css";
import type { GraphEdge, GraphNode, TrustBoundaryView } from "@/shared/viewModel";
import { layoutGraph, NODE_HEIGHT, NODE_WIDTH } from "@/client/layoutGraph";
import { edgeColor, edgeMarker, edgeRoutes, reverseEdgeShape } from "@/client/graphEdges";
import ArchitectureNode, {
  BoundaryGroup,
  type ArchitectureNodeData,
  type BoundaryGroupData,
} from "@/components/ArchitectureNode";

/**
 * Wider than layoutGraph's defaults: edge labels sit at edge midpoints, and dagre does not
 * reserve room for them, so the extra gap is what keeps neighbouring labels apart.
 */
const LAYOUT_OPTIONS = { nodesep: 120, ranksep: 130 } as const;

/** Unselected flow labels are clipped so they do not run into each other. */
const LABEL_MAX = 24;

function shortLabel(label: string | undefined, full: boolean): string | undefined {
  if (!label || full || label.length <= LABEL_MAX) return label;
  return `${label.slice(0, LABEL_MAX - 1).trimEnd()}\u2026`;
}

type ArchitectureGraphProps = {
  nodes: readonly GraphNode[];
  edges: readonly GraphEdge[];
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
};

/** Defined once, outside render: React Flow warns when nodeTypes changes identity. */
const NODE_TYPES = { component: ArchitectureNode, boundary: BoundaryGroup };

export default function ArchitectureGraph({
  nodes,
  edges,
  boundaries = [],
  highlightNodeIds,
  highlightEdgeIds,
  selectedNodeId,
  onSelectNode,
}: ArchitectureGraphProps) {
  // Layout depends only on the graph itself, so it is not recomputed when the selection
  // changes — which also keeps node positions stable while a user clicks around.
  const layout = useMemo(
    () => layoutGraph(nodes, edges, { ...LAYOUT_OPTIONS, boundaries }),
    [nodes, edges, boundaries],
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
        const on = highlightedNodes.has(node.id);
        const parent = node.boundaryId ? groupAt.get(node.boundaryId) : undefined;
        return {
          id: node.id,
          type: "component",
          // A child is positioned relative to its group.
          position: parent
            ? { x: node.position.x - parent.x, y: node.position.y - parent.y }
            : node.position,
          ...(parent ? { parentNode: `boundary:${node.boundaryId}` } : {}),
          data: { node, on, selected: selectedNodeId === node.id, dimmed: dimming && !on },
          // The custom node draws its own outline; the wrapper adds no box of its own.
          style: { width: NODE_WIDTH, height: NODE_HEIGHT, background: "transparent", border: 0, padding: 0 },
        };
      });
    return [...groups, ...components];
  }, [layout.nodes, layout.groups, highlightedNodes, dimming, selectedNodeId]);

  const routes = useMemo(() => edgeRoutes(layout.edges), [layout.edges]);

  const flowEdges = useMemo<Edge[]>(
    () =>
      layout.edges.map((edge, index) => {
        const on = highlightedEdges.has(edge.id);
        return {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          // Every flow points the way its data moves, dotted crossings included.
          markerEnd: { ...edgeMarker(edge, { on, dimming }), type: MarkerType.ArrowClosed },
          ...reverseEdgeShape(routes[index]),
          label: shortLabel(edge.label, on),
          animated: edge.crossesTrustBoundary,
          labelShowBg: true,
          labelStyle: {
            fill: on ? "var(--color-fg)" : "var(--color-muted)",
            fontSize: 10,
            fontWeight: on ? 600 : 500,
            opacity: dimming && !on ? 0.35 : 1,
          },
          labelBgStyle: {
            fill: on ? "var(--color-mint-deep)" : "var(--color-surface)",
            stroke: "var(--color-line)",
            strokeWidth: 1,
            opacity: dimming && !on ? 0.35 : 1,
          },
          labelBgPadding: [7, 4] as [number, number],
          labelBgBorderRadius: 7,
          style: {
            // A trust-boundary crossing is drawn heavier because it is where most
            // threats live; the flag itself comes from the model, not from us.
            strokeWidth: on ? 3 : edge.crossesTrustBoundary ? 2 : 1.5,
            stroke: edgeColor(edge, on),
            opacity: dimming && !on ? 0.25 : 1,
          },
        } as Edge;
      }),
    [layout.edges, routes, highlightedEdges, dimming],
  );

  if (layout.nodes.length === 0) {
    return (
      <p className="rounded-2xl border border-dashed border-line-strong p-8 text-center text-sm text-muted">
        This analysis did not produce an architecture diagram.
      </p>
    );
  }

  return (
    <div
      className="h-[380px] w-full overflow-hidden rounded-2xl border border-line bg-surface sm:h-[520px]"
      aria-label="Architecture diagram"
      role="group"
    >
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={NODE_TYPES}
        onNodeClick={(_event, node) => {
          if (node.type === "component") onSelectNode(node.id);
        }}
        onPaneClick={() => onSelectNode(null)}
        fitView
        fitViewOptions={{ padding: 0.15 }}
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
        <Controls showInteractive={false} />
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
