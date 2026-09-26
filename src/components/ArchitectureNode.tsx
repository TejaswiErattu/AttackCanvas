"use client";

/**
 * The custom React Flow node for one architecture component.
 *
 * Each ComponentType gets its own outline and icon, both inline SVG so no icon package is
 * needed: an actor is a pill with a person, a frontend a browser window, backend and api a
 * rounded box, a database a cylinder, storage a bucket, an external service a cloud, an
 * auth provider a shield-cornered badge with a shield, and any other type (worker, queue,
 * or a value added later) a plain square-cornered box.
 *
 * What the old box node showed is kept: the severity accent (a bar down the left, in the
 * colour of the node's worst threat), the mint outline when highlighted or selected, and
 * the dimming when something else is highlighted. Nothing here computes a severity; it is
 * read from the view model (CLAUDE.md rule 2).
 *
 * The shape and icon tables are plain data and NodeShape/TypeIcon need no React Flow
 * context, so they are unit tested in jsdom; only ArchitectureNode itself uses Handle.
 */

import { memo } from "react";
import { Handle, Position, type NodeProps } from "reactflow";
import type { ComponentType, Severity } from "@/shared/schema";
import type { GraphNode } from "@/shared/viewModel";
import { NODE_HEIGHT, NODE_WIDTH } from "@/client/layoutGraph";
import { SEVERITY_ACCENT, SEVERITY_TEXT } from "@/components/SeveritySummary";

export const COMPONENT_TYPE_TEXT: Record<ComponentType, string> = {
  actor: "Actor",
  frontend: "Frontend",
  backend: "Backend",
  api: "API",
  database: "Database",
  storage: "Storage",
  external_service: "External service",
  auth_provider: "Auth provider",
  worker: "Worker",
  queue: "Queue",
};

export type ShapeKind =
  | "person"
  | "browser"
  | "rounded"
  | "cylinder"
  | "bucket"
  | "cloud"
  | "shield"
  | "neutral";

/** The outline for each type. Anything not listed, now or later, is the neutral box. */
const SHAPES: Partial<Record<string, ShapeKind>> = {
  actor: "person",
  frontend: "browser",
  backend: "rounded",
  api: "rounded",
  database: "cylinder",
  storage: "bucket",
  external_service: "cloud",
  auth_provider: "shield",
};

export function shapeOf(type: string): ShapeKind {
  return SHAPES[type] ?? "neutral";
}

/** A display label for a type, falling back to the raw value for an unknown one. */
export function typeText(type: string): string {
  return COMPONENT_TYPE_TEXT[type as ComponentType] ?? type.replace(/_/g, " ");
}

const NEUTRAL_ACCENT = "var(--color-line-strong)";

export function accentFor(severity: Severity | null): string {
  return severity ? (SEVERITY_ACCENT[severity] ?? NEUTRAL_ACCENT) : NEUTRAL_ACCENT;
}

// ---------------------------------------------------------------------------
// Outlines
// ---------------------------------------------------------------------------

/** SVG path data for an outline of width w and height h, inset by the stroke. */
function outlinePath(shape: ShapeKind, w: number, h: number): string {
  const i = 1.5;
  const r = (x0: number, y0: number, x1: number, y1: number, rad: number) =>
    `M${x0 + rad},${y0} H${x1 - rad} Q${x1},${y0} ${x1},${y0 + rad} V${y1 - rad} Q${x1},${y1} ${x1 - rad},${y1} H${x0 + rad} Q${x0},${y1} ${x0},${y1 - rad} V${y0 + rad} Q${x0},${y0} ${x0 + rad},${y0} Z`;
  switch (shape) {
    case "person":
      return r(i, i, w - i, h - i, (h - 2 * i) / 2);
    case "browser":
    case "rounded":
      return r(i, i, w - i, h - i, 12);
    case "neutral":
      return r(i, i, w - i, h - i, 3);
    case "cylinder": {
      const ry = 8;
      return `M${i},${i + ry} A${w / 2 - i},${ry} 0 0 1 ${w - i},${i + ry} V${h - i - ry} A${w / 2 - i},${ry} 0 0 1 ${i},${h - i - ry} Z`;
    }
    case "bucket": {
      const ry = 6;
      const taper = 14;
      return `M${i},${i + ry} A${w / 2 - i},${ry} 0 0 1 ${w - i},${i + ry} L${w - i - taper},${h - i - 4} Q${w - i - taper},${h - i} ${w - i - taper - 4},${h - i} H${i + taper + 4} Q${i + taper},${h - i} ${i + taper},${h - i - 4} Z`;
    }
    case "cloud":
      return `M${28},${h - i} C${6},${h - i} ${i},${h - 20} ${14},${h - 34} C${4},${20} ${26},${6} ${48},${16} C${62},${i} ${98},${i} ${112},${14} C${130},${i} ${168},${i} ${176},${18} C${204},${14} ${w - i},${34} ${w - 12},${50} C${w - i},${60} ${w - 14},${h - i} ${w - 34},${h - i} Z`;
    case "shield": {
      const c = 14;
      return `M${i + c},${i} H${w - i - c} L${w - i},${i + c} V${h - i - c} L${w - i - c},${h - i} H${i + c} L${i},${h - i - c} V${i + c} Z`;
    }
  }
}

/** Extra strokes drawn inside an outline: the browser's title bar, the cylinder's rim. */
function outlineDetail(shape: ShapeKind, w: number): string | null {
  switch (shape) {
    case "browser":
      return `M1.5,16 H${w - 1.5}`;
    case "cylinder":
      return `M1.5,9.5 A${w / 2 - 1.5},8 0 0 0 ${w - 1.5},9.5`;
    case "bucket":
      return `M1.5,7.5 A${w / 2 - 1.5},6 0 0 0 ${w - 1.5},7.5`;
    default:
      return null;
  }
}

export function NodeShape({
  shape,
  width,
  height,
  fill,
  stroke,
  strokeWidth,
}: {
  shape: ShapeKind;
  width: number;
  height: number;
  fill: string;
  stroke: string;
  strokeWidth: number;
}) {
  const detail = outlineDetail(shape, width);
  return (
    <svg
      aria-hidden="true"
      data-shape={shape}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="pointer-events-none absolute inset-0 overflow-visible"
    >
      <path d={outlinePath(shape, width, height)} fill={fill} stroke={stroke} strokeWidth={strokeWidth} />
      {detail ? <path d={detail} fill="none" stroke={stroke} strokeWidth={1} /> : null}
      {shape === "browser"
        ? [10, 18, 26].map((cx) => <circle key={cx} cx={cx} cy={8.5} r={2} fill={stroke} />)
        : null}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Icons, 16x16, stroke only so they take the current text colour
// ---------------------------------------------------------------------------

const ICON_PATHS: Record<ShapeKind, string[]> = {
  person: ["M8 7.2a2.6 2.6 0 1 0 0-5.2 2.6 2.6 0 0 0 0 5.2Z", "M2.8 14c.5-2.9 2.6-4.4 5.2-4.4s4.7 1.5 5.2 4.4"],
  browser: ["M1.8 3h12.4v10H1.8Z", "M1.8 6h12.4", "M3.8 4.5h.01M5.6 4.5h.01"],
  rounded: ["M2.5 3.5h11a1.5 1.5 0 0 1 1.5 1.5v6a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 1 11V5a1.5 1.5 0 0 1 1.5-1.5Z", "M4 8h.01M6.5 8h5"],
  cylinder: ["M2.5 3.8c0-1 2.5-1.8 5.5-1.8s5.5.8 5.5 1.8v8.4c0 1-2.5 1.8-5.5 1.8s-5.5-.8-5.5-1.8Z", "M2.5 3.8c0 1 2.5 1.8 5.5 1.8s5.5-.8 5.5-1.8", "M2.5 8c0 1 2.5 1.8 5.5 1.8s5.5-.8 5.5-1.8"],
  bucket: ["M2 4.2c0-.9 2.7-1.6 6-1.6s6 .7 6 1.6l-1.5 8.6c-.2.8-2.2 1.2-4.5 1.2s-4.3-.4-4.5-1.2Z", "M2 4.2c0 .9 2.7 1.6 6 1.6s6-.7 6-1.6"],
  cloud: ["M4.5 12.5h7.2a3 3 0 0 0 .4-6 4 4 0 0 0-7.7-.9A3.4 3.4 0 0 0 4.5 12.5Z"],
  shield: ["M8 1.8 13.2 3.7v4c0 3.3-2.3 5.6-5.2 6.6-2.9-1-5.2-3.3-5.2-6.6v-4Z", "M5.8 8.1l1.6 1.6 2.9-3.2"],
  neutral: ["M2.5 2.5h11v11h-11Z"],
};

export function TypeIcon({ shape, className = "" }: { shape: ShapeKind; className?: string }) {
  return (
    <svg
      aria-hidden="true"
      data-icon={shape}
      viewBox="0 0 16 16"
      width={16}
      height={16}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.4}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      {ICON_PATHS[shape].map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------

export type ArchitectureNodeData = {
  node: GraphNode;
  /** Highlighted by the current selection. */
  on: boolean;
  selected: boolean;
  /** Something is highlighted and this node is not. */
  dimmed: boolean;
};

/** Handles are needed for edges to attach; they are invisible and not connectable. */
const HIDDEN_HANDLE = { opacity: 0, width: 6, height: 6, border: 0, pointerEvents: "none" } as const;

export function NodeContent({ data }: { data: ArchitectureNodeData }) {
  const { node, on, selected, dimmed } = data;
  const shape = shapeOf(node.type);
  const severity = node.maxSeverity;
  const outlined = selected || on;
  // The browser's title bar and the database/bucket rims take room at the top.
  const topPad = shape === "browser" ? 18 : shape === "cylinder" || shape === "bucket" ? 14 : 8;
  const sidePad = shape === "cloud" ? 30 : shape === "person" ? 24 : 16;

  return (
    <div
      className="relative"
      style={{ width: NODE_WIDTH, height: NODE_HEIGHT, opacity: dimmed ? 0.3 : 1 }}
      data-component-type={node.type}
    >
      <NodeShape
        shape={shape}
        width={NODE_WIDTH}
        height={NODE_HEIGHT}
        fill={selected ? "var(--color-mint-deep)" : "var(--color-surface)"}
        stroke={outlined ? "var(--color-mint)" : "var(--color-line-strong)"}
        strokeWidth={outlined ? 2 : 1.2}
      />
      <span
        aria-hidden="true"
        className="absolute rounded-full"
        style={{
          left: sidePad - 9,
          top: topPad + 4,
          bottom: 10,
          width: 4,
          background: accentFor(severity),
        }}
      />
      <div
        className="relative flex h-full items-start gap-2 text-left"
        style={{ paddingTop: topPad, paddingLeft: sidePad, paddingRight: sidePad - 4 }}
      >
        <TypeIcon shape={shape} className="mt-0.5 shrink-0 text-muted" />
        <div className="min-w-0 flex-1">
          <div className="truncate font-display text-sm font-semibold text-fg">{node.label}</div>
          <div className="mt-0.5 truncate text-[10px] uppercase tracking-wider text-subtle">
            {typeText(node.type)}
          </div>
          <div className="mt-0.5 truncate text-[11px] text-muted">
            {node.threatCount} threat{node.threatCount === 1 ? "" : "s"}
            {severity ? ` · ${SEVERITY_TEXT[severity] ?? severity} max` : ""}
          </div>
        </div>
      </div>
    </div>
  );
}

function ArchitectureNode({ data }: NodeProps<ArchitectureNodeData>) {
  return (
    <>
      <Handle id="in" type="target" position={Position.Top} isConnectable={false} style={HIDDEN_HANDLE} />
      <NodeContent data={data} />
      <Handle id="out" type="source" position={Position.Bottom} isConnectable={false} style={HIDDEN_HANDLE} />
    </>
  );
}

export default memo(ArchitectureNode);

// ---------------------------------------------------------------------------
// Trust boundary group
// ---------------------------------------------------------------------------

export type BoundaryGroupData = { label: string };

/**
 * A trust boundary drawn behind its components: dashed outline, tinted background and
 * its name in the top-left corner. Not selectable; clicks fall through to the canvas.
 */
function BoundaryGroupNode({ data }: NodeProps<BoundaryGroupData>) {
  return (
    <div
      className="pointer-events-none h-full w-full rounded-2xl border-2 border-dashed border-boundary/60 bg-boundary/[0.06]"
      data-boundary-group=""
    >
      <span className="absolute left-3 top-2 rounded-full bg-surface/90 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.12em] text-boundary">
        {data.label}
      </span>
    </div>
  );
}

export const BoundaryGroup = memo(BoundaryGroupNode);
