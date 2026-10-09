"use client";

/**
 * The architecture diagram's edge: React Flow's own bezier (or, for the reverse edge of an
 * opposite-direction pair, smoothstep) path, with two differences it cannot be given by
 * props. The label sits LABEL_FRACTION (35%) of the way from the source instead of at the
 * midpoint, so flows that fan out of one node do not stack their labels, and a wide
 * invisible path makes a thin line easy to hover.
 *
 * The label's position is measured from the rendered path (graphEdges.pointAlong); until
 * it is measured, or where SVG geometry is missing, it stays at the path's midpoint.
 * Everything else (stroke, marker, label text and background) arrives as ordinary edge
 * props from ArchitectureGraph; nothing here reads the model.
 */

import { useLayoutEffect, useRef, useState } from "react";
import {
  EdgeText,
  getBezierPath,
  getSmoothStepPath,
  type EdgeProps,
} from "reactflow";
import { LABEL_FRACTION, pointAlong } from "@/client/graphEdges";

export type FlowEdgeData = {
  /** The later edge of an opposite-direction pair: drawn as its own offset curve. */
  reverse?: boolean;
  /** Pixels that curve is pushed away from its partner (REVERSE_OFFSET). */
  offset?: number;
};

/** Width of the invisible hover target, in pixels. */
const HOVER_WIDTH = 18;

export default function FlowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  style,
  markerEnd,
  label,
  labelStyle,
  labelShowBg,
  labelBgStyle,
  labelBgPadding,
  labelBgBorderRadius,
}: EdgeProps<FlowEdgeData>) {
  const geometry = { sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition };
  const [path, midX, midY] = data?.reverse
    ? getSmoothStepPath({ ...geometry, offset: data.offset })
    : getBezierPath(geometry);

  const pathRef = useRef<SVGPathElement>(null);
  const [at, setAt] = useState<{ x: number; y: number } | null>(null);
  useLayoutEffect(() => {
    // The point can only be measured once the path is in the document.
    setAt(pointAlong(pathRef.current, LABEL_FRACTION, { x: midX, y: midY }));
  }, [path, midX, midY]);
  const point = at ?? { x: midX, y: midY };

  return (
    <>
      <path id={id} ref={pathRef} d={path} fill="none" className="react-flow__edge-path" style={style} markerEnd={markerEnd} />
      <path d={path} fill="none" strokeOpacity={0} strokeWidth={HOVER_WIDTH} className="react-flow__edge-interaction" />
      {label ? (
        <EdgeText
          x={point.x}
          y={point.y}
          label={label}
          labelStyle={labelStyle}
          labelShowBg={labelShowBg}
          labelBgStyle={labelBgStyle}
          labelBgPadding={labelBgPadding}
          labelBgBorderRadius={labelBgBorderRadius}
        />
      ) : null}
    </>
  );
}
