import { describe, expect, it } from "vitest";
import {
  ARROW_CLOSED,
  HANDLES,
  LABEL_EDGE_LIMIT,
  LABEL_FRACTION,
  edgeMarker,
  edgeRoutes,
  edgeStrokeWidth,
  handlesFor,
  labelVisible,
  pointAlong,
  reverseEdgeShape,
  touchesNode,
} from "@/client/graphEdges";

const e = (id: string, source: string, target: string) => ({ id, source, target });

describe("edgeRoutes", () => {
  it("marks only the later edge of an opposite-direction pair as reverse", () => {
    expect(edgeRoutes([e("a-b", "a", "b"), e("b-a", "b", "a"), e("b-c", "b", "c")])).toEqual([
      { id: "a-b", reverse: false },
      { id: "b-a", reverse: true },
      { id: "b-c", reverse: false },
    ]);
  });

  it("does not treat two flows in the same direction as a pair", () => {
    expect(edgeRoutes([e("x", "a", "b"), e("y", "a", "b")]).every((r) => !r.reverse)).toBe(true);
  });

  it("draws the reverse edge as its own offset curve, and leaves the forward one alone", () => {
    const [forward, back] = edgeRoutes([e("a-b", "a", "b"), e("b-a", "b", "a")]);
    expect(reverseEdgeShape(forward)).toEqual({});
    expect(reverseEdgeShape(back).type).toBe("smoothstep");
    expect(reverseEdgeShape(back).pathOptions?.offset).toBeGreaterThan(0);
  });
});

describe("edgeMarker", () => {
  it("puts an arrowhead on a trust-boundary crossing and on an internal flow alike", () => {
    for (const crossesTrustBoundary of [true, false]) {
      expect(edgeMarker({ crossesTrustBoundary }, { on: false, dimming: false }).type).toBe(ARROW_CLOSED);
    }
  });

  it("colours the arrowhead like the stroke", () => {
    expect(edgeMarker({ crossesTrustBoundary: true }, { on: false, dimming: false }).color).toBe("var(--color-boundary)");
    expect(edgeMarker({ crossesTrustBoundary: false }, { on: true, dimming: false }).color).toBe("var(--color-mint)");
  });
});

describe("handlesFor", () => {
  it("uses right-out/left-in for a left-to-right or same-column flow", () => {
    expect(handlesFor(0, 400)).toEqual({ sourceHandle: HANDLES.out, targetHandle: HANDLES.in });
    expect(handlesFor(400, 400)).toEqual({ sourceHandle: HANDLES.out, targetHandle: HANDLES.in });
  });

  it("uses left-out/right-in for a flow that runs right to left", () => {
    expect(handlesFor(800, 400)).toEqual({ sourceHandle: HANDLES.outLeft, targetHandle: HANDLES.inRight });
  });
});

describe("labelVisible", () => {
  const calm = { on: false, hovered: false, touchesSelected: false };

  it("labels every edge of a diagram with up to 12 flows", () => {
    expect(LABEL_EDGE_LIMIT).toBe(12);
    expect(labelVisible({ ...calm, edgeCount: 12 })).toBe(true);
    expect(labelVisible({ ...calm, edgeCount: 1 })).toBe(true);
  });

  it("past 12 flows labels only a highlighted, hovered or selected-node edge", () => {
    expect(labelVisible({ ...calm, edgeCount: 13 })).toBe(false);
    expect(labelVisible({ ...calm, edgeCount: 13, on: true })).toBe(true);
    expect(labelVisible({ ...calm, edgeCount: 13, hovered: true })).toBe(true);
    expect(labelVisible({ ...calm, edgeCount: 13, touchesSelected: true })).toBe(true);
  });

  it("knows which edges touch the selected node", () => {
    expect(touchesNode({ source: "a", target: "b" }, "a")).toBe(true);
    expect(touchesNode({ source: "a", target: "b" }, "b")).toBe(true);
    expect(touchesNode({ source: "a", target: "b" }, "c")).toBe(false);
    expect(touchesNode({ source: "a", target: "b" }, null)).toBe(false);
  });
});

describe("edgeStrokeWidth", () => {
  const calm = { on: false, hovered: false };

  it("keeps the weights it had: boundary crossings heavier, highlighted heavier still", () => {
    expect(edgeStrokeWidth({ crossesTrustBoundary: false }, calm)).toBe(1.5);
    expect(edgeStrokeWidth({ crossesTrustBoundary: true }, calm)).toBe(2);
    expect(edgeStrokeWidth({ crossesTrustBoundary: false }, { on: true, hovered: false })).toBe(3);
  });

  it("draws the hovered edge thicker than the same edge unhovered, whatever its kind", () => {
    for (const crossesTrustBoundary of [true, false]) {
      for (const on of [true, false]) {
        const edge = { crossesTrustBoundary };
        expect(edgeStrokeWidth(edge, { on, hovered: true })).toBeGreaterThan(
          edgeStrokeWidth(edge, { on, hovered: false }),
        );
      }
    }
  });
});

describe("pointAlong", () => {
  const line = (length: number) => ({
    getTotalLength: () => length,
    getPointAtLength: (at: number) => ({ x: at, y: 2 * at }),
  });

  it("puts labels 35% of the way along, not at the midpoint", () => {
    expect(LABEL_FRACTION).toBe(0.35);
    expect(pointAlong(line(200), LABEL_FRACTION, { x: -1, y: -1 })).toEqual({ x: 70, y: 140 });
  });

  it("gives two edges out of one node different label points", () => {
    const a = pointAlong(line(200), LABEL_FRACTION, { x: 0, y: 0 });
    const b = pointAlong(line(320), LABEL_FRACTION, { x: 0, y: 0 });
    expect(a).not.toEqual(b);
  });

  it("falls back when the path cannot be measured", () => {
    const fallback = { x: 5, y: 6 };
    expect(pointAlong(null, 0.35, fallback)).toBe(fallback);
    expect(pointAlong({} as never, 0.35, fallback)).toBe(fallback);
    expect(pointAlong(line(0), 0.35, fallback)).toBe(fallback);
    expect(pointAlong(line(Number.NaN), 0.35, fallback)).toBe(fallback);
    expect(
      pointAlong({ getTotalLength: () => 10, getPointAtLength: () => { throw new Error("no svg"); } }, 0.35, fallback),
    ).toBe(fallback);
  });
});
