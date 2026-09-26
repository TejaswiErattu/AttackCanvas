import { describe, expect, it } from "vitest";
import { ARROW_CLOSED, edgeMarker, edgeRoutes, reverseEdgeShape } from "@/client/graphEdges";

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
