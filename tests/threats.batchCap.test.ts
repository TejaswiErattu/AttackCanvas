import { describe, expect, it } from "vitest";
import { batchElements, capBatchesByGaps } from "@/server/analysis/threats";
import { skippedElementsLimitation } from "@/server/analysis/pipeline";
import type { ControlGap } from "@/server/detect/types";
import type { Component, DataFlow } from "@/shared/schema";

function component(id: string): Component {
  return {
    id,
    name: id,
    type: "backend",
    description: `${id} description`,
    technologies: [],
    files: [`src/${id}.ts`],
    assets: [],
  };
}

function flow(id: string, sourceId: string, targetId: string): DataFlow {
  return {
    id,
    sourceId,
    targetId,
    label: `${sourceId} to ${targetId}`,
    dataClassification: "internal",
    crossesTrustBoundary: false,
  };
}

function gapIn(id: string, componentId: string): ControlGap {
  return { id, scope: "route", file: `src/${componentId}.ts`, line: 1 } as ControlGap;
}

const architecture = {
  components: ["a", "b", "c", "d", "e"].map(component),
  dataFlows: [flow("f-e", "e", "a")],
};

describe("capBatchesByGaps", () => {
  const batches = [["a", "b"], ["c", "d"], ["e", "f-e"]];

  it("keeps the gap-richest batches in their original order and names the rest", () => {
    const gaps = [gapIn("g1", "e"), gapIn("g2", "c"), gapIn("g3", "c")];
    // c/d = 2, e/f-e = 1 + 1 (the flow counts its source's gap), a/b = 0
    expect(capBatchesByGaps(batches, architecture, gaps, 2)).toEqual({
      kept: [["c", "d"], ["e", "f-e"]],
      skippedElementIds: ["a", "b"],
    });
  });

  it("breaks ties by the batchElements order", () => {
    expect(capBatchesByGaps(batches, architecture, [], 1)).toEqual({
      kept: [["a", "b"]],
      skippedElementIds: ["c", "d", "e", "f-e"],
    });
  });

  it("skips nothing when the cap covers every batch", () => {
    const real = batchElements(architecture);
    expect(capBatchesByGaps(real, architecture, [], real.length + 1)).toEqual({
      kept: real,
      skippedElementIds: [],
    });
  });

  it("rejects a non-positive cap", () => {
    expect(() => capBatchesByGaps(batches, architecture, [], 0)).toThrow();
  });
});

describe("skippedElementsLimitation", () => {
  it("says how many were not analysed and that a higher level covers them", () => {
    expect(skippedElementsLimitation(4, 10)).toBe(
      "This quick analysis looked for threats in 6 of 10 architecture elements; 4 were not analysed. Run level 1 or higher to cover them.",
    );
  });
});
