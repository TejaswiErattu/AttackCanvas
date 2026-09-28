/**
 * carryForward: which of the last run's threats stay in view as "Still open from the last run".
 */

import { describe, expect, it } from "vitest";
import { carryForward } from "@/client/carryForward";
import { diffThreatModels, threatKey } from "@/client/drift";
import type { StatusMap } from "@/client/findingStatus";
import type { ThreatCardData } from "@/shared/viewModel";

function card(id: string, title: string, severity = "high", confidence = 60): ThreatCardData {
  return {
    id, title, severity, confidence, componentNames: ["API"],
    owasp: [{ code: "A01:2025", label: "A01" }],
  } as unknown as ThreatCardData;
}

const open = card("threat-1", "Open one", "critical", 80);
const fixed = card("threat-2", "Fixed one");
const falsePositive = card("threat-3", "False positive one");
const accepted = card("threat-4", "Accepted one");
const refound = card("threat-5", "Found again");
const dropped = card("threat-6", "Dropped one");
const wasHidden = card("threat-7", "Was hidden", "medium", 10);

const prev = {
  nodes: [], edges: [],
  threats: [open, fixed, falsePositive, accepted, refound, dropped],
  hiddenThreats: [wasHidden],
};
const next = {
  nodes: [], edges: [],
  threats: [card("threat-1", "Found again")],
  hiddenThreats: [card("threat-2", "Dropped one", "high", 12)],
};

const statuses: StatusMap = {
  [threatKey(fixed)]: "fixed",
  [threatKey(falsePositive)]: "false_positive",
  [threatKey(accepted)]: "accepted_risk",
};

describe("carryForward", () => {
  const carried = carryForward(diffThreatModels(prev, next), statuses);

  it("keeps not-found threats whose status is not Fixed or False positive", () => {
    expect(carried.map((t) => t.title)).toEqual(["Open one", "Accepted one"]);
  });

  it("keeps the original severity, confidence and status", () => {
    expect(carried[0]).toMatchObject({ severity: "critical", confidence: 80, status: "open" });
    expect(carried[1].status).toBe("accepted_risk");
  });

  it("does not carry a threat re-found this run, or one only dropped below 25%", () => {
    const titles = carried.map((t) => t.title);
    expect(titles).not.toContain("Found again");
    expect(titles).not.toContain("Dropped one");
  });

  it("does not carry a threat that was already below 25% last run", () => {
    expect(carried.map((t) => t.title)).not.toContain("Was hidden");
  });

  it("carries nothing on a first run", () => {
    expect(carryForward(null, statuses)).toEqual([]);
  });
});
