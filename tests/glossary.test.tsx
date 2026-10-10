// @vitest-environment jsdom

/**
 * "How to read these numbers": the glossary must say what the code does. Every figure is
 * checked against the constant it is built from, and the ones that have no shared constant
 * (severity bands, the Fix now bar, the label floors) against the real scoring functions, so
 * a change to the scoring that is not mirrored here fails a test instead of misleading a reader.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { CONFIDENCE_POINTS, GAP_FLOOR, confidenceOf } from "@/shared/confidence";
import { BASIS_LABELS } from "@/shared/labels";
import type { Evidence } from "@/shared/schema";
import { HIDE_BELOW, confidenceLabelOf, isHidden, priorityOf, severityOf } from "@/server/scoring";
import { HIDE_BELOW_CONFIDENCE } from "@/client/adapter";
import {
  LABEL_FLOORS,
  PRIORITY_CONFIDENCE_BAR,
  SEVERITY_FLOORS,
  glossaryEntries,
} from "@/client/glossary";
import SeveritySummary from "@/components/SeveritySummary";

afterEach(cleanup);

const text = (id: string): string => glossaryEntries().find((e) => e.id === id)?.text ?? "";
const signed = (thousandths: number): string =>
  `${thousandths < 0 ? "-" : "+"}${(Math.abs(thousandths) / 1000).toFixed(2)}`;

const code: Evidence = { id: "c", kind: "code", source: "detector", summary: "c" };
const semgrep: Evidence = { id: "s", kind: "scanner", source: "semgrep", summary: "s" };
const osv: Evidence = { id: "o", kind: "dependency", source: "osv", summary: "o" };
const developer: Evidence = { id: "d", kind: "developer_answer", source: "developer", summary: "d" };
const inference: Evidence = { id: "i", kind: "inference", source: "ai", summary: "i" };
const gap: Evidence = { id: "g", kind: "code", source: "detector", ruleId: "gap:authn_missing", summary: "g" };
const score = (e: Evidence[], assumptions: string[] = []) =>
  Math.round(
    confidenceOf(e, new Map([["g", { control: "x", certainty: 1 }]]), assumptions, []).value * 1000,
  );

describe("the confidence line shows the constants", () => {
  it("names every point value as the constants hold it", () => {
    const line = text("confidence");
    const p = CONFIDENCE_POINTS;
    for (const value of [p.code, p.controlGap, p.semgrep, p.osv, p.developer, p.secondSource, p.inferenceOnly, p.assumption]) {
      expect(line).toContain(signed(value));
    }
    expect(line).toContain(`raised to ${GAP_FLOOR.toFixed(2)}`);
    expect(line).toContain(`combined certainty ${(p.gapFloorCertainty / 1000).toFixed(2)}`);
  });

  it("is built from the numbers confidenceOf really adds", () => {
    const p = CONFIDENCE_POINTS;
    expect(score([code])).toBe(p.code);
    expect(score([gap])).toBe(p.controlGap);
    expect(score([semgrep])).toBe(p.semgrep);
    expect(score([osv])).toBe(p.osv);
    expect(score([developer])).toBe(p.developer);
    expect(score([inference])).toBe(p.inferenceOnly);
    expect(score([code, semgrep])).toBe(p.code + p.semgrep + p.secondSource);
    expect(score([code], ["unsure"])).toBe(p.code + p.assumption);
    // The gap floor: two near-certain gaps alone reach GAP_FLOOR.
    const gaps = new Map([
      ["g1", { control: "a", certainty: 0.4, cwe: ["CWE-1"] }],
      ["g2", { control: "b", certainty: 0.4, cwe: ["CWE-1"] }],
    ]);
    const floored = confidenceOf(
      [{ ...gap, id: "g1", filePath: "a", lineStart: 1 }, { ...gap, id: "g2", filePath: "b", lineStart: 2 }],
      gaps,
      ["unsure", "unsure", "unsure"],
      ["CWE-1"],
    );
    expect(floored.value).toBe(GAP_FLOOR);
    expect(p.gapFloorCertainty).toBe(800);
  });
});

describe("the bands and bars match the scoring code", () => {
  it("severity floors are the lowest risk of each severity", () => {
    const lowest = { critical: 99, high: 99, medium: 99, low: 99 };
    for (let impact = 1; impact <= 5; impact += 1) {
      for (let likelihood = 1; likelihood <= 5; likelihood += 1) {
        const severity = severityOf(impact, likelihood);
        lowest[severity] = Math.min(lowest[severity], impact * likelihood);
      }
    }
    expect(lowest).toEqual(SEVERITY_FLOORS);
    expect(text("severity")).toContain("20-25 is Critical, 12-19 High, 6-11 Medium, 1-5 Low");
  });

  it("the Fix now bar is where priorityOf changes", () => {
    const bar = PRIORITY_CONFIDENCE_BAR;
    expect(priorityOf("high", bar)).toBe("fix_now");
    expect(priorityOf("high", bar - 0.01)).toBe("fix_soon");
    expect(priorityOf("medium", bar)).toBe("fix_soon");
    expect(priorityOf("medium", bar - 0.01)).toBe("monitor");
    expect(priorityOf("critical", 0)).toBe("fix_now");
    expect(priorityOf("low", 1)).toBe("monitor");
    expect(text("priority")).toContain("Critical threat, and High ones at 0.50 confidence or more");
  });

  it("the confidence labels start where confidenceLabelOf says", () => {
    expect(confidenceLabelOf(LABEL_FLOORS.high)).toBe("high");
    expect(confidenceLabelOf(LABEL_FLOORS.high - 0.01)).toBe("medium");
    expect(confidenceLabelOf(LABEL_FLOORS.medium)).toBe("medium");
    expect(confidenceLabelOf(LABEL_FLOORS.medium - 0.01)).toBe("low");
    expect(text("confidence")).toContain("High is 0.70 and above, Medium 0.40 to 0.69, Low below 0.40");
  });

  it("the 25% cutoff is the one the adapter and the scoring both use", () => {
    expect(HIDE_BELOW_CONFIDENCE).toBe(HIDE_BELOW);
    expect(isHidden(HIDE_BELOW - 0.01)).toBe(true);
    expect(isHidden(HIDE_BELOW)).toBe(false);
    expect(text("cutoff")).toContain("below 25% confidence");
    expect(text("unverified")).toContain("below 25% confidence");
  });
});

describe("the entries", () => {
  it("has the seven items asked for, each with a term and a sentence", () => {
    const entries = glossaryEntries();
    expect(entries.map((e) => e.id)).toEqual([
      "severity", "confidence", "cutoff", "priority", "basis", "not-found", "unverified",
    ]);
    for (const entry of entries) {
      expect(entry.term.length).toBeGreaterThan(3);
      expect(entry.text.length).toBeGreaterThan(30);
    }
  });

  it("uses the app's own names for Confirmed and Predicted", () => {
    const basis = glossaryEntries().find((e) => e.id === "basis");
    expect(basis?.term).toBe(`${BASIS_LABELS.evidence_backed} vs ${BASIS_LABELS.assumption_dependent}`);
  });

  it("says a threat not found is not fixed, and never calls it resolved", () => {
    const line = text("not-found");
    expect(line).toContain("only a status you set marks a threat as fixed");
    expect(line).not.toMatch(/resolved/i);
  });
});

describe("the panel on the severity tiles", () => {
  const counts = { critical: 1, high: 2, medium: 3, low: 4 };

  it("is closed by default and opens to every entry with the same numbers", () => {
    render(<SeveritySummary counts={counts} basisCounts={null} fixNowCount={1} />);
    const panel = screen.getByTestId("glossary") as HTMLDetailsElement;
    expect(panel.open).toBe(false);
    expect(within(panel).getByText("How to read these numbers")).toBeTruthy();
    fireEvent.click(within(panel).getByText("How to read these numbers"));
    for (const entry of glossaryEntries()) {
      expect(within(panel).getByText(entry.term)).toBeTruthy();
      expect(within(panel).getByText(entry.text)).toBeTruthy();
    }
    expect(panel.textContent).toContain(signed(CONFIDENCE_POINTS.code));
  });

  it("does not change the tiles", () => {
    render(<SeveritySummary counts={counts} basisCounts={null} fixNowCount={1} />);
    expect(screen.getByTestId("scored-line").textContent).toBe("10 threats scored.");
  });
});
