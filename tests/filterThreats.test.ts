/**
 * filterThreats: pure, order-preserving, non-mutating threat filtering.
 *
 * Filtering is the one thing the dashboard is allowed to do to the threat list, so the
 * properties that matter are that it never mutates what it is given, never reorders the
 * server's ranking, and treats an empty facet as "no constraint" rather than "match
 * nothing". Inputs are deep-frozen so any in-place write throws.
 *
 * Plain Node environment: src/client/filterThreats.ts must not need a DOM.
 */

import { describe, expect, it } from "vitest";
import {
  EMPTY_FILTERS,
  filterThreats,
  hasActiveFilters,
  toggleFilterValue,
} from "@/client/filterThreats";
import type { ThreatCardData } from "@/shared/viewModel";
import { deepFreeze } from "./helpers";

function threat(
  id: string,
  overrides: Partial<ThreatCardData> = {},
): ThreatCardData {
  return {
    id,
    title: `Threat ${id}`,
    severity: "high",
    confidence: 70,
    confidenceLabel: "high",
    priority: "fix_soon",
    priorityLabel: "Fix soon",
    stride: [{ code: "S", label: "Spoofing" }],
    owasp: [{ code: "A01:2025", label: "Broken Access Control" }],
    cwe: ["CWE-284"],
    basis: "evidence_backed",
    basisLabel: "Confirmed by evidence",
    componentNames: ["API"],
    componentIds: ["api"],
    dataFlowIds: [],
    confidenceReasons: [],
    attackScenario: `Scenario for ${id}`,
    evidence: [],
    mitigation: { summary: "Fix it", steps: ["Step"], codeLocation: null },
    assumptions: [],
    ...overrides,
  };
}

const THREATS: readonly ThreatCardData[] = deepFreeze([
  threat("alpha", { severity: "critical", priority: "fix_now", priorityLabel: "Fix now" }),
  threat("bravo", {
    severity: "high",
    confidenceLabel: "medium",
    stride: [{ code: "T", label: "Tampering" }],
    owasp: [{ code: "A05:2025", label: "Injection" }],
    componentNames: ["Database"],
    componentIds: ["db"],
    dataFlowIds: ["api-db"],
    cwe: ["CWE-89"],
  }),
  threat("charlie", {
    severity: "low",
    priority: "monitor",
    priorityLabel: "Monitor",
    basis: "assumption_dependent",
    basisLabel: "Predicted from a missing control",
    confidenceLabel: "low",
  }),
]);

describe("filterThreats", () => {
  it("returns every threat when no facet is selected", () => {
    expect(filterThreats(THREATS, EMPTY_FILTERS).map((t) => t.id)).toEqual([
      "alpha",
      "bravo",
      "charlie",
    ]);
  });

  it("treats an omitted filters argument as no constraint", () => {
    expect(filterThreats(THREATS)).toHaveLength(3);
  });

  it("does not mutate the threats it is given", () => {
    // THREATS is deep-frozen; an in-place sort or splice would throw here.
    expect(() =>
      filterThreats(THREATS, { severities: ["critical"], search: "alpha" }),
    ).not.toThrow();
    expect(THREATS.map((t) => t.id)).toEqual(["alpha", "bravo", "charlie"]);
  });

  it("does not mutate the filters it is given", () => {
    const filters = deepFreeze({ ...EMPTY_FILTERS, severities: ["high"] as const });
    expect(() => filterThreats(THREATS, filters)).not.toThrow();
    expect(filters.severities).toEqual(["high"]);
  });

  it("returns a new array, never the input", () => {
    const result = filterThreats(THREATS, EMPTY_FILTERS);
    expect(result).not.toBe(THREATS);
  });

  it("preserves the server's ordering", () => {
    // "charlie" is the lowest severity but last in server order; filtering must not
    // promote "alpha" or re-rank anything.
    const result = filterThreats(THREATS, { confidenceLabels: ["high", "low"] });
    expect(result.map((t) => t.id)).toEqual(["alpha", "charlie"]);
  });

  it("filters by severity", () => {
    expect(filterThreats(THREATS, { severities: ["critical"] }).map((t) => t.id)).toEqual([
      "alpha",
    ]);
  });

  it("ORs multiple values within one facet", () => {
    expect(
      filterThreats(THREATS, { severities: ["critical", "low"] }).map((t) => t.id),
    ).toEqual(["alpha", "charlie"]);
  });

  it("ANDs across facets", () => {
    expect(
      filterThreats(THREATS, {
        severities: ["critical", "high"],
        stride: ["T"],
      }).map((t) => t.id),
    ).toEqual(["bravo"]);
  });

  it("filters by STRIDE code", () => {
    expect(filterThreats(THREATS, { stride: ["T"] }).map((t) => t.id)).toEqual(["bravo"]);
  });

  it("filters by OWASP code", () => {
    expect(filterThreats(THREATS, { owasp: ["A05:2025"] }).map((t) => t.id)).toEqual([
      "bravo",
    ]);
  });

  it("filters by priority and basis", () => {
    expect(filterThreats(THREATS, { priorities: ["fix_now"] }).map((t) => t.id)).toEqual([
      "alpha",
    ]);
    expect(
      filterThreats(THREATS, { basis: ["assumption_dependent"] }).map((t) => t.id),
    ).toEqual(["charlie"]);
  });

  it("filters by component id using the threat's component ids", () => {
    expect(filterThreats(THREATS, { componentIds: ["db"] }).map((t) => t.id)).toEqual([
      "bravo",
    ]);
  });

  it("never matches a component filter against a data-flow id", () => {
    // The schema only makes ids unique within one collection, so a flow can share its id
    // with a component. A threat that only touches the flow "db" does not touch component
    // "db" and must not pass that component's filter.
    const flowOnly = threat("delta", { componentIds: ["api"], dataFlowIds: ["db"] });
    const result = filterThreats([...THREATS, flowOnly], { componentIds: ["db"] });
    expect(result.map((t) => t.id)).toEqual(["bravo"]);
  });

  it("matches search case-insensitively across title, component, CWE and OWASP label", () => {
    expect(filterThreats(THREATS, { search: "BRAVO" }).map((t) => t.id)).toEqual(["bravo"]);
    expect(filterThreats(THREATS, { search: "database" }).map((t) => t.id)).toEqual([
      "bravo",
    ]);
    expect(filterThreats(THREATS, { search: "cwe-89" }).map((t) => t.id)).toEqual(["bravo"]);
    expect(filterThreats(THREATS, { search: "injection" }).map((t) => t.id)).toEqual([
      "bravo",
    ]);
  });

  it("ignores a whitespace-only search", () => {
    expect(filterThreats(THREATS, { search: "   " })).toHaveLength(3);
  });

  it("returns an empty list when nothing matches", () => {
    expect(filterThreats(THREATS, { search: "no-such-threat" })).toEqual([]);
  });

  it("survives threats missing optional array fields", () => {
    const partial = [
      { id: "partial", severity: "high", priority: "monitor" } as unknown as ThreatCardData,
    ];
    expect(() => filterThreats(partial, { stride: ["S"] })).not.toThrow();
    expect(filterThreats(partial, { severities: ["high"] })).toHaveLength(1);
  });
});

describe("hasActiveFilters", () => {
  it("is false for the default filters", () => {
    expect(hasActiveFilters(EMPTY_FILTERS)).toBe(false);
  });

  it("is true once any facet or the search box is used", () => {
    expect(hasActiveFilters({ severities: ["low"] })).toBe(true);
    expect(hasActiveFilters({ search: "api" })).toBe(true);
    expect(hasActiveFilters({ search: "  " })).toBe(false);
  });
});

describe("toggleFilterValue", () => {
  it("adds a value without mutating the original filters", () => {
    const filters = deepFreeze({ ...EMPTY_FILTERS });
    const next = toggleFilterValue(filters, "severities", "high");

    expect(next.severities).toEqual(["high"]);
    expect(filters.severities).toEqual([]);
    expect(next).not.toBe(filters);
  });

  it("removes a value that is already selected", () => {
    const filters = { ...EMPTY_FILTERS, severities: ["high", "low"] as const };
    expect(toggleFilterValue(filters, "severities", "high").severities).toEqual(["low"]);
  });

  it("leaves other facets untouched", () => {
    const filters = { ...EMPTY_FILTERS, stride: ["S"] as const };
    expect(toggleFilterValue(filters, "severities", "low").stride).toEqual(["S"]);
  });
});
