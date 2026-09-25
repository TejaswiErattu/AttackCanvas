import { describe, expect, it } from "vitest";
import { matchRoute, routesNamedIn, stripCrossRouteGapCitations } from "@/server/analysis/routeScope";
import type { DraftThreat } from "@/shared/schema";

const KNOWN = ["/", "/learn", "/research", "/allocations/:userId", "/benefits", "/memos"];

function threat(title: string, attackScenario: string, evidenceIds: string[]): DraftThreat {
  return {
    title,
    attackScenario,
    evidenceIds,
    stride: ["T"],
    owasp: ["A05:2025"],
    cwe: [],
    componentIds: ["api"],
    dataFlowIds: [],
    asset: "data",
    assumptions: [],
    dependsOnUnknownIds: [],
    impact: 3,
    likelihood: 3,
    impactReason: "r",
    likelihoodReason: "r",
    mitigation: { summary: "m", steps: [] },
  } as DraftThreat;
}

const GAPS = new Map([["ev-gap-5", "/learn"]]);

describe("routesNamedIn", () => {
  it("finds known routes, including a parameter written another way", () => {
    expect(routesNamedIn("GET /allocations/{id} and POST /benefits", KNOWN)).toEqual(["/allocations/:userId", "/benefits"]);
    expect(routesNamedIn("via /allocations/:uid.", KNOWN)).toEqual(["/allocations/:userId"]);
  });

  it("ignores URLs, file paths, longer paths, and the root path", () => {
    expect(routesNamedIn("redirect to https://evil.example/learn", KNOWN)).toEqual([]);
    expect(routesNamedIn("see app/routes/learn.js and /learning and /learn/more", KNOWN)).toEqual([]);
    expect(routesNamedIn("the / page", KNOWN)).toEqual([]);
  });

  it("does not count paths the detector never found", () => {
    expect(routesNamedIn("POST /admin/delete", KNOWN)).toEqual([]);
  });
});

describe("matchRoute", () => {
  it("classifies same, different and unknown", () => {
    expect(matchRoute("/learn", ["/learn", "/research"])).toBe("same");
    expect(matchRoute("/learn", ["/research"])).toBe("different");
    expect(matchRoute("/learn", [])).toBe("unknown");
  });
});

describe("stripCrossRouteGapCitations", () => {
  it("keeps a same-route citation", () => {
    const t = threat("Open redirect on GET /learn", "url param", ["ev-gap-5", "ev-code"]);
    const out = stripCrossRouteGapCitations(t, GAPS, KNOWN);
    expect(out.removed).toEqual([]);
    expect(out.threat).toBe(t);
  });

  it("removes a cross-route citation and keeps the rest", () => {
    const t = threat("SSRF on GET /research", "fetches req.query.url", ["ev-code", "ev-gap-5"]);
    const out = stripCrossRouteGapCitations(t, GAPS, KNOWN);
    expect(out.threat.evidenceIds).toEqual(["ev-code"]);
    expect(out.removed).toEqual([{ evidenceId: "ev-gap-5", gapRoute: "/learn", threatRoutes: ["/research"] }]);
  });

  it("keeps the citation when the threat names no route (ambiguous)", () => {
    const t = threat("Unvalidated input reaches the database", "no validation library", ["ev-gap-5"]);
    const out = stripCrossRouteGapCitations(t, GAPS, KNOWN);
    expect(out.removed).toEqual([]);
    expect(out.threat.evidenceIds).toEqual(["ev-gap-5"]);
  });

  it("leaves citations of non-route-scoped evidence alone", () => {
    const t = threat("SSRF on GET /research", "x", ["ev-other-gap"]);
    expect(stripCrossRouteGapCitations(t, GAPS, KNOWN).removed).toEqual([]);
  });
});
