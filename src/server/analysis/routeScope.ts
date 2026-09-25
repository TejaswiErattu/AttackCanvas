/**
 * Deterministic check on route-scoped control-gap citations.
 *
 * A gap such as "GET /learn reads request input and imports no validation library" is
 * bound to a whole component (every gap in its files), so the threat model sees it beside
 * every threat about that component and has cited it for threats about other routes. The
 * threat prompt now says which route a gap is about (threatPrompt.ts formatGap), but that
 * is guidance; this module enforces it.
 *
 * The rule, per citation of a route-scoped gap:
 *   - "same":      the threat's title or scenario names the gap's route  -> keep;
 *   - "different": it names one or more known routes, none of them the gap's -> remove;
 *   - "unknown":   it names no known route at all                          -> keep.
 * Unknown is kept on purpose: a threat that never says which route it is about is not
 * evidence of a mismatch, and guessing would drop real support.
 *
 * Routes are compared by normalized path only, not method: "/benefits" GET and POST are
 * one route for this purpose, which errs toward keeping a citation. Only paths the
 * detector actually found count as "naming a route", so a URL, a file path or an attacker
 * host in the scenario never reads as a different route. The root path "/" is never
 * matched: it is a substring of everything.
 *
 * Pure. Removing a citation changes nothing else; confidence and basis are recomputed from
 * the surviving evidenceIds by src/server/scoring when the model is assembled.
 */

import type { DraftThreat } from "@/shared/schema";

export type RouteMatch = "same" | "different" | "unknown";

export type RemovedCitation = {
  evidenceId: string;
  gapRoute: string;
  /** Known routes the threat names instead, sorted. */
  threatRoutes: string[];
};

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * A matcher for one normalized path. A `:param` segment also matches `{param}`, `[param]`
 * or `<param>` with any name, since the model writes parameters its own way. The path must
 * stand alone: not preceded by a word character, "/" or ":" (so "https://x/learn" and
 * "app/learn.js" do not match), and not continued by another segment or a word character
 * (so "/learn" does not match "/learning" or "/learn/more").
 */
function pathPattern(path: string): RegExp {
  const segments = path
    .split("/")
    .filter((s) => s.length > 0)
    .map((s) =>
      s.startsWith(":") ? String.raw`(?::[\w-]+|\{[\w-]+\}|\[[\w-]+\]|<[\w-]+>)` : escapeRegExp(s),
    );
  return new RegExp(String.raw`(?<![\w/:.])/${segments.join("/")}(?![\w/-])`, "i");
}

/** The known routes (normalized paths) a text names, sorted and de-duplicated. */
export function routesNamedIn(text: string, knownPaths: Iterable<string>): string[] {
  const named = new Set<string>();
  for (const path of knownPaths) {
    if (path === "/" || path.length === 0) continue;
    if (pathPattern(path).test(text)) named.add(path);
  }
  return [...named].sort();
}

export function matchRoute(gapRoute: string, threatRoutes: readonly string[]): RouteMatch {
  if (threatRoutes.length === 0) return "unknown";
  return threatRoutes.includes(gapRoute) ? "same" : "different";
}

/**
 * Removes the threat's citations of route-scoped gaps that it clearly does not concern.
 * `gapRouteByEvidenceId` maps a route-scoped gap's evidence id to its route path; every
 * other cited id is left alone.
 */
export function stripCrossRouteGapCitations(
  threat: DraftThreat,
  gapRouteByEvidenceId: ReadonlyMap<string, string>,
  knownPaths: Iterable<string>,
): { threat: DraftThreat; removed: RemovedCitation[] } {
  const threatRoutes = routesNamedIn(`${threat.title}\n${threat.attackScenario}`, knownPaths);
  const removed: RemovedCitation[] = [];
  const evidenceIds = threat.evidenceIds.filter((id) => {
    const gapRoute = gapRouteByEvidenceId.get(id);
    if (gapRoute === undefined || matchRoute(gapRoute, threatRoutes) !== "different") return true;
    removed.push({ evidenceId: id, gapRoute, threatRoutes });
    return false;
  });
  return removed.length === 0 ? { threat, removed } : { threat: { ...threat, evidenceIds }, removed };
}
