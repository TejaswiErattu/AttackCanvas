/**
 * The architecture diagram's sub-views: which components and flows each one shows.
 *
 * Pure and presentation-only. It reads the view model the server built (component types,
 * flow classifications, the threats' OWASP and STRIDE codes) and returns ids; it never
 * recomputes a severity or a confidence (CLAUDE.md rule 2), and the threat list is not
 * filtered by it. Ids come back in the view model's order, so the layout that follows is
 * as deterministic as the full diagram's.
 */

import type { DashboardViewModel } from "@/shared/viewModel";

export const DIAGRAM_VIEWS = ["overall", "identity", "data_flows", "external"] as const;
export type DiagramView = (typeof DIAGRAM_VIEWS)[number];

export const DIAGRAM_VIEW_LABELS: Record<DiagramView, string> = {
  overall: "Overall",
  identity: "Identity and auth",
  data_flows: "Data flows",
  external: "External systems",
};

export type DiagramSelection = { nodeIds: string[]; edgeIds: string[] };

type ViewInput = Pick<DashboardViewModel, "nodes" | "edges" | "threats">;

/** OWASP Broken Access Control and Authentication Failures. */
const IDENTITY_OWASP = new Set(["A01:2025", "A07:2025"]);
/** STRIDE Spoofing and Elevation of privilege. */
const IDENTITY_STRIDE = new Set(["S", "E"]);
const SENSITIVE_DATA = new Set(["sensitive", "credential"]);
const EXTERNAL_TYPES = new Set(["external_service", "auth_provider"]);

/** The edges of `input` whose two ends are both in `shown`, in order. */
function edgesAmong(input: ViewInput, shown: ReadonlySet<string>): string[] {
  return (input.edges ?? [])
    .filter((edge) => shown.has(edge.source) && shown.has(edge.target))
    .map((edge) => edge.id);
}

function inNodeOrder(input: ViewInput, shown: ReadonlySet<string>): string[] {
  return (input.nodes ?? []).filter((node) => shown.has(node.id)).map((node) => node.id);
}

/**
 * The node and edge ids `view` shows:
 *   overall            everything;
 *   identity           auth providers, every component a threat in A01 or A07 or with
 *                      STRIDE spoofing or elevation of privilege touches, and the edges
 *                      between them;
 *   data_flows         flows classified sensitive or credential or crossing a trust
 *                      boundary, and the components they touch;
 *   external           external services and auth providers, their direct neighbours, and
 *                      the edges between them.
 * An unknown view name shows everything.
 */
export function selectDiagramView(input: ViewInput, view: DiagramView): DiagramSelection {
  const nodes = input.nodes ?? [];
  const edges = input.edges ?? [];
  const known = new Set(nodes.map((node) => node.id));

  switch (view) {
    case "identity": {
      const shown = new Set(nodes.filter((node) => node.type === "auth_provider").map((node) => node.id));
      for (const threat of input.threats ?? []) {
        const identity =
          (threat.owasp ?? []).some((o) => IDENTITY_OWASP.has(o.code)) ||
          (threat.stride ?? []).some((s) => IDENTITY_STRIDE.has(s.code));
        if (!identity) continue;
        for (const id of threat.componentIds ?? []) if (known.has(id)) shown.add(id);
      }
      return { nodeIds: inNodeOrder(input, shown), edgeIds: edgesAmong(input, shown) };
    }
    case "data_flows": {
      const picked = edges.filter(
        (edge) =>
          (SENSITIVE_DATA.has(edge.dataClassification) || edge.crossesTrustBoundary) &&
          known.has(edge.source) &&
          known.has(edge.target),
      );
      const shown = new Set(picked.flatMap((edge) => [edge.source, edge.target]));
      return { nodeIds: inNodeOrder(input, shown), edgeIds: picked.map((edge) => edge.id) };
    }
    case "external": {
      const core = new Set(nodes.filter((node) => EXTERNAL_TYPES.has(node.type)).map((node) => node.id));
      const shown = new Set(core);
      for (const edge of edges) {
        if (core.has(edge.source) && known.has(edge.target)) shown.add(edge.target);
        if (core.has(edge.target) && known.has(edge.source)) shown.add(edge.source);
      }
      return { nodeIds: inNodeOrder(input, shown), edgeIds: edgesAmong(input, shown) };
    }
    default:
      return {
        nodeIds: nodes.map((node) => node.id),
        edgeIds: edges.filter((e) => known.has(e.source) && known.has(e.target)).map((e) => e.id),
      };
  }
}
