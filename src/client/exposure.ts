/**
 * How exposed a component is, by where it sits relative to the outside world.
 *
 *   external  an external service or an auth provider: someone else runs it;
 *   edge      an actor, a frontend, or any component an actor sends data to directly:
 *             it takes input from outside;
 *   internal  everything else: reachable only through another component.
 *
 * Pure, and free of React and the server, so the dashboard badge and the STRIDE prompt's
 * "## EXPOSURE" block (src/server/analysis/threatPrompt.ts) use the same rule. It is a
 * description, never a score: nothing in src/server/scoring reads it (CLAUDE.md rule 2).
 *
 * `flows` alone cannot say whether a flow's source is an actor, so the types of the
 * components are passed alongside, by id.
 */

import type { Exposure } from "@/shared/viewModel";

export type { Exposure };

export const EXPOSURE_LABELS: Record<Exposure, string> = {
  external: "External",
  edge: "Edge",
  internal: "Internal",
};

const EXTERNAL_TYPES = new Set(["external_service", "auth_provider"]);
const EDGE_TYPES = new Set(["actor", "frontend"]);

export type ExposureComponent = { id: string; type: string };
export type ExposureFlow = { source: string; target: string };

export function exposureOf(
  component: ExposureComponent,
  flows: readonly ExposureFlow[],
  typeOf: ReadonlyMap<string, string>,
): Exposure {
  if (EXTERNAL_TYPES.has(component.type)) return "external";
  if (EDGE_TYPES.has(component.type)) return "edge";
  const fromActor = flows.some(
    (flow) => flow.target === component.id && typeOf.get(flow.source) === "actor",
  );
  return fromActor ? "edge" : "internal";
}

/** exposureOf for every component, keyed by id. */
export function exposureMap(
  components: readonly ExposureComponent[],
  flows: readonly ExposureFlow[],
): Map<string, Exposure> {
  const typeOf = new Map(components.map((c) => [c.id, c.type]));
  return new Map(components.map((c) => [c.id, exposureOf(c, flows, typeOf)]));
}
