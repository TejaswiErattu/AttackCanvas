/**
 * "Since last run": what changed between the previous analysis of a repository and this one.
 *
 * The browser holds the dashboard view model, not the schema ThreatModel, so the diff is
 * over that: its nodes (components), edges (data flows) and threats carry the names, types,
 * labels, titles and OWASP codes the comparison needs. Component and flow ids are minted
 * per run and are never compared; everything is matched by name.
 *
 * Matching rules:
 *   components  name + type
 *   flows       source name + target name + label
 *   threats     normalised title + set of component names + set of OWASP codes (threatKey)
 *
 * Threats are compared over every scored threat, visible and below 25% confidence alike, so
 * a threat that only dropped under the display cutoff is not reported as gone. A threat
 * absent from this run is "not found this run", never "resolved" or "fixed": nothing here
 * checks the code changed. Only a status the reader set records that.
 *
 * Pure and DOM-free. The runs themselves are kept in src/client/runHistory.ts, which stores
 * a ring of the last few under attackcanvas:runs:<owner>/<repo>; this module only compares
 * them. Snapshots saved before hidden threats were stored have no `hiddenThreats`; they read
 * as having none.
 */

import type { Severity } from "@/shared/schema";
import type { DashboardViewModel, ThreatCardData } from "@/shared/viewModel";

export type DriftModel = Pick<DashboardViewModel, "nodes" | "edges" | "threats"> & {
  /** Absent from snapshots saved before hidden threats were kept. */
  hiddenThreats?: ThreatCardData[];
  repo?: { ref?: string; analyzedAt?: string };
};

export type ComponentRef = { name: string; type: string };
export type FlowRef = { source: string; target: string; label: string };
export type ThreatRef = {
  key: string;
  title: string;
  componentNames: string[];
  owasp: string[];
  severity: Severity;
  /** 0-100, as the run scored it. */
  confidence: number;
  /** True when the threat was below 25% confidence in the run it comes from. */
  belowCutoff: boolean;
};

export type DriftResult = {
  components: { added: ComponentRef[]; removed: ComponentRef[] };
  flows: { added: FlowRef[]; removed: FlowRef[] };
  threats: {
    /** Visible now; not scored at all last run. */
    new: ThreatRef[];
    /** Visible now; scored last run too (visible or not). */
    persisting: ThreatRef[];
    /** Scored last run (visible or not); not scored this run. */
    notFound: ThreatRef[];
    /** Visible last run; scored this run but below 25%. */
    droppedBelowCutoff: ThreatRef[];
  };
};

// ---------------------------------------------------------------------------
// Matching keys
// ---------------------------------------------------------------------------

export function norm(text: string | undefined | null): string {
  return (text ?? "").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
}

function sortedNorm(values: readonly (string | undefined)[] | undefined): string[] {
  return [...new Set((values ?? []).map(norm).filter((v) => v !== ""))].sort();
}

/** The identity of a threat across runs: title, components affected and OWASP categories. */
export function threatKey(threat: ThreatCardData): string {
  return JSON.stringify([
    norm(threat.title),
    sortedNorm(threat.componentNames),
    sortedNorm((threat.owasp ?? []).map((o) => o?.code)),
  ]);
}

function componentKey(c: ComponentRef): string {
  return JSON.stringify([norm(c.name), c.type]);
}

function flowKey(f: FlowRef): string {
  return JSON.stringify([norm(f.source), norm(f.target), norm(f.label)]);
}

type Delta<T> = { added: T[]; removed: T[]; kept: T[] };

/** Splits two lists by key. Duplicate keys within one list collapse to the first. */
function delta<T>(prev: readonly T[], next: readonly T[], key: (item: T) => string): Delta<T> {
  const first = (items: readonly T[]) => {
    const map = new Map<string, T>();
    for (const item of items) if (!map.has(key(item))) map.set(key(item), item);
    return map;
  };
  const before = first(prev);
  const after = first(next);
  return {
    added: [...after].filter(([k]) => !before.has(k)).map(([, v]) => v),
    removed: [...before].filter(([k]) => !after.has(k)).map(([, v]) => v),
    kept: [...after].filter(([k]) => before.has(k)).map(([, v]) => v),
  };
}

function componentsOf(model: DriftModel): ComponentRef[] {
  return (model.nodes ?? []).map((n) => ({ name: n.label, type: n.type }));
}

function flowsOf(model: DriftModel): FlowRef[] {
  const names = new Map((model.nodes ?? []).map((n) => [n.id, n.label]));
  return (model.edges ?? []).map((e) => ({
    source: names.get(e.source) ?? e.source,
    target: names.get(e.target) ?? e.target,
    label: e.label,
  }));
}

function threatRef(t: ThreatCardData, belowCutoff: boolean): ThreatRef {
  return {
    key: threatKey(t),
    title: t.title,
    componentNames: [...(t.componentNames ?? [])],
    owasp: (t.owasp ?? []).map((o) => o.code),
    severity: t.severity,
    confidence: t.confidence,
    belowCutoff,
  };
}

/** Every scored threat of a run, visible first; a key seen twice keeps its first entry. */
export function allThreatRefs(model: DriftModel): ThreatRef[] {
  const refs = [
    ...(model.threats ?? []).map((t) => threatRef(t, false)),
    ...(Array.isArray(model.hiddenThreats) ? model.hiddenThreats : []).map((t) =>
      threatRef(t, true),
    ),
  ];
  const seen = new Set<string>();
  return refs.filter((r) => (seen.has(r.key) ? false : (seen.add(r.key), true)));
}

/**
 * The threat half of the diff, over two runs' scored threats (see allThreatRefs). Also what
 * the stored run history compares, where only threats are kept.
 */
export function diffThreatRefs(
  before: readonly ThreatRef[],
  after: readonly ThreatRef[],
): DriftResult["threats"] {
  const beforeKeys = new Set(before.map((r) => r.key));
  const afterByKey = new Map(after.map((r) => [r.key, r]));
  const visibleNow = after.filter((r) => !r.belowCutoff);
  return {
    new: visibleNow.filter((r) => !beforeKeys.has(r.key)),
    persisting: visibleNow.filter((r) => beforeKeys.has(r.key)),
    notFound: before.filter((r) => !afterByKey.has(r.key)),
    droppedBelowCutoff: before
      .filter((r) => !r.belowCutoff && afterByKey.get(r.key)?.belowCutoff === true)
      .map((r) => afterByKey.get(r.key) as ThreatRef),
  };
}

export function diffThreatModels(prev: DriftModel, next: DriftModel): DriftResult {
  const components = delta(componentsOf(prev), componentsOf(next), componentKey);
  const flows = delta(flowsOf(prev), flowsOf(next), flowKey);
  return {
    components: { added: components.added, removed: components.removed },
    flows: { added: flows.added, removed: flows.removed },
    threats: diffThreatRefs(allThreatRefs(prev), allThreatRefs(next)),
  };
}

/** Keys in `after` that no threat of `before` had, for the "new" badge. */
export function newKeysFrom(
  before: readonly ThreatRef[],
  after: readonly ThreatRef[],
): Set<string> {
  const known = new Set(before.map((r) => r.key));
  return new Set(after.map((r) => r.key).filter((k) => !known.has(k)));
}

/** Keys of this run's threats (visible or not) that no threat of `prev` had, for the "new" badge. */
export function newThreatKeys(prev: DriftModel, next: DriftModel): Set<string> {
  return newKeysFrom(allThreatRefs(prev), allThreatRefs(next));
}

// ---------------------------------------------------------------------------
// Legacy storage keys
// ---------------------------------------------------------------------------

/**
 * The two full snapshots the browser kept before the run ring (src/client/runHistory.ts).
 * Only the migration reads them now.
 */
export function lastRunKey(owner: string, repo: string): string {
  return `attackcanvas:last:${owner}/${repo}`;
}

export function prevRunKey(owner: string, repo: string): string {
  return `attackcanvas:prev:${owner}/${repo}`;
}
