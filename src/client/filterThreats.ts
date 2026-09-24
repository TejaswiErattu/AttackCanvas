/**
 * Client-side threat filtering.
 *
 * Purely a view concern: this narrows the list of threats the server already scored,
 * ordered and returned. It never recomputes severity, confidence, priority or basis, and
 * it never reorders — server order (priority, then risk, then confidence, then id; see
 * src/client/adapter.ts) is preserved exactly, because that ordering is part of the
 * analysis result, not a display preference (CLAUDE.md rule 2).
 *
 * Every function is pure and DOM-free so it can be unit-tested in the plain Node
 * environment: inputs are never mutated, and a new array is always returned.
 *
 * An empty selection means "no constraint on this facet", not "match nothing" — so the
 * default, all-empty filter returns the list unchanged. Within one facet the selected
 * values are OR-ed; across facets they are AND-ed, which is what a user reading
 * "Critical + Injection" expects.
 */

import type {
  Basis,
  ConfidenceLabel,
  Owasp2025,
  Priority,
  Severity,
  Stride,
} from "@/shared/schema";
import type { ThreatCardData } from "@/shared/viewModel";

export type ThreatFilters = {
  severities: readonly Severity[];
  stride: readonly Stride[];
  owasp: readonly Owasp2025[];
  /** Component ids, matched against the threat's component ids (never its data-flow ids). */
  componentIds: readonly string[];
  confidenceLabels: readonly ConfidenceLabel[];
  priorities: readonly Priority[];
  basis: readonly Basis[];
  /** Free text; case-insensitive, matched against title, scenario, components and ids. */
  search: string;
};

/** Frozen so a caller cannot accidentally turn the shared default into shared state. */
export const EMPTY_FILTERS: ThreatFilters = Object.freeze({
  severities: Object.freeze([]) as readonly Severity[],
  stride: Object.freeze([]) as readonly Stride[],
  owasp: Object.freeze([]) as readonly Owasp2025[],
  componentIds: Object.freeze([]) as readonly string[],
  confidenceLabels: Object.freeze([]) as readonly ConfidenceLabel[],
  priorities: Object.freeze([]) as readonly Priority[],
  basis: Object.freeze([]) as readonly Basis[],
  search: "",
});

/** A partial API response may omit an array field entirely; treat that as empty. */
function toArray<T>(value: readonly T[] | undefined | null): readonly T[] {
  return Array.isArray(value) ? value : [];
}

function toText(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** True when the facet places no constraint (nothing selected). */
function unconstrained(selected: readonly unknown[] | undefined): boolean {
  return toArray(selected).length === 0;
}

function matchesAny<T>(
  selected: readonly T[] | undefined,
  values: readonly (T | undefined)[],
): boolean {
  const wanted = toArray(selected);
  if (wanted.length === 0) return true;
  return values.some((value) => value !== undefined && wanted.includes(value));
}

/**
 * The searchable text of one threat. Ids are included so a user can paste a threat id, and
 * STRIDE/OWASP labels so "Injection" matches A05:2025 without knowing the code.
 */
function searchCorpus(threat: ThreatCardData): string {
  const stride = toArray(threat.stride);
  const owasp = toArray(threat.owasp);
  return [
    toText(threat.id),
    toText(threat.title),
    toText(threat.attackScenario),
    ...toArray(threat.componentNames).map(toText),
    ...toArray(threat.cwe).map(toText),
    ...stride.flatMap((item) => [toText(item?.code), toText(item?.label)]),
    ...owasp.flatMap((item) => [toText(item?.code), toText(item?.label)]),
  ]
    .join("\n")
    .toLowerCase();
}

function matchesSearch(threat: ThreatCardData, search: string): boolean {
  const needle = toText(search).trim().toLowerCase();
  if (needle === "") return true;
  return searchCorpus(threat).includes(needle);
}

/**
 * Component match uses the threat's own `componentIds` only. Data-flow ids are a separate
 * collection whose ids may coincide with a component's (the schema only makes ids unique
 * within one collection), so matching against them would let a threat that merely touches
 * a same-named flow pass a component filter.
 */
function matchesComponents(
  threat: ThreatCardData,
  selected: readonly string[] | undefined,
): boolean {
  if (unconstrained(selected)) return true;
  const components = toArray(threat.componentIds);
  return toArray(selected).some((id) => components.includes(id));
}

/**
 * Returns the threats that satisfy every active facet, in their original order.
 *
 * Pure: `threats` and `filters` are only read. The result is always a new array, so the
 * caller can hold both the full and filtered lists without aliasing.
 */
export function filterThreats(
  threats: readonly ThreatCardData[],
  filters: Partial<ThreatFilters> = {},
): ThreatCardData[] {
  // Annotated, because Array.isArray widens a readonly array to any[] and that would
  // leave every element below typed as `any`.
  const source: readonly ThreatCardData[] = Array.isArray(threats) ? threats : [];
  return source.filter((threat) => {
    if (threat === null || typeof threat !== "object") return false;
    // Pulled out as locals so the element type comes from the threat, not from the
    // contextual type of the argument being matched against.
    const strideCodes = toArray(threat.stride).map((item) => item?.code);
    const owaspCodes = toArray(threat.owasp).map((item) => item?.code);
    return (
      matchesAny(filters.severities, [threat.severity]) &&
      matchesAny(filters.priorities, [threat.priority]) &&
      matchesAny(filters.basis, [threat.basis]) &&
      matchesAny(filters.confidenceLabels, [threat.confidenceLabel]) &&
      matchesAny(filters.stride, strideCodes) &&
      matchesAny(filters.owasp, owaspCodes) &&
      matchesComponents(threat, filters.componentIds) &&
      matchesSearch(threat, filters.search ?? "")
    );
  });
}

/** True when at least one facet is constraining the list — drives the "Clear all" button. */
export function hasActiveFilters(filters: Partial<ThreatFilters> = {}): boolean {
  return (
    !unconstrained(filters.severities) ||
    !unconstrained(filters.stride) ||
    !unconstrained(filters.owasp) ||
    !unconstrained(filters.componentIds) ||
    !unconstrained(filters.confidenceLabels) ||
    !unconstrained(filters.priorities) ||
    !unconstrained(filters.basis) ||
    toText(filters.search).trim() !== ""
  );
}

/**
 * Adds or removes one value in a facet and returns a new filters object. Used by every
 * checkbox in FilterBar, and pure for the same reason the rest of this module is.
 */
export function toggleFilterValue<K extends Exclude<keyof ThreatFilters, "search">>(
  filters: ThreatFilters,
  facet: K,
  value: ThreatFilters[K][number],
): ThreatFilters {
  const current = toArray(filters[facet]) as readonly ThreatFilters[K][number][];
  const next = current.includes(value)
    ? current.filter((item) => item !== value)
    : [...current, value];
  return { ...filters, [facet]: next };
}
