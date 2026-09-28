/**
 * Per-finding status, kept in the browser only.
 *
 * A status is the reader's own triage note ("we fixed this", "we accept this"); it never
 * feeds back into severity, confidence or priority, which stay server-computed (CLAUDE.md
 * rule 2). Statuses live in localStorage under one key per repository and ref, as
 * { [threatKey]: status }, where threatKey (src/client/drift.ts) is the threat's identity
 * across runs: normalised title, component names and OWASP codes. Threat ids ("threat-3")
 * are reassigned every run, so a status stored by id would land on another threat next
 * time; stored by key, a Fixed status follows the same threat to the next run. "open" is
 * the default and is never stored.
 *
 * Maps saved before this were keyed by id. migrateStatuses rewrites them once, against the
 * run they were saved on, and drops the id entries.
 *
 * The storage object is injected, so this module is pure and tests in plain Node. Every
 * storage access is wrapped: private windows, blocked storage and a full quota all throw,
 * and none of them may break the dashboard.
 */

import type { Priority } from "@/shared/schema";
import type { ThreatCardData } from "@/shared/viewModel";
import { threatKey } from "@/client/drift";

export const FINDING_STATUSES = ["open", "fixed", "accepted_risk", "false_positive"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Open",
  fixed: "Fixed",
  accepted_risk: "Accepted risk",
  false_positive: "False positive",
};

/** The subset of the Web Storage API this module uses. */
export type StatusStorage = Pick<Storage, "getItem" | "setItem">;

/**
 * Only threats with a non-open status appear; a missing entry means "open". Stored maps are
 * keyed by threatKey; the dashboard projects them onto this run's ids (statusesById).
 */
export type StatusMap = Readonly<Record<string, FindingStatus>>;

export type StatusCounts = Record<FindingStatus, number>;

export function isFindingStatus(value: unknown): value is FindingStatus {
  return typeof value === "string" && (FINDING_STATUSES as readonly string[]).includes(value);
}

export function statusStorageKey(owner: string, repo: string, ref: string): string {
  return `attackcanvas:status:${owner}/${repo}@${ref}`;
}

/** Splits "owner/repo" as the view model carries it; null when it is not in that shape. */
export function splitFullName(fullName: string): { owner: string; repo: string } | null {
  const [owner, repo, ...rest] = fullName.split("/");
  return owner && repo && rest.length === 0 ? { owner, repo } : null;
}

/** Reads the saved map. Anything unreadable or malformed yields an empty map. */
export function loadStatuses(storage: StatusStorage | null | undefined, key: string): StatusMap {
  try {
    const raw = storage?.getItem(key);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    const result: Record<string, FindingStatus> = {};
    for (const [id, value] of Object.entries(parsed)) {
      if (isFindingStatus(value) && value !== "open") result[id] = value;
    }
    return result;
  } catch {
    return {};
  }
}

/** Saves the whole map. A failed save is ignored: the in-memory map stays correct. */
export function saveStatuses(
  storage: StatusStorage | null | undefined,
  key: string,
  statuses: StatusMap,
): void {
  try {
    storage?.setItem(key, JSON.stringify(statuses));
  } catch {
    // Storage unavailable or full: keep the in-memory choice.
  }
}

/**
 * Returns the map with one status changed, and saves it. The returned map is correct even
 * when the save fails, so the page still reflects the choice for this visit.
 */
export function setStatus(
  storage: StatusStorage | null | undefined,
  key: string,
  current: StatusMap,
  entry: string,
  status: FindingStatus,
): StatusMap {
  const next: Record<string, FindingStatus> = { ...current };
  if (status === "open") delete next[entry];
  else next[entry] = status;
  saveStatuses(storage, key, next);
  return next;
}

export function statusOf(statuses: StatusMap, entry: string): FindingStatus {
  const value = statuses[entry];
  return value === undefined ? "open" : value;
}

/** True for an entry keyed by threatKey (a JSON array); false for a legacy "threat-N" id. */
export function isThreatKeyEntry(entry: string): boolean {
  if (!entry.startsWith("[")) return false;
  try {
    return Array.isArray(JSON.parse(entry));
  } catch {
    return false;
  }
}

type RunThreats = {
  threats?: readonly ThreatCardData[];
  hiddenThreats?: readonly ThreatCardData[];
};

/**
 * Rewrites id-keyed entries ("threat-3": "fixed") to threatKey entries, looking each id up
 * in `savedOn`, the run the map was saved against. Id entries are then dropped, mapped or
 * not: an id that run does not have names no threat. A key entry already present wins over
 * a migrated one. `changed` is true when there was anything to migrate, so the caller
 * saves the result once and never migrates again.
 */
export function migrateStatuses(
  statuses: StatusMap,
  savedOn: RunThreats | null | undefined,
): { statuses: StatusMap; changed: boolean } {
  const legacy = Object.entries(statuses).filter(([entry]) => !isThreatKeyEntry(entry));
  if (legacy.length === 0) return { statuses, changed: false };
  const byId = new Map(
    [...(savedOn?.threats ?? []), ...(savedOn?.hiddenThreats ?? [])].map((t) => [t.id, t]),
  );
  const result: Record<string, FindingStatus> = Object.fromEntries(
    Object.entries(statuses).filter(([entry]) => isThreatKeyEntry(entry)),
  );
  for (const [id, status] of legacy) {
    const threat = byId.get(id);
    if (!threat) continue;
    const key = threatKey(threat);
    if (!(key in result)) result[key] = status;
  }
  return { statuses: result, changed: true };
}

/**
 * The stored (threatKey-keyed) map projected onto this run's threat ids, which is what the
 * list, filters and counts look statuses up by.
 */
export function statusesById(
  threats: readonly ThreatCardData[],
  byKey: StatusMap,
): StatusMap {
  const result: Record<string, FindingStatus> = {};
  for (const threat of threats) {
    const status = byKey[threatKey(threat)];
    if (status !== undefined) result[threat.id] = status;
  }
  return result;
}

/** Counts by status over the given threat ids; an id absent from the map counts as open. */
export function summarise(threatIds: readonly string[], statuses: StatusMap): StatusCounts {
  const counts: StatusCounts = { open: 0, fixed: 0, accepted_risk: 0, false_positive: 0 };
  for (const id of threatIds) counts[statusOf(statuses, id)] += 1;
  return counts;
}

/**
 * Within each priority band, moves handled findings (anything not open) after open ones.
 * Both groups keep the server's order, and the bands themselves are not reordered: the
 * server sorts by priority first, so a band is a run of equal priorities. Returns a new
 * array and never mutates its input.
 */
export function orderByStatus<T extends { id: string; priority: Priority }>(
  threats: readonly T[],
  statuses: StatusMap,
): T[] {
  const result: T[] = [];
  let index = 0;
  while (index < threats.length) {
    const priority = threats[index].priority;
    const band: T[] = [];
    while (index < threats.length && threats[index].priority === priority) {
      band.push(threats[index]);
      index += 1;
    }
    result.push(
      ...band.filter((t) => statusOf(statuses, t.id) === "open"),
      ...band.filter((t) => statusOf(statuses, t.id) !== "open"),
    );
  }
  return result;
}
