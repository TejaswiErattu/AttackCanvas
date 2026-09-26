/**
 * Per-finding status, kept in the browser only.
 *
 * A status is the reader's own triage note ("we fixed this", "we accept this"); it never
 * feeds back into severity, confidence or priority, which stay server-computed (CLAUDE.md
 * rule 2). Statuses live in localStorage under one key per repository and ref, as
 * { [threatId]: status }. "open" is the default and is never stored.
 *
 * The storage object is injected, so this module is pure and tests in plain Node. Every
 * storage access is wrapped: private windows, blocked storage and a full quota all throw,
 * and none of them may break the dashboard.
 */

import type { Priority } from "@/shared/schema";

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

/** Only threats with a non-open status appear; a missing id means "open". */
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

/**
 * Returns the map with one status changed, and saves it. The returned map is correct even
 * when the save fails, so the page still reflects the choice for this visit.
 */
export function setStatus(
  storage: StatusStorage | null | undefined,
  key: string,
  current: StatusMap,
  threatId: string,
  status: FindingStatus,
): StatusMap {
  const next: Record<string, FindingStatus> = { ...current };
  if (status === "open") delete next[threatId];
  else next[threatId] = status;
  try {
    storage?.setItem(key, JSON.stringify(next));
  } catch {
    // Storage unavailable or full: keep the in-memory choice.
  }
  return next;
}

export function statusOf(statuses: StatusMap, threatId: string): FindingStatus {
  const value = statuses[threatId];
  return value === undefined ? "open" : value;
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
