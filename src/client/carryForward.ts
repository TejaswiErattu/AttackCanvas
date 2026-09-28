/**
 * Threats the previous run listed at 25% confidence or above that this run did not find,
 * and that the reader has not marked Fixed or False positive. The drift panel reports how
 * many ("k of them not marked Fixed or False positive").
 *
 * A threat can vanish from a run because the code changed, or because a model run sampled
 * differently. Nothing here can tell which, so only a status the reader set closes it.
 *
 * Pure: statuses are the stored threatKey-keyed map (src/client/findingStatus.ts).
 */

import type { DriftResult, ThreatRef } from "@/client/drift";
import { statusOf, type FindingStatus, type StatusMap } from "@/client/findingStatus";

/** Statuses that close a threat; anything else (open, accepted risk) carries it forward. */
const CLOSED: ReadonlySet<FindingStatus> = new Set<FindingStatus>(["fixed", "false_positive"]);

export type CarriedThreat = ThreatRef & { status: FindingStatus };

export function carryForward(
  drift: DriftResult | null,
  statusesByKey: StatusMap,
): CarriedThreat[] {
  if (!drift) return [];
  return drift.threats.notFound
    .filter((ref) => !ref.belowCutoff)
    .map((ref) => ({ ...ref, status: statusOf(statusesByKey, ref.key) }))
    .filter((ref) => !CLOSED.has(ref.status));
}
