/**
 * "Still open from the last run": threats the previous run listed that this run did not
 * find, and that the reader has not marked Fixed or False positive.
 *
 * A threat can vanish from a run because the code changed, or because a model run sampled
 * differently. Nothing here can tell which, so a threat the reader has not closed stays in
 * view, greyed, with the severity and confidence the previous run gave it. It is display
 * only: carried threats never enter this run's counts, filters or Fix now.
 *
 * Only threats that were visible in the previous run are carried. One that was already
 * below 25% confidence then is listed under "Not found this run" in the drift panel but is
 * not carried, so a hidden threat never appears without the reader asking for it.
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
