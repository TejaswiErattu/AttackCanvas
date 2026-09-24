/**
 * The pure parts of scripts/try-threats.ts, kept in their own module so tests can import
 * them: the script itself runs a live, paid check the moment it is loaded.
 */

import { formatUsd, type AnalysisUsage } from "@/server/ai/usage";
import { isGapEvidence } from "@/server/scoring";
import type { Evidence } from "@/shared/schema";

/**
 * A guard, not a limit of the engine: each batch is a paid call. Two-element batching of
 * the saved 14-element bezkoder architecture needs 7, so the guard sits at 8; more needs
 * --allow-large.
 */
export const MAX_BATCHES_WITHOUT_FLAG = 8;

/** The refusal to print when a plan is too large, or undefined when it may run. */
export function batchLimitMessage(
  batchCount: number,
  allowLarge: boolean,
): string | undefined {
  if (batchCount <= MAX_BATCHES_WITHOUT_FLAG || allowLarge) return undefined;
  return (
    `${batchCount} batches means ${batchCount} paid calls, more than the ` +
    `${MAX_BATCHES_WITHOUT_FLAG} allowed by default. Re-run with --allow-large to go ahead.`
  );
}

export type ThreatKind = "confirmed" | "gap-only" | "assumption-only";

/** "confirmed" cites a positive observation; "gap-only" cites only gaps; else assumption-only. */
export function classifyThreat(
  evidenceIds: readonly string[],
  byId: ReadonlyMap<string, Evidence>,
): ThreatKind {
  const cited = evidenceIds.flatMap((id) => {
    const e = byId.get(id);
    return e ? [e] : [];
  });
  if (cited.some((e) => !isGapEvidence(e))) return "confirmed";
  return cited.length > 0 ? "gap-only" : "assumption-only";
}

/**
 * What the ledger holds for one analysis, as lines to print. Used on success AND failure,
 * so a run that dies mid-way still reports what it was billed for. An empty ledger says so
 * plainly: a call that received no response records no usage.
 */
export function formatUsageLines(usage: AnalysisUsage): string[] {
  if (usage.calls.length === 0) {
    return ["usage: none recorded (no response was received)"];
  }
  const lines = usage.calls.map((c) => {
    const stop = c.stopReason ?? "unknown";
    const who = c.callId ? `${c.callId} attempt ${c.attempt ?? "?"}` : "call";
    return (
      `  ${who}: ${c.stage} ${c.responseModel ?? c.model} | stop ${stop} | ` +
      `requests ${c.requests} | in ${c.inputTokens} out ${c.outputTokens} ` +
      `(thinking ${c.thinkingTokens}) cache-read ${c.cacheReadTokens} ` +
      `cache-write ${c.cacheWriteTokens} | ${formatUsd(c.costUsd)}`
    );
  });
  const t = usage.totals;
  return [
    `usage: ${usage.calls.length} provider response(s) recorded`,
    ...lines,
    `  total: in ${t.inputTokens} out ${t.outputTokens} (thinking ${t.thinkingTokens}) ` +
      `cache-read ${t.cacheReadTokens} cache-write ${t.cacheWriteTokens}`,
    `cost: ${formatUsd(usage.totalUsd)} (estimated from list prices)`,
  ];
}
