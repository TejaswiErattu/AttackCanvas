/**
 * The per-run spend cap.
 *
 * ATTACKCANVAS_MAX_RUN_USD is the most one analysis may spend, in USD, as the usage ledger
 * estimates it (list price times reported tokens). callStructured checks it before every
 * provider request; once an analysis's recorded cost has reached the cap, the next request
 * is refused with an AiError coded SPEND_CAP and the job fails.
 *
 * It is a stop before the next call, not a ceiling on the invoice: a call already in
 * flight is billed and recorded after the check passed, and the threat stage runs several
 * batches at once, so a run can end above the cap by what those in-flight calls cost. A
 * response served from the model cache costs nothing and is never refused.
 *
 * Unset, blank, or not a positive finite number, the default applies: a cap is never
 * switched off by a typo. Pure: the environment and the ledger's total are passed in.
 */

export const MAX_RUN_USD_ENV = "ATTACKCANVAS_MAX_RUN_USD";

/** Above the highest level-4 estimate in docs/cost.md ($5.90), below a surprise. */
export const DEFAULT_MAX_RUN_USD = 6;

export function maxRunUsd(env: Record<string, string | undefined> = process.env): number {
  const raw = env[MAX_RUN_USD_ENV]?.trim();
  if (!raw) return DEFAULT_MAX_RUN_USD;
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_MAX_RUN_USD;
}

/** True when `spentUsd` has reached `capUsd`: the next model call must not be made. */
export function spendCapReached(spentUsd: number, capUsd: number): boolean {
  return spentUsd >= capUsd;
}

/** Reader-safe: amounts only, to the cent. */
export function describeSpendCap(spentUsd: number, capUsd: number): string {
  return `spent $${spentUsd.toFixed(2)} of the $${capUsd.toFixed(2)} per-run limit`;
}
