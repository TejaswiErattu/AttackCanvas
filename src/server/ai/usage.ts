/**
 * What each model call cost, and what an analysis cost in total.
 *
 * The cost is an ESTIMATE: list price multiplied by reported tokens. It exists so a
 * run can be priced without opening the billing console, and so the cost of the
 * evidence-only pipeline can be compared against the cost once predicted threats are
 * being generated. Nothing here is a billing record.
 *
 * Pure except for the ledger, which is a Map. Nothing logs.
 */

import {
  CACHE_READ_MULTIPLIER,
  CACHE_WRITE_MULTIPLIER,
  priceFor,
  type AiStage,
  type ModelId,
} from "@/server/ai/models";

const PER_MILLION = 1_000_000;

/** Token counts as the API reports them. Every field is optional-with-zero: the API
 * returns null for input_tokens on some responses, and absent cache fields when the
 * request did not use caching. */
export type TokenCounts = {
  inputTokens: number;
  outputTokens: number;
  /**
   * Output tokens the model spent on internal reasoning. INCLUDED in `outputTokens`, which
   * is the authoritative billed total, so it is reported but never priced separately.
   */
  thinkingTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
};

export const NO_TOKENS: TokenCounts = {
  inputTokens: 0,
  outputTokens: 0,
  thinkingTokens: 0,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
};

/** One model call. Carries counts and cost only -- never prompt text, never a key. */
export type CallUsage = TokenCounts & {
  stage: AiStage;
  model: ModelId;
  /** Requests actually sent, including retries for validation and for backoff. */
  requests: number;
  costUsd: number;
  /** Why the response stopped ("end_turn", "max_tokens", ...). */
  stopReason?: string;
  /** The model id the API reported for the response, which can be a dated snapshot. */
  responseModel?: string;
  /** Identifies the logical structured call this response belongs to. */
  callId?: string;
  /** Which provider response of that call this is: 1, or 2 after a validation retry. */
  attempt?: number;
};

/**
 * Estimated USD for one call. Cache reads are billed well below a fresh input token
 * and cache writes slightly above, so both are priced off the input rate rather than
 * folded into it.
 */
export function estimateCostUsd(model: ModelId, tokens: TokenCounts): number {
  const price = priceFor(model);
  const units =
    tokens.inputTokens * price.input +
    tokens.outputTokens * price.output +
    tokens.cacheReadTokens * price.input * CACHE_READ_MULTIPLIER +
    tokens.cacheWriteTokens * price.input * CACHE_WRITE_MULTIPLIER;
  return units / PER_MILLION;
}

/** Adds two token counts, for accumulating the retries of one logical call. */
export function addTokens(a: TokenCounts, b: TokenCounts): TokenCounts {
  return {
    inputTokens: a.inputTokens + b.inputTokens,
    outputTokens: a.outputTokens + b.outputTokens,
    thinkingTokens: a.thinkingTokens + b.thinkingTokens,
    cacheReadTokens: a.cacheReadTokens + b.cacheReadTokens,
    cacheWriteTokens: a.cacheWriteTokens + b.cacheWriteTokens,
  };
}

export type AnalysisUsage = {
  analysisId: string;
  calls: readonly CallUsage[];
  totals: TokenCounts;
  totalUsd: number;
};

/**
 * Per-analysis running totals. In-process and unbounded on purpose: an analysis makes
 * on the order of ten calls and the entry is dropped with `clear` when the analysis
 * finishes. A long-lived server must call `clear`, which is why it exists.
 */
export class UsageLedger {
  private readonly byAnalysis = new Map<string, CallUsage[]>();

  /**
   * Records one provider response. Every response is billable, so a call that needed a
   * validation retry has two entries, one per attempt, and the totals include both.
   *
   * Idempotent for an attempt that carries an identity: recording the same
   * (callId, attempt) again returns the entry already stored and adds nothing, so the same
   * response cannot be counted twice. An entry with no identity is always appended.
   */
  record(analysisId: string, call: CallUsage): CallUsage {
    const calls = this.byAnalysis.get(analysisId);
    if (call.callId !== undefined && call.attempt !== undefined && calls) {
      const existing = calls.find(
        (c) => c.callId === call.callId && c.attempt === call.attempt,
      );
      if (existing) return existing;
    }
    if (calls) calls.push(call);
    else this.byAnalysis.set(analysisId, [call]);
    return call;
  }

  forAnalysis(analysisId: string): AnalysisUsage {
    const calls = this.byAnalysis.get(analysisId) ?? [];
    const totals = calls.reduce<TokenCounts>(
      (acc, call) => addTokens(acc, call),
      NO_TOKENS,
    );
    const totalUsd = calls.reduce((sum, call) => sum + call.costUsd, 0);
    return { analysisId, calls: [...calls], totals, totalUsd };
  }

  clear(analysisId?: string): void {
    if (analysisId === undefined) this.byAnalysis.clear();
    else this.byAnalysis.delete(analysisId);
  }
}

/** The ledger the pipeline shares. Tests inject their own rather than use this. */
export const usageLedger = new UsageLedger();

/** "$0.0432", for a script or a log line. Four places: a cheap call is sub-cent. */
export function formatUsd(usd: number): string {
  return `$${usd.toFixed(4)}`;
}
