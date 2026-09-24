import { describe, expect, it } from "vitest";
import {
  CACHE_READ_MULTIPLIER,
  CACHE_WRITE_MULTIPLIER,
  PRICES,
} from "@/server/ai/models";
import {
  NO_TOKENS,
  UsageLedger,
  addTokens,
  estimateCostUsd,
  formatUsd,
  type CallUsage,
  type TokenCounts,
} from "@/server/ai/usage";

const tokens = (partial: Partial<TokenCounts> = {}): TokenCounts => ({
  ...NO_TOKENS,
  ...partial,
});

const call = (partial: Partial<CallUsage> = {}): CallUsage => ({
  stage: "architecture",
  model: "claude-sonnet-5",
  ...NO_TOKENS,
  requests: 1,
  costUsd: 0,
  ...partial,
});

describe("estimateCostUsd", () => {
  it("prices input and output at the per-million rate", () => {
    // Sonnet: $2/M in, $10/M out. 1M in + 1M out = $12.
    expect(
      estimateCostUsd("claude-sonnet-5", {
        ...NO_TOKENS,
        inputTokens: 1_000_000,
        outputTokens: 1_000_000,
      }),
    ).toBeCloseTo(12, 10);
  });

  it("uses each model's own rates", () => {
    const one = tokens({ inputTokens: 1_000_000 });
    expect(estimateCostUsd("claude-opus-5", one)).toBeCloseTo(5, 10);
    expect(estimateCostUsd("claude-sonnet-5", one)).toBeCloseTo(2, 10);
    expect(estimateCostUsd("claude-haiku-4-5-20251001", one)).toBeCloseTo(1, 10);
  });

  it("prices a cache read well below a fresh input token", () => {
    const read = estimateCostUsd(
      "claude-sonnet-5",
      tokens({ cacheReadTokens: 1_000_000 }),
    );
    const fresh = estimateCostUsd(
      "claude-sonnet-5",
      tokens({ inputTokens: 1_000_000 }),
    );
    expect(read).toBeCloseTo(fresh * CACHE_READ_MULTIPLIER, 10);
    expect(read).toBeLessThan(fresh);
    // The whole reason caching is worth wiring up.
    expect(read).toBeCloseTo(0.2, 10);
  });

  it("prices a cache write slightly above a fresh input token", () => {
    const write = estimateCostUsd(
      "claude-opus-5",
      tokens({ cacheWriteTokens: 1_000_000 }),
    );
    expect(write).toBeCloseTo(PRICES["claude-opus-5"].input * CACHE_WRITE_MULTIPLIER, 10);
    expect(write).toBeGreaterThan(estimateCostUsd("claude-opus-5", tokens({ inputTokens: 1_000_000 })));
  });

  it("is zero for no tokens and never negative", () => {
    expect(estimateCostUsd("claude-opus-5", NO_TOKENS)).toBe(0);
  });

  it("sums the four token kinds rather than picking one", () => {
    const mixed = tokens({
      inputTokens: 1000,
      outputTokens: 500,
      cacheReadTokens: 10_000,
      cacheWriteTokens: 2000,
    });
    const expected =
      (1000 * 2 + 500 * 10 + 10_000 * 2 * 0.1 + 2000 * 2 * 1.25) / 1_000_000;
    expect(estimateCostUsd("claude-sonnet-5", mixed)).toBeCloseTo(expected, 12);
  });
});

describe("addTokens", () => {
  it("adds each field independently", () => {
    expect(
      addTokens(
        tokens({ inputTokens: 1, outputTokens: 2, thinkingTokens: 1, cacheReadTokens: 3 }),
        tokens({ inputTokens: 10, thinkingTokens: 5, cacheReadTokens: 30, cacheWriteTokens: 40 }),
      ),
    ).toEqual({
      inputTokens: 11,
      outputTokens: 2,
      thinkingTokens: 6,
      cacheReadTokens: 33,
      cacheWriteTokens: 40,
    });
  });

  it("leaves NO_TOKENS unmutated when used as a reduce seed", () => {
    addTokens(NO_TOKENS, tokens({ inputTokens: 99 }));
    expect(NO_TOKENS).toEqual({
      inputTokens: 0,
      outputTokens: 0,
      thinkingTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });
});

describe("UsageLedger", () => {
  it("returns an empty analysis for an id it has never seen", () => {
    const ledger = new UsageLedger();
    const usage = ledger.forAnalysis("nothing-here");
    expect(usage.calls).toEqual([]);
    expect(usage.totalUsd).toBe(0);
    expect(usage.totals).toEqual(NO_TOKENS);
  });

  it("accumulates calls and money per analysis", () => {
    const ledger = new UsageLedger();
    ledger.record("a", call({ inputTokens: 100, costUsd: 0.01 }));
    ledger.record("a", call({ stage: "stride", outputTokens: 50, costUsd: 0.02 }));

    const usage = ledger.forAnalysis("a");
    expect(usage.calls).toHaveLength(2);
    expect(usage.totals.inputTokens).toBe(100);
    expect(usage.totals.outputTokens).toBe(50);
    expect(usage.totalUsd).toBeCloseTo(0.03, 10);
  });

  it("keeps analyses apart", () => {
    const ledger = new UsageLedger();
    ledger.record("a", call({ costUsd: 1 }));
    ledger.record("b", call({ costUsd: 2 }));
    expect(ledger.forAnalysis("a").totalUsd).toBe(1);
    expect(ledger.forAnalysis("b").totalUsd).toBe(2);
  });

  it("hands back a copy, so a caller cannot grow the ledger", () => {
    const ledger = new UsageLedger();
    ledger.record("a", call({ costUsd: 1 }));
    const first = ledger.forAnalysis("a");
    (first.calls as CallUsage[]).push(call({ costUsd: 99 }));
    expect(ledger.forAnalysis("a").calls).toHaveLength(1);
    expect(ledger.forAnalysis("a").totalUsd).toBe(1);
  });

  it("clears one analysis, or all of them", () => {
    const ledger = new UsageLedger();
    ledger.record("a", call({ costUsd: 1 }));
    ledger.record("b", call({ costUsd: 2 }));

    ledger.clear("a");
    expect(ledger.forAnalysis("a").calls).toEqual([]);
    expect(ledger.forAnalysis("b").calls).toHaveLength(1);

    ledger.clear();
    expect(ledger.forAnalysis("b").calls).toEqual([]);
  });

  it("records no prompt text -- only counts, cost, stage and model", () => {
    const ledger = new UsageLedger();
    ledger.record("a", call({ inputTokens: 5, costUsd: 0.001 }));
    const [only] = ledger.forAnalysis("a").calls;
    expect(Object.keys(only).sort()).toEqual(
      [
        "cacheReadTokens",
        "cacheWriteTokens",
        "costUsd",
        "inputTokens",
        "model",
        "outputTokens",
        "requests",
        "stage",
        "thinkingTokens",
      ].sort(),
    );
  });
});

describe("UsageLedger, one entry per provider response", () => {
  const attempt = (n: number, over: Partial<CallUsage> = {}) =>
    call({ callId: "call-1", attempt: n, inputTokens: 100, outputTokens: 20, costUsd: 0.001, ...over });

  it("counts two attempts of one call as two, so two 100-token attempts total 200", () => {
    const ledger = new UsageLedger();
    ledger.record("a", attempt(1));
    ledger.record("a", attempt(2));
    const total = ledger.forAnalysis("a");
    expect(total.calls).toHaveLength(2);
    expect(total.totals.inputTokens).toBe(200);
    expect(total.totals.outputTokens).toBe(40);
    expect(total.totalUsd).toBeCloseTo(0.002, 12);
  });

  it("is idempotent: recording the same (call, attempt) again adds nothing", () => {
    const ledger = new UsageLedger();
    const first = ledger.record("a", attempt(1));
    const again = ledger.record("a", attempt(1, { inputTokens: 999 }));
    expect(again).toBe(first);
    expect(ledger.forAnalysis("a").calls).toEqual([first]);
    expect(ledger.forAnalysis("a").totals.inputTokens).toBe(100);
  });

  it("does not confuse another attempt, another call, or another analysis", () => {
    const ledger = new UsageLedger();
    ledger.record("a", attempt(1));
    ledger.record("a", attempt(2));
    ledger.record("a", call({ callId: "call-2", attempt: 1, inputTokens: 5 }));
    ledger.record("b", attempt(1));
    expect(ledger.forAnalysis("a").calls).toHaveLength(3);
    expect(ledger.forAnalysis("b").calls).toHaveLength(1);
  });

  it("always appends an entry that carries no identity", () => {
    const ledger = new UsageLedger();
    ledger.record("a", call({ inputTokens: 1 }));
    ledger.record("a", call({ inputTokens: 1 }));
    expect(ledger.forAnalysis("a").calls).toHaveLength(2);
  });

  it("needs both the call and the attempt to match", () => {
    const ledger = new UsageLedger();
    ledger.record("a", call({ callId: "call-1", inputTokens: 1 }));
    ledger.record("a", call({ callId: "call-1", inputTokens: 1 }));
    ledger.record("a", call({ attempt: 1, inputTokens: 1 }));
    ledger.record("a", call({ attempt: 1, inputTokens: 1 }));
    expect(ledger.forAnalysis("a").calls).toHaveLength(4);
  });

  it("reports thinking tokens in the totals without pricing them separately", () => {
    const ledger = new UsageLedger();
    ledger.record("a", call({ outputTokens: 1000, thinkingTokens: 800 }));
    expect(ledger.forAnalysis("a").totals.thinkingTokens).toBe(800);
    const priced = estimateCostUsd("claude-sonnet-5", tokens({ outputTokens: 1000, thinkingTokens: 800 }));
    expect(priced).toBeCloseTo(estimateCostUsd("claude-sonnet-5", tokens({ outputTokens: 1000 })), 12);
  });
});

describe("formatUsd", () => {
  it("shows four places, so a sub-cent call is not rounded to nothing", () => {
    expect(formatUsd(0.00042)).toBe("$0.0004");
    expect(formatUsd(1.5)).toBe("$1.5000");
    expect(formatUsd(0)).toBe("$0.0000");
  });
});
