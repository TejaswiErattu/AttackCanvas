/**
 * The per-run spend cap (src/server/ai/spendGuard.ts) as callStructured and the pipeline
 * use it. A fake ledger reports whatever total a test needs; a scripted client counts
 * requests, so "no further model call" is a count of zero.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { AiError, callStructured, type ClaudeDeps, type MessagesApi } from "@/server/ai/claude";
import { fileModelCache } from "@/server/ai/modelCache";
import {
  DEFAULT_MAX_RUN_USD,
  MAX_RUN_USD_ENV,
  describeSpendCap,
  maxRunUsd,
  spendCapReached,
} from "@/server/ai/spendGuard";
import { UsageLedger, type AnalysisUsage, type CallUsage } from "@/server/ai/usage";
import { ERROR_COPY } from "@/shared/labels";
import { ErrorCodeSchema } from "@/shared/schema";
import { createAnalysis, getAnalysis, runAnalysis, toErrorCode, resetStore } from "@/server/analysis/pipeline";
import { loadCanaryRepo } from "./canaryRepo";

const Output = z.object({ summary: z.string() });
const JSON_SCHEMA = z.toJSONSchema(Output) as Record<string, unknown>;

function reply(text: string, outputTokens = 20): Anthropic.Message {
  return {
    id: "msg_test",
    type: "message",
    role: "assistant",
    model: "claude-sonnet-5",
    content: [{ type: "text", text, citations: null }],
    stop_reason: "end_turn",
    stop_sequence: null,
    stop_details: null,
    usage: { input_tokens: 100, output_tokens: outputTokens, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
  } as Anthropic.Message;
}

/** A ledger whose reported total for any analysis is `spent`, and which records nothing. */
function fakeLedger(spent: () => number): UsageLedger {
  const ledger = new UsageLedger();
  ledger.forAnalysis = (analysisId: string): AnalysisUsage => ({
    analysisId,
    calls: [],
    totals: { inputTokens: 0, outputTokens: 0, thinkingTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 },
    totalUsd: spent(),
  });
  ledger.record = (_id: string, call: CallUsage) => call;
  return ledger;
}

function setup(replies: string[], spent: () => number, maxRunUsd = 1, extra: Partial<ClaudeDeps> = {}) {
  let requests = 0;
  const client: MessagesApi = {
    async create() {
      const text = replies[requests];
      requests += 1;
      if (text === undefined) throw new Error("unexpected request");
      return reply(text);
    },
  };
  const deps: Partial<ClaudeDeps> = {
    client,
    ledger: fakeLedger(spent),
    isDevelopment: false,
    sleep: async () => {},
    schedule: () => () => {},
    modelCache: undefined,
    maxRunUsd,
    ...extra,
  };
  const call = () =>
    callStructured({
      stage: "architecture",
      analysisId: "spend-test",
      system: "You are a security reviewer.",
      user: '<repo_file path="a.js">\nx\n</repo_file>',
      schema: Output,
      jsonSchema: JSON_SCHEMA,
      deps,
    });
  return { call, requests: () => requests };
}

describe("maxRunUsd", () => {
  it("defaults to 6 when unset, blank, or not a positive finite number", () => {
    expect(DEFAULT_MAX_RUN_USD).toBe(6);
    for (const value of [undefined, "", "  ", "abc", "0", "-3", "Infinity", "NaN"]) {
      expect(maxRunUsd({ [MAX_RUN_USD_ENV]: value }), String(value)).toBe(6);
    }
  });

  it("reads a positive number", () => {
    expect(maxRunUsd({ [MAX_RUN_USD_ENV]: "2.5" })).toBe(2.5);
    expect(maxRunUsd({ [MAX_RUN_USD_ENV]: " 10 " })).toBe(10);
  });
});

describe("spendCapReached", () => {
  it("is true at the cap, false below it", () => {
    expect(spendCapReached(0.99, 1)).toBe(false);
    expect(spendCapReached(1, 1)).toBe(true);
    expect(spendCapReached(7, 6)).toBe(true);
    expect(describeSpendCap(6.1234, 6)).toBe("spent $6.12 of the $6.00 per-run limit");
  });
});

describe("callStructured with the spend cap", () => {
  it("makes the call when the run is under the cap", async () => {
    const t = setup([JSON.stringify({ summary: "ok" })], () => 0.99);
    expect((await t.call()).value).toEqual({ summary: "ok" });
    expect(t.requests()).toBe(1);
  });

  it("refuses before any request once the run has reached the cap, with SPEND_CAP and the amounts", async () => {
    const t = setup([JSON.stringify({ summary: "never" })], () => 1.5, 1);
    const error = await t.call().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AiError);
    expect((error as AiError).code).toBe("SPEND_CAP");
    expect((error as AiError).spend).toEqual({ spentUsd: 1.5, capUsd: 1 });
    expect(t.requests()).toBe(0);
  });

  it("stops the validation retry when the first reply took the run over the cap", async () => {
    let spent = 0;
    let sent = 0;
    const t = setup([], () => spent, 1, {
      client: {
        async create() {
          sent += 1;
          spent = 1.2; // this response cost enough to pass the cap
          return reply("{}"); // and it fails validation, so a retry would follow
        },
      },
    });
    const error = await t.call().catch((e: unknown) => e);
    expect((error as AiError).code).toBe("SPEND_CAP");
    expect((error as AiError).spend).toEqual({ spentUsd: 1.2, capUsd: 1 });
    expect(sent).toBe(1); // the first request only; the correction retry never started
  });

  it("serves a model-cache hit even over the cap, since it costs nothing", async () => {
    const cache = fileModelCache(mkdtempSync(join(tmpdir(), "spend-cache-")));
    let spent = 0;
    const t = setup([JSON.stringify({ summary: "cached" })], () => spent, 1, { modelCache: cache });
    await t.call();
    spent = 5;
    const again = await t.call();
    expect(again.value).toEqual({ summary: "cached" });
    expect(t.requests()).toBe(1);
  });

  it("never reads another analysis's spend: the cap is per run", async () => {
    const seen: string[] = [];
    const ledger = fakeLedger(() => 0);
    const forAnalysis = ledger.forAnalysis.bind(ledger);
    ledger.forAnalysis = (id) => {
      seen.push(id);
      return forAnalysis(id);
    };
    const t = setup([JSON.stringify({ summary: "ok" })], () => 0, 1, { ledger });
    await t.call();
    expect(seen).toContain("spend-test");
  });
});

describe("SPEND_CAP in the contract and the pipeline", () => {
  it("is an error code with its own copy, and not retryable", () => {
    expect(ErrorCodeSchema.options).toContain("SPEND_CAP");
    expect(ERROR_COPY.SPEND_CAP.title).toBe("Spending limit reached");
  });

  it("maps to the SPEND_CAP code", () => {
    expect(toErrorCode(new AiError("SPEND_CAP", "stopped", { spend: { spentUsd: 6, capUsd: 6 } }))).toBe("SPEND_CAP");
  });

  it("fails the job with SPEND_CAP and records how much was spent", async () => {
    resetStore();
    const state = createAnalysis("https://github.com/acme/canary", 1);
    const done = await runAnalysis(state.id, {
      loadRepository: async () => ({
        summary: {
          owner: "acme",
          name: "canary",
          ref: "main",
          languages: ["JavaScript"],
          frameworks: [],
          fileCountAnalyzed: 0,
          analyzedAt: new Date(0).toISOString(),
        },
        files: loadCanaryRepo(),
        skipped: { ignored: 0, overLimit: 0 },
        truncated: false,
      }),
      scanFiles: async () => [],
      scanDependencies: async () => ({ evidence: [], limitations: [] }),
      inferArchitecture: async () => {
        throw new AiError("SPEND_CAP", "architecture: stopped", { spend: { spentUsd: 6.07, capUsd: 6 } });
      },
    });
    expect(done.stage).toBe("failed");
    expect(done.error?.code).toBe("SPEND_CAP");
    expect(done.error?.message).toBe(ERROR_COPY.SPEND_CAP.message);
    expect(done.diagnostics).toContain("Spend cap reached: spent $6.07 of the $6.00 per-run limit.");
    expect(done.threatModel).toBeUndefined();
    expect(getAnalysis(state.id)?.stage).toBe("failed");
  });
});
