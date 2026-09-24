import { describe, expect, it } from "vitest";
import { NO_TOKENS, UsageLedger, type CallUsage } from "@/server/ai/usage";
import { batchElements } from "@/server/analysis/threats";
import type { Component, DataFlow, Evidence } from "@/shared/schema";
import {
  MAX_BATCHES_WITHOUT_FLAG,
  batchLimitMessage,
  classifyThreat,
  formatUsageLines,
} from "../scripts/try-threats-lib";

const component = (id: string): Component => ({
  id,
  name: id,
  type: "backend",
  description: id,
  technologies: [],
  files: [],
  assets: [],
});
const flow = (id: string, sourceId: string, targetId: string): DataFlow => ({
  id,
  sourceId,
  targetId,
  label: id,
  dataClassification: "internal",
  crossesTrustBoundary: false,
});

/** The saved bezkoder architecture after the N2 merge: 5 components and 9 flows = 14 elements. */
function savedShape() {
  const ids = [
    "df-root",
    "df-signin",
    "df-signout",
    "df-signup",
    "df-test-admin",
    "df-test-all",
    "df-test-mod",
    "df-test-user",
  ];
  return {
    components: [
      "client",
      "datastore-mysql",
      "datastore-sequelize",
      "express-api",
      "mysql-db",
    ].map(component),
    dataFlows: [
      ...ids.map((id) => flow(id, "client", "express-api")),
      flow("df-api-db", "express-api", "mysql-db"),
    ],
  };
}

describe("the live-run batch safety limit", () => {
  it("allows up to eight batches by default", () => {
    expect(MAX_BATCHES_WITHOUT_FLAG).toBe(8);
  });

  it("accepts the 14-element saved shape, which needs seven batches, without --allow-large", () => {
    const shape = savedShape();
    expect(shape.components.length + shape.dataFlows.length).toBe(14);
    const batches = batchElements(shape);
    expect(batches).toHaveLength(7);
    expect(batchLimitMessage(batches.length, false)).toBeUndefined();
  });

  it("accepts exactly eight and refuses nine without the flag", () => {
    expect(batchLimitMessage(8, false)).toBeUndefined();
    const refusal = batchLimitMessage(9, false);
    expect(refusal).toContain("9 batches");
    expect(refusal).toContain("--allow-large");
  });

  it("accepts any size with --allow-large", () => {
    expect(batchLimitMessage(9, true)).toBeUndefined();
    expect(batchLimitMessage(40, true)).toBeUndefined();
  });

  it("accepts an empty or one-batch plan", () => {
    expect(batchLimitMessage(0, false)).toBeUndefined();
    expect(batchLimitMessage(1, false)).toBeUndefined();
  });
});

describe("classifyThreat", () => {
  const ev = (id: string, ruleId?: string): Evidence => ({
    id,
    kind: "code",
    source: "detector",
    summary: id,
    ...(ruleId ? { ruleId } : {}),
  });
  const byId = new Map([
    ["ev-1", ev("ev-1")],
    ["ev-gap-1", ev("ev-gap-1", "gap:authz_missing")],
  ]);

  it("calls a threat citing a non-gap item confirmed", () => {
    expect(classifyThreat(["ev-gap-1", "ev-1"], byId)).toBe("confirmed");
  });
  it("calls a threat citing only gaps gap-only", () => {
    expect(classifyThreat(["ev-gap-1"], byId)).toBe("gap-only");
  });
  it("calls a threat citing nothing that resolves assumption-only", () => {
    expect(classifyThreat([], byId)).toBe("assumption-only");
    expect(classifyThreat(["ev-missing"], byId)).toBe("assumption-only");
  });
});

describe("formatUsageLines", () => {
  const call = (over: Partial<CallUsage> = {}): CallUsage => ({
    stage: "stride",
    model: "claude-sonnet-5",
    ...NO_TOKENS,
    requests: 1,
    costUsd: 0,
    ...over,
  });

  it("says plainly when nothing was recorded, so a connection failure invents no usage", () => {
    const lines = formatUsageLines(new UsageLedger().forAnalysis("x"));
    expect(lines).toEqual(["usage: none recorded (no response was received)"]);
  });

  it("prints every recorded field and the total cost, for a call that succeeded", () => {
    const ledger = new UsageLedger();
    ledger.record(
      "x",
      call({
        callId: "call-9",
        attempt: 1,
        inputTokens: 1200,
        outputTokens: 3400,
        thinkingTokens: 2100,
        cacheReadTokens: 800,
        cacheWriteTokens: 90,
        stopReason: "end_turn",
        responseModel: "claude-sonnet-5-20260901",
        costUsd: 0.0123,
      }),
    );
    const lines = formatUsageLines(ledger.forAnalysis("x"));
    const text = lines.join("\n");
    const perCall = lines.find((l) => l.startsWith("  call-9 attempt 1:"))!;
    const total = lines.find((l) => l.startsWith("  total:"))!;
    expect(text).toContain("1 provider response(s) recorded");
    // The per-call line and the total line each carry every field: one cannot stand in for the other.
    for (const line of [perCall, total]) {
      for (const part of ["in 1200 out 3400", "thinking 2100", "cache-read 800", "cache-write 90"]) {
        expect(line).toContain(part);
      }
    }
    for (const part of ["stride", "claude-sonnet-5-20260901", "stop end_turn", "requests 1", "$0.0123"]) {
      expect(perCall).toContain(part);
    }
    expect(text).toContain("cost: $0.0123");
  });

  it("prints usage for a call that FAILED, including its stop reason, so a failed run still reports cost", () => {
    const ledger = new UsageLedger();
    ledger.record(
      "x",
      call({
        inputTokens: 500,
        outputTokens: 12000,
        thinkingTokens: 11000,
        stopReason: "max_tokens",
        costUsd: 0.121,
      }),
    );
    const text = formatUsageLines(ledger.forAnalysis("x")).join("\n");
    expect(text).toContain("stop max_tokens");
    expect(text).toContain("out 12000");
    expect(text).toContain("thinking 11000");
    expect(text).toContain("cost: $0.1210");
  });

  it("shows both attempts of a retried call, each on its own line, and a total that includes both", () => {
    const ledger = new UsageLedger();
    ledger.record("x", call({ callId: "call-3", attempt: 1, inputTokens: 100, outputTokens: 20, costUsd: 0.001, stopReason: "end_turn" }));
    ledger.record("x", call({ callId: "call-3", attempt: 2, inputTokens: 100, outputTokens: 20, costUsd: 0.001, stopReason: "end_turn" }));
    const lines = formatUsageLines(ledger.forAnalysis("x"));
    expect(lines.filter((l) => l.startsWith("  call-3 attempt "))).toHaveLength(2);
    expect(lines.some((l) => l.startsWith("  call-3 attempt 1:"))).toBe(true);
    expect(lines.some((l) => l.startsWith("  call-3 attempt 2:"))).toBe(true);
    expect(lines.find((l) => l.startsWith("  total:"))).toContain("in 200 out 40");
    expect(lines.join("\n")).toContain("cost: $0.0020");
  });

  it("sums several calls and reports an unknown stop reason honestly", () => {
    const ledger = new UsageLedger();
    ledger.record("x", call({ inputTokens: 100, outputTokens: 10, costUsd: 0.001 }));
    ledger.record(
      "x",
      call({ inputTokens: 200, outputTokens: 20, costUsd: 0.002, stopReason: "end_turn" }),
    );
    const text = formatUsageLines(ledger.forAnalysis("x")).join("\n");
    expect(text).toContain("2 provider response(s) recorded");
    expect(text).toContain("stop unknown");
    expect(text).toContain("total: in 300 out 30");
    expect(text).toContain("cost: $0.0030");
  });
});
