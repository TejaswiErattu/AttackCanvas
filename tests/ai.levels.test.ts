import { describe, expect, it } from "vitest";
import {
  DEEP_CONTEXT_TOKENS,
  EXHAUSTIVE_THINKING_BUDGET,
  LEVEL_COST_RANGES,
  LEVEL_PLANS,
  SNAPSHOT_CONTEXT_TOKENS,
  SNAPSHOT_MAX_BATCHES,
  planFor,
} from "@/server/ai/levels";
import { AI_STAGES, MODELS, modelFor } from "@/server/ai/models";
import { formatCostRange } from "@/shared/levelCost";

const SONNET = "claude-sonnet-5";
const HAIKU = "claude-haiku-4-5-20251001";
const OPUS = "claude-opus-5";
const LEVELS = [0, 1, 2, 3, 4] as const;

describe("level 2 matches the code before levels existed", () => {
  // Literal values copied from the pre-change constants, so a drift in either shows up.
  it("uses the demo profile's models on every stage", () => {
    const plan = planFor(2, "demo");
    for (const stage of AI_STAGES) {
      expect(plan.models[stage]).toBe(modelFor(stage, "demo"));
    }
  });

  it("keeps the pre-H demo model ids, budgets, batching, questions and thinking", () => {
    // Literals, not MODELS.demo: an edit to the profile table must not silently move the
    // evaluated setup (the six NodeGoat runs in docs/cost.md).
    expect(planFor(2, "demo")).toEqual({
      models: {
        architecture: "claude-opus-5",
        stride: "claude-opus-5",
        questions: "claude-sonnet-5",
        remediation: "claude-sonnet-5",
        classify: "claude-haiku-4-5-20251001",
      },
      architecture: { contextTokens: 60_000, maxTokens: 12_000, thinking: { type: "disabled" } },
      stride: { maxBatches: null, maxTokens: 12_000, thinking: { type: "disabled" } },
      questions: true,
    });
  });

  it("under dev is exactly today's dev run", () => {
    const plan = planFor(2, "dev");
    for (const stage of AI_STAGES) {
      expect(plan.models[stage]).toBe(modelFor(stage, "dev"));
    }
    expect(plan.architecture.contextTokens).toBe(60_000);
  });
});

describe("every level (demo profile)", () => {
  const cases = [
    { level: 0, arch: SONNET, stride: SONNET, questions: SONNET, ctx: SNAPSHOT_CONTEXT_TOKENS, batches: SNAPSHOT_MAX_BATCHES, thinking: "disabled", strideMax: 12_000, asks: false },
    { level: 1, arch: SONNET, stride: SONNET, questions: SONNET, ctx: 60_000, batches: null, thinking: "disabled", strideMax: 12_000, asks: true },
    { level: 2, arch: OPUS, stride: OPUS, questions: SONNET, ctx: 60_000, batches: null, thinking: "disabled", strideMax: 12_000, asks: true },
    { level: 3, arch: OPUS, stride: OPUS, questions: SONNET, ctx: DEEP_CONTEXT_TOKENS, batches: null, thinking: "disabled", strideMax: 12_000, asks: true },
    { level: 4, arch: OPUS, stride: OPUS, questions: SONNET, ctx: DEEP_CONTEXT_TOKENS, batches: null, thinking: "adaptive", strideMax: 12_000 + EXHAUSTIVE_THINKING_BUDGET, asks: true },
  ] as const;

  it.each(cases)("level $level", (c) => {
    const plan = planFor(c.level, "demo");
    expect(plan.models.architecture).toBe(c.arch);
    expect(plan.models.stride).toBe(c.stride);
    expect(plan.models.questions).toBe(c.questions);
    expect(plan.models.classify).toBe(HAIKU);
    expect(plan.architecture.contextTokens).toBe(c.ctx);
    expect(plan.architecture.maxTokens).toBe(12_000);
    expect(plan.stride.maxBatches).toBe(c.batches);
    expect(plan.stride.thinking.type).toBe(c.thinking);
    expect(plan.stride.maxTokens).toBe(c.strideMax);
    expect(plan.questions).toBe(c.asks);
  });

  it("level 4's STRIDE budget stays below the non-streaming ceiling", () => {
    expect(LEVEL_PLANS[4].stride.maxTokens).toBeLessThan(21_333);
  });
});

describe("dev profile", () => {
  it.each(LEVELS)("overrides every model at level %i but keeps the level's work", (level) => {
    const plan = planFor(level, "dev");
    expect(plan.models).toEqual(MODELS.dev);
    for (const stage of AI_STAGES) expect(plan.models[stage]).not.toBe(OPUS);
    expect(plan.architecture).toEqual(LEVEL_PLANS[level].architecture);
    expect(plan.stride).toEqual(LEVEL_PLANS[level].stride);
    expect(plan.questions).toBe(LEVEL_PLANS[level].questions);
  });
});

describe("profile-routed stages", () => {
  // remediation and classify have no call site; if one is added it would fall back to
  // modelFor(stage). This pins that the fallback and the plan agree at every level.
  it.each(LEVELS)("remediation and classify match modelFor at level %i", (level) => {
    for (const profile of ["dev", "demo"] as const) {
      const plan = planFor(level, profile);
      expect(plan.models.remediation).toBe(modelFor("remediation", profile));
      expect(plan.models.classify).toBe(modelFor("classify", profile));
    }
  });
});

describe("cost ranges", () => {
  it.each(LEVELS)("level %i has an ordered range and reads as a sentence", (level) => {
    const { low, high } = LEVEL_COST_RANGES[level];
    expect(low).toBeLessThan(high);
    expect(formatCostRange(level)).toMatch(/^about \$[\d.]+ to \$[\d.]+ for a small repository$/);
  });

  it("formats level 0 and level 2", () => {
    expect(formatCostRange(0)).toBe("about $0.30 to $0.60 for a small repository");
    expect(formatCostRange(2)).toBe("about $3 to $4 for a small repository");
    expect(formatCostRange(1)).toBe("about $1 to $1.50 for a small repository");
  });
});
