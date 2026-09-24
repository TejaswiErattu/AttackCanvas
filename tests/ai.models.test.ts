import { describe, expect, it } from "vitest";
import {
  AI_STAGES,
  DEFAULT_PROFILE,
  MODELS,
  MODEL_PROFILES,
  PRICES,
  activeProfile,
  isModelProfile,
  modelFor,
  priceFor,
  type AiStage,
  type ModelId,
} from "@/server/ai/models";

const env = (value?: string): Record<string, string | undefined> =>
  value === undefined ? {} : { ATTACKCANVAS_MODEL_PROFILE: value };

describe("activeProfile", () => {
  it("defaults to dev when the variable is unset", () => {
    expect(activeProfile(env())).toBe("dev");
    expect(DEFAULT_PROFILE).toBe("dev");
  });

  it("treats an empty or whitespace value as unset", () => {
    expect(activeProfile(env(""))).toBe("dev");
    expect(activeProfile(env("   "))).toBe("dev");
  });

  it("reads each valid profile, trimming surrounding whitespace", () => {
    expect(activeProfile(env("dev"))).toBe("dev");
    expect(activeProfile(env("demo"))).toBe("demo");
    expect(activeProfile(env(" demo "))).toBe("demo");
  });

  it("throws on a set but unrecognised value rather than falling back", () => {
    // A typo on the demo machine must not silently run the cheap profile.
    expect(() => activeProfile(env("Demo"))).toThrow(/must be one of/);
    expect(() => activeProfile(env("production"))).toThrow(/production/);
  });

  it("does not leak the variable's value into a wider surface than the message", () => {
    expect(isModelProfile("production")).toBe(false);
    expect(isModelProfile("dev")).toBe(true);
    expect(isModelProfile(7)).toBe(false);
  });
});

describe("the profile map", () => {
  it("covers every stage in both profiles", () => {
    for (const profile of MODEL_PROFILES) {
      for (const stage of AI_STAGES) {
        expect(MODELS[profile][stage], `${profile}/${stage}`).toBeTruthy();
      }
      expect(Object.keys(MODELS[profile]).sort()).toEqual([...AI_STAGES].sort());
    }
  });

  it("runs the dev profile on sonnet, with haiku for classification", () => {
    expect(modelFor("architecture", "dev")).toBe("claude-sonnet-5");
    expect(modelFor("stride", "dev")).toBe("claude-sonnet-5");
    expect(modelFor("questions", "dev")).toBe("claude-sonnet-5");
    expect(modelFor("remediation", "dev")).toBe("claude-sonnet-5");
    expect(modelFor("classify", "dev")).toBe("claude-haiku-4-5-20251001");
  });

  it("lifts only architecture and stride to opus on the demo profile", () => {
    expect(modelFor("architecture", "demo")).toBe("claude-opus-5");
    expect(modelFor("stride", "demo")).toBe("claude-opus-5");
    expect(modelFor("questions", "demo")).toBe("claude-sonnet-5");
    expect(modelFor("remediation", "demo")).toBe("claude-sonnet-5");
    expect(modelFor("classify", "demo")).toBe("claude-haiku-4-5-20251001");
  });

  it("only ever moves a stage up, never down, from dev to demo", () => {
    const tier: Record<ModelId, number> = {
      "claude-haiku-4-5-20251001": 0,
      "claude-sonnet-5": 1,
      "claude-opus-5": 2,
    };
    for (const stage of AI_STAGES) {
      expect(tier[MODELS.demo[stage]], stage).toBeGreaterThanOrEqual(
        tier[MODELS.dev[stage]],
      );
    }
  });
});

describe("prices", () => {
  it("matches the published per-million rates", () => {
    expect(PRICES["claude-opus-5"]).toEqual({ input: 5, output: 25 });
    expect(PRICES["claude-sonnet-5"]).toEqual({ input: 2, output: 10 });
    expect(PRICES["claude-haiku-4-5-20251001"]).toEqual({ input: 1, output: 5 });
  });

  it("prices every model either profile can select", () => {
    for (const profile of MODEL_PROFILES) {
      for (const stage of AI_STAGES) {
        const price = priceFor(MODELS[profile][stage]);
        expect(price.input, `${profile}/${stage}`).toBeGreaterThan(0);
        expect(price.output).toBeGreaterThan(price.input);
      }
    }
  });
});

describe("AiStage", () => {
  it("is the AI call sites, not the user-facing AnalysisStage", () => {
    // A regression guard: if someone points this at the schema's AnalysisStage, the
    // non-model stages ("queued", "complete") would appear here and every profile
    // lookup would go undefined at runtime.
    const stages: readonly string[] = AI_STAGES;
    expect(stages).not.toContain("queued");
    expect(stages).not.toContain("complete");
    expect(stages).not.toContain("loading_repo");
  });

  it("keeps modelFor total over the stage union", () => {
    const stage: AiStage = "classify";
    expect(modelFor(stage, "dev")).toBe(MODELS.dev.classify);
  });
});
