/**
 * What each analysis level buys: the model per AI stage, the architecture budgets, how
 * many STRIDE batches run, whether STRIDE thinks, and whether questions are asked.
 *
 * Pure data plus one pure lookup. The level is the user's choice (AnalysisRequest); the
 * profile is the operator's: ATTACKCANVAS_MODEL_PROFILE=dev (also the default when unset)
 * swaps every level's models for MODELS.dev so development stays cheap, while budgets,
 * batching and questions still follow the level. `demo` lets the level choose models.
 */

import type { ThinkingSetting } from "@/server/ai/claude";
import { MODELS, type AiStage, type ModelId, type ModelProfile } from "@/server/ai/models";
import {
  ARCHITECTURE_CONTEXT_TOKENS,
  ARCHITECTURE_MAX_TOKENS,
  ARCHITECTURE_THINKING,
} from "@/server/analysis/architecture";
import { THREATS_MAX_TOKENS } from "@/server/analysis/threatPrompt";
import { THREATS_THINKING } from "@/server/analysis/threats";
import type { AnalysisLevel } from "@/shared/schema";

export type { ThinkingSetting };

export type LevelPlan = {
  models: Readonly<Record<AiStage, ModelId>>;
  architecture: {
    contextTokens: number;
    maxTokens: number;
    thinking: ThinkingSetting;
  };
  stride: {
    /** At most this many batches run, gap-richest first; null runs them all. */
    maxBatches: number | null;
    thinking: ThinkingSetting;
    maxTokens: number;
  };
  questions: boolean;
};

/** Level 0's context: a third of ARCHITECTURE_CONTEXT_TOKENS, enough for the facts prefix and the top files. */
export const SNAPSHOT_CONTEXT_TOKENS = 20_000;

/** Level 0's batch cap: one concurrency round (THREATS_CONCURRENCY = 3), so one round-trip of wall-clock. */
export const SNAPSHOT_MAX_BATCHES = 3;

/** Level 3's context: 1.5x ARCHITECTURE_CONTEXT_TOKENS, for wider file coverage in the architecture draft. */
export const DEEP_CONTEXT_TOKENS = 90_000;

/**
 * Level 4's STRIDE thinking allowance. Opus 5 and Sonnet 5 take adaptive thinking only
 * (budget_tokens is a 400), so this is not sent as a budget: it is headroom added to
 * THREATS_MAX_TOKENS, because reasoning tokens count against max_tokens and once used all
 * 12,000 of them (THREATS_THINKING's comment).
 */
export const EXHAUSTIVE_THINKING_BUDGET = 4_000;

const SONNET: ModelId = "claude-sonnet-5";
const HAIKU: ModelId = "claude-haiku-4-5-20251001";

/** Sonnet 5 on every stage except Haiku on classify. */
const SONNET_MODELS = {
  architecture: SONNET,
  stride: SONNET,
  questions: SONNET,
  remediation: SONNET,
  classify: HAIKU,
} as const satisfies Record<AiStage, ModelId>;

const STANDARD: LevelPlan = {
  models: MODELS.demo,
  architecture: {
    contextTokens: ARCHITECTURE_CONTEXT_TOKENS,
    maxTokens: ARCHITECTURE_MAX_TOKENS,
    thinking: ARCHITECTURE_THINKING,
  },
  stride: { maxBatches: null, thinking: THREATS_THINKING, maxTokens: THREATS_MAX_TOKENS },
  questions: true,
};

const DEEP: LevelPlan = {
  ...STANDARD,
  architecture: { ...STANDARD.architecture, contextTokens: DEEP_CONTEXT_TOKENS },
};

export const LEVEL_PLANS: Readonly<Record<AnalysisLevel, LevelPlan>> = {
  0: {
    models: SONNET_MODELS,
    architecture: { ...STANDARD.architecture, contextTokens: SNAPSHOT_CONTEXT_TOKENS },
    stride: { ...STANDARD.stride, maxBatches: SNAPSHOT_MAX_BATCHES },
    questions: false,
  },
  1: { ...STANDARD, models: SONNET_MODELS },
  2: STANDARD,
  3: DEEP,
  4: {
    ...DEEP,
    stride: {
      maxBatches: null,
      thinking: { type: "adaptive" },
      maxTokens: THREATS_MAX_TOKENS + EXHAUSTIVE_THINKING_BUDGET,
    },
  },
};

/** The plan for `level` under `profile`: dev keeps the level's budgets but uses MODELS.dev. */
export function planFor(level: AnalysisLevel, profile: ModelProfile): LevelPlan {
  const plan = LEVEL_PLANS[level];
  return profile === "dev" ? { ...plan, models: MODELS.dev } : plan;
}

export { LEVEL_COST_RANGES } from "@/shared/levelCost";
