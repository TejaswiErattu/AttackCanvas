/**
 * Which model runs which AI stage, and what a token costs.
 *
 * Two profiles. `dev` is what you build against: Sonnet for the reasoning stages and
 * Haiku for classification, so an accidental loop costs cents rather than dollars.
 * `demo` moves the two stages where reasoning quality is visible in the output --
 * architecture and STRIDE -- up to Opus.
 *
 * The profile is read per call rather than captured at module load, so a script can
 * set ATTACKCANVAS_MODEL_PROFILE before calling without caring about import order.
 */

/**
 * The AI steps of the pipeline. Deliberately NOT the schema's AnalysisStage, which
 * describes progress shown to the user ("loading_repo", "complete") and includes
 * stages that never call a model. This one names model call sites.
 */
export type AiStage =
  | "architecture"
  | "stride"
  | "questions"
  | "remediation"
  | "classify";

export const AI_STAGES: readonly AiStage[] = [
  "architecture",
  "stride",
  "questions",
  "remediation",
  "classify",
];

/** Exact model ids. No date suffix on the aliases: the alias is the whole id. */
export type ModelId =
  | "claude-opus-5"
  | "claude-sonnet-5"
  | "claude-haiku-4-5-20251001";

export type ModelProfile = "dev" | "demo";

export const MODEL_PROFILES: readonly ModelProfile[] = ["dev", "demo"];

export const DEFAULT_PROFILE: ModelProfile = "dev";

export const MODELS = {
  dev: {
    architecture: "claude-sonnet-5",
    stride: "claude-sonnet-5",
    questions: "claude-sonnet-5",
    remediation: "claude-sonnet-5",
    classify: "claude-haiku-4-5-20251001",
  },
  demo: {
    architecture: "claude-opus-5",
    stride: "claude-opus-5",
    questions: "claude-sonnet-5",
    remediation: "claude-sonnet-5",
    classify: "claude-haiku-4-5-20251001",
  },
} as const satisfies Record<ModelProfile, Record<AiStage, ModelId>>;

/** USD per million tokens. */
export type Price = { readonly input: number; readonly output: number };

/**
 * List price per million tokens, input/output. These are a build-time snapshot for the
 * cost estimate, not a billing source: the number in the usage log is an estimate and
 * the invoice is the truth. If a price changes, this table is the one place to edit.
 */
export const PRICES = {
  "claude-opus-5": { input: 5, output: 25 },
  "claude-sonnet-5": { input: 2, output: 10 },
  "claude-haiku-4-5-20251001": { input: 1, output: 5 },
} as const satisfies Record<ModelId, Price>;

/**
 * Cache multipliers applied to the INPUT price. A cache read is far cheaper than a
 * fresh input token and a cache write is slightly dearer; counting either at the plain
 * input rate would misreport the saving that caching exists to produce.
 */
export const CACHE_READ_MULTIPLIER = 0.1;
export const CACHE_WRITE_MULTIPLIER = 1.25;

export function isModelProfile(value: unknown): value is ModelProfile {
  return (
    typeof value === "string" &&
    (MODEL_PROFILES as readonly string[]).includes(value)
  );
}

/**
 * The profile in force. Unset or empty means `dev`.
 *
 * A value that is set but unrecognised throws rather than falling back, because the
 * failure it usually represents is a typo in ATTACKCANVAS_MODEL_PROFILE on the demo
 * machine, and silently running the cheap profile through a demo is worse than a loud
 * error on the first model call.
 */
export function activeProfile(
  env: Record<string, string | undefined> = process.env,
): ModelProfile {
  const raw = env.ATTACKCANVAS_MODEL_PROFILE?.trim();
  if (!raw) return DEFAULT_PROFILE;
  if (!isModelProfile(raw)) {
    throw new Error(
      `ATTACKCANVAS_MODEL_PROFILE must be one of ${MODEL_PROFILES.join(", ")}, got "${raw}"`,
    );
  }
  return raw;
}

/** The model that runs `stage` under `profile` (the active profile by default). */
export function modelFor(
  stage: AiStage,
  profile: ModelProfile = activeProfile(),
): ModelId {
  return MODELS[profile][stage];
}

export function priceFor(model: ModelId): Price {
  return PRICES[model];
}
