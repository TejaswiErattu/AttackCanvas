/**
 * One evaluation run of one repo: runAnalysis, then (if questions were asked) every
 * question answered "skipped", then either an EvalResult or a RunFailure. Separate from
 * run.ts so tests can drive it with a fake pipeline; run.ts passes the real one.
 *
 * A failed job never yields a result: pipeline.ts's fail() clears threatModel, and this
 * returns ok:false for anything other than stage "complete" with a model.
 */

import type { AnalysisState } from "@/server/analysis/pipeline";
import type { AnalysisLevel } from "@/shared/schema";
import type { DeveloperAnswer } from "@/server/analysis/answers";
import { DEFAULT_LEVEL, StageTracker, requireRepoUrl, type EvalRepo, type EvalResult, type RunFailure } from "./lib";

export type PipelineApi = {
  createAnalysis: (repoUrl: string, level: AnalysisLevel, options: { timeoutMs: number }) => AnalysisState;
  runAnalysis: (id: string) => Promise<AnalysisState>;
  resumeWithAnswers: (id: string, answers: readonly DeveloperAnswer[]) => Promise<AnalysisState>;
  getAnalysis: (id: string) => AnalysisState | undefined;
};

export type AnalyseOutcome = { ok: true; result: EvalResult } | { ok: false; failure: RunFailure };

/** How often the stage is sampled while a phase runs. Stages last seconds to minutes. */
export const STAGE_POLL_MS = 100;

async function tracking<T>(api: PipelineApi, id: string, tracker: StageTracker, work: Promise<T>): Promise<T> {
  const timer = setInterval(() => {
    const stage = api.getAnalysis(id)?.stage;
    if (stage) tracker.record(stage);
  }, STAGE_POLL_MS);
  try {
    return await work;
  } finally {
    clearInterval(timer);
  }
}

export async function analyseRepo(
  api: PipelineApi,
  repo: EvalRepo,
  options: { timeoutMs: number; profile: string; level?: AnalysisLevel; now?: () => number },
): Promise<AnalyseOutcome> {
  const now = options.now ?? Date.now;
  const repoUrl = requireRepoUrl(repo);
  const level = options.level ?? DEFAULT_LEVEL;
  const started = now();
  const tracker = new StageTracker();
  let phase: RunFailure["phase"] = "analysis";

  let state = api.createAnalysis(repoUrl, level, { timeoutMs: options.timeoutMs });
  state = await tracking(api, state.id, tracker, api.runAnalysis(state.id));
  tracker.record(state.stage);
  if (state.stage === "awaiting_answers" && state.questions) {
    phase = "resume";
    const skipped = state.questions.map((q) => ({ questionId: q.id, status: "skipped" as const }));
    state = await tracking(api, state.id, tracker, api.resumeWithAnswers(state.id, skipped));
    tracker.record(state.stage);
  }

  if (state.stage !== "complete" || !state.threatModel) {
    return {
      ok: false,
      failure: {
        repo: repo.name,
        failedDuring: tracker.lastSeen,
        phase,
        // Already a safe, user-facing message (pipeline.ts safeMessage).
        ...(state.error ? { error: state.error } : {}),
        // fail() refreshes this from the usage ledger at the moment of failure.
        cost: { calls: state.cost.calls, totalUsd: state.cost.totalUsd },
        timeoutMs: options.timeoutMs,
        elapsedMs: now() - started,
      },
    };
  }
  return {
    ok: true,
    result: {
      repo: repo.name,
      repoUrl,
      modelProfile: options.profile,
      ranAt: new Date(now()).toISOString(),
      level,
      durationMs: now() - started,
      cost: { calls: state.cost.calls, totalUsd: state.cost.totalUsd },
      threatModel: state.threatModel,
      diagnostics: [...(state.diagnostics ?? [])],
    },
  };
}
