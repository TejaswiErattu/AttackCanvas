/**
 * The golden-demo fallback: when a submitted repoUrl matches GOLDEN_REPO_URL and
 * DEMO_FALLBACK=1, POST /api/analyze serves a canned ThreatModel instead of running the
 * real pipeline (no MCP servers, no model calls, no cost, and a result that never
 * changes for a live demo).
 *
 * fixtures/golden-demo.json wins when present; fixtures/demo-analysis.json is the
 * fallback until it exists (it is already a validated, realistic ThreatModel used by
 * tests/fixtures.test.ts, and it carries 2 developer questions -- exercised below).
 *
 * Stage transitions are simulated with real delays so a client polling GET
 * /api/analyze/<id> sees the same stage sequence a live run would, rather than jumping
 * straight to "complete" -- the point of a demo is to look like the real thing. If the
 * fixture carries developer questions, the job pauses at "awaiting_answers" exactly like
 * a real one, so POST .../answers has something real to demonstrate against the demo
 * path too, with no external credentials needed.
 *
 * The demo has no `PendingAnswerState` to resume with (there is no real QuestionEffects
 * sidecar for canned data, since nothing actually ran) -- resumeDemoAnalysis finishes the
 * job by simply moving it to "complete" with the fixture unchanged, which is exactly why
 * this is a separate function from src/server/analysis/pipeline.ts's resumeWithAnswers:
 * that one re-scores for real and needs `pending`; a demo has nothing to re-score.
 *
 * A demo job is identified by the explicit `state.isDemo` flag (set at createAnalysis
 * time by the route, and asserted again here), never by the absence of `pending` -- an
 * absent `pending` on what should be a real job is a bug and must not be read as "this is
 * a demo, finish it anyway".
 *
 * Both functions mutate the AnalysisState object src/server/analysis/pipeline.ts's store
 * already holds (getAnalysis returns that exact reference, not a copy), the same way
 * pipeline.ts's own setStage does. This module is the one place outside pipeline.ts
 * allowed to write state, because the demo path deliberately skips runAnalysis and
 * resumeWithAnswers entirely. Like those two, both functions here NEVER reject: every
 * caller starts them with `void`, fire-and-forget, so an unhandled rejection would
 * otherwise escape uncaught -- any unexpected failure (a malformed fixture, a filesystem
 * error) is caught and turned into a normal "failed" state instead.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { validateThreatModel, type AnalysisStage, type ErrorCode } from "@/shared/schema";
import { ERROR_COPY } from "@/shared/labels";
import { getAnalysis, type AnalysisState } from "@/server/analysis/pipeline";

export const DEMO_STAGES_BEFORE_QUESTIONS: readonly { stage: AnalysisStage; delayMs: number }[] = [
  { stage: "loading_repo", delayMs: 700 },
  { stage: "scanning", delayMs: 1100 },
  { stage: "mapping_architecture", delayMs: 1400 },
  { stage: "generating_threats", delayMs: 1800 },
];

export const DEMO_STAGES_NO_QUESTIONS: readonly { stage: AnalysisStage; delayMs: number }[] = [
  { stage: "finalizing", delayMs: 500 },
  { stage: "complete", delayMs: 0 },
];

export const DEMO_RESUME_STAGES: readonly { stage: AnalysisStage; delayMs: number }[] = [
  { stage: "finalizing", delayMs: 400 },
  { stage: "complete", delayMs: 0 },
];

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function loadDemoFixture(): unknown {
  const golden = join(process.cwd(), "fixtures", "golden-demo.json");
  const fallback = join(process.cwd(), "fixtures", "demo-analysis.json");
  const path = existsSync(golden) ? golden : fallback;
  return JSON.parse(readFileSync(path, "utf8"));
}

async function walkStages(
  state: AnalysisState,
  stages: readonly { stage: AnalysisStage; delayMs: number }[],
): Promise<void> {
  for (const { stage, delayMs } of stages) {
    if (delayMs > 0) await sleep(delayMs);
    state.stage = stage;
    state.updatedAt = Date.now();
  }
}

/** Marks a demo job failed the same safe way pipeline.ts's fail() does, and never throws. */
function failDemo(state: AnalysisState, code: ErrorCode = "AI_FAILURE"): void {
  state.stage = "failed";
  state.error = { code, message: ERROR_COPY[code].message };
  state.threatModel = undefined;
  state.questions = undefined;
  state.pending = undefined;
  state.updatedAt = Date.now();
}

/**
 * Walks a job already created by createAnalysis (with `isDemo: true`) through the same
 * stage sequence runAnalysis would. Pauses at "awaiting_answers" when the fixture carries
 * developer questions (demo-analysis.json has 2); otherwise runs straight through to
 * "complete". Never rejects: any failure, expected (an invalid fixture) or not (a
 * filesystem error, a bug), fails the job the same way runAnalysis fails one, with a safe
 * ERROR_COPY message -- this call is always started with `void` and nothing else awaits it.
 *
 * `beforeQuestions`/`afterQuestions` default to the real, human-visible delays; tests
 * pass near-zero-delay schedules so this does not add seconds to every test run.
 */
export async function seedDemoAnalysis(
  id: string,
  beforeQuestions: readonly { stage: AnalysisStage; delayMs: number }[] = DEMO_STAGES_BEFORE_QUESTIONS,
  afterQuestions: readonly { stage: AnalysisStage; delayMs: number }[] = DEMO_STAGES_NO_QUESTIONS,
): Promise<void> {
  const state = getAnalysis(id);
  if (!state) return;
  state.isDemo = true; // explicit marker, asserted even if the caller already set it

  try {
    const validated = validateThreatModel(loadDemoFixture());
    if (!validated.ok) {
      failDemo(state);
      return;
    }

    await walkStages(state, beforeQuestions);

    if (validated.data.questions.length > 0) {
      state.questions = validated.data.questions;
      state.threatModel = validated.data;
      state.stage = "awaiting_answers";
      state.updatedAt = Date.now();
      return;
    }

    state.threatModel = validated.data;
    await walkStages(state, afterQuestions);
  } catch {
    // Never leak the cause (a filesystem error can carry a path; JSON.parse a snippet of
    // the bad file) -- CLAUDE.md rule 8 applies here exactly as it does in pipeline.ts.
    failDemo(state);
  }
}

/**
 * Finishes a demo job paused at "awaiting_answers". The submitted answers are accepted
 * but not applied -- there is no real QuestionEffects sidecar to re-score against, since
 * nothing actually ran -- so the fixture's canned scoring is the final result either way.
 * Never rejects, for the same fire-and-forget reason as seedDemoAnalysis.
 *
 * Leaves "awaiting_answers" SYNCHRONOUSLY, before any delay: walkStages sleeps before
 * writing each stage, so without this a duplicate POST .../answers arriving during the
 * first call's delay would still see "awaiting_answers" and be processed a second time.
 * resumeWithAnswers (pipeline.ts) does not need this because its pure applyAnswers has
 * already moved the job off "awaiting_answers" by the time control returns to the caller,
 * with no delay to race against.
 */
export async function resumeDemoAnalysis(
  id: string,
  stages: readonly { stage: AnalysisStage; delayMs: number }[] = DEMO_RESUME_STAGES,
): Promise<void> {
  const state = getAnalysis(id);
  if (!state || !state.isDemo || state.stage !== "awaiting_answers") return;
  state.questions = undefined;
  state.stage = "finalizing";
  state.updatedAt = Date.now();
  try {
    await walkStages(state, stages);
  } catch {
    failDemo(state);
  }
}
