/**
 * Smoke test: run the whole analysis pipeline (Prompt V) over a real repository. PAID --
 * makes several Claude calls (architecture, threats, and questions when any qualify).
 *
 *   pnpm try scripts/try-pipeline.ts bezkoder/node-js-express-login-example
 *   pnpm try scripts/try-pipeline.ts <owner/repo> --timeout 600000   # override the 10-minute budget
 *
 * Needs ANTHROPIC_API_KEY, GITHUB_PERSONAL_ACCESS_TOKEN (environment or .env.local) and
 * Docker, plus the semgrep CLI on PATH -- a missing Semgrep degrades the run (a
 * limitation is recorded) rather than failing it.
 *
 * Polls getAnalysis alongside runAnalysis and prints every stage transition, using the
 * same STAGE_LABELS copy the dashboard reads, so the Prompt V mod-1 label change is
 * visible end to end. If the run pauses at awaiting_answers, every question is answered
 * "skipped" so the script always reaches a terminal state and prints a final summary.
 */

import { performance } from "node:perf_hooks";
import { AiError } from "@/server/ai/claude";
import { closeClient } from "@/server/mcp/githubClient";
import { closeSemgrepClient } from "@/server/mcp/semgrepClient";
import { IngestError } from "@/server/ingest/loader";
import { ERROR_COPY } from "@/shared/labels";
import {
  MAX_TIMEOUT_MS,
  PIPELINE_TIMEOUT_MS,
  countByBasis,
  createAnalysis,
  getAnalysis,
  resumeWithAnswers,
  runAnalysis,
  type AnalysisState,
} from "@/server/analysis/pipeline";
import { formatStageLine, formatSummary, parseTarget, parseTimeoutMs, toGitHubUrl } from "./try-pipeline-lib";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

const started = performance.now();
const elapsed = () => (performance.now() - started) / 1000;

/** Prints every stage the state passes through while `work` is in flight. */
async function pollWhile<T>(id: string, work: Promise<T>): Promise<T> {
  let lastStage: string | undefined;
  const timer = setInterval(() => {
    const state = getAnalysis(id);
    if (!state || state.stage === lastStage) return;
    lastStage = state.stage;
    console.log(formatStageLine(state.stage, elapsed()));
  }, 250);
  try {
    return await work;
  } finally {
    clearInterval(timer);
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const target = args.find((a) => !a.startsWith("--"));
  const timeoutIndex = args.indexOf("--timeout");
  const timeoutArg = timeoutIndex === -1 ? undefined : args[timeoutIndex + 1];

  // Validate everything about the invocation BEFORE any network or model work starts,
  // including a bad --timeout: rejected here, not discovered later as a confusing
  // immediate TIMEOUT failure from a deadline that was already in the past.
  const parsedTimeout = parseTimeoutMs(timeoutArg, PIPELINE_TIMEOUT_MS, MAX_TIMEOUT_MS);
  if (!parsedTimeout.ok) {
    console.error(parsedTimeout.message);
    process.exitCode = 1;
    return;
  }

  if (!target) {
    console.error("usage: pnpm try scripts/try-pipeline.ts <owner/repo> [--timeout <ms>]");
    process.exitCode = 1;
    return;
  }
  if (!process.env.ANTHROPIC_API_KEY?.trim()) {
    console.error(
      "ANTHROPIC_API_KEY is not set.\n" +
        "Add it to .env.local (which is gitignored), or export it in this shell.",
    );
    process.exitCode = 1;
    return;
  }

  const { owner, repo } = parseTarget(target);
  // The public API's contract (AnalysisRequestSchema) requires a full URL; normalize the
  // shorthand this script accepts before calling into the pipeline, rather than lean on
  // its still-shorthand-tolerant parseGitHubUrl to paper over the difference.
  const repoUrl = toGitHubUrl(owner, repo);
  const budget = parsedTimeout.value;
  console.log(`repo:    ${repoUrl}`);
  console.log(`budget:  ${(budget / 1000).toFixed(0)}s (THREATS_TIMEOUT_MS is 300s PER BATCH -- see pipeline.ts header)\n`);

  let state = createAnalysis(repoUrl, 2, { timeoutMs: budget });

  state = await pollWhile(state.id, runAnalysis(state.id));
  console.log(formatStageLine(state.stage, elapsed()));

  if (state.stage === "awaiting_answers" && state.questions) {
    console.log(`\n${state.questions.length} developer question(s) asked; answering all "skipped":`);
    for (const q of state.questions) console.log(`  - ${q.text}`);
    const answers = state.questions.map((q) => ({ questionId: q.id, status: "skipped" as const }));
    state = await pollWhile(state.id, resumeWithAnswers(state.id, answers));
    console.log(formatStageLine(state.stage, elapsed()));
  }

  const basisCounts = countByBasis(state.threatModel?.threats ?? []);
  console.log("\n=== summary ===");
  for (const line of formatSummary(state, basisCounts, elapsed())) console.log(line);

  if (state.stage === "failed") process.exitCode = 1;
}

function printFailure(error: unknown, state?: AnalysisState): void {
  // Never print the raw error object: an AiError's cause chain carries the API's
  // response body and headers, and an IngestError/SecretLeakError message can carry
  // repository text. Print only the safe [code] message pipeline.ts already computed,
  // falling back to a generic line for anything thrown outside the pipeline itself.
  console.error(`\nfailed after ${elapsed().toFixed(1)}s`);
  if (state?.error) {
    console.error(`[${state.error.code}] ${state.error.message}`);
    return;
  }
  if (error instanceof AiError) {
    console.error(`[${error.code}] ${ERROR_COPY[error.code].message}`);
  } else if (error instanceof IngestError) {
    console.error(`[${error.code}] ${ERROR_COPY[error.code].message}`);
  } else {
    console.error("[AI_FAILURE] an unexpected error stopped the run");
  }
}

main()
  .catch((error: unknown) => {
    printFailure(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeClient();
    await closeSemgrepClient();
  });
