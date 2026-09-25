/**
 * Evaluation step 1: run the real pipeline over each repo in eval/repos.yaml and save the
 * ThreatModel and its cost to eval/results/<repo>.json. PAID -- several Claude calls per
 * repo.
 *
 *   pnpm try scripts/eval/run.ts              # every repo in eval/repos.yaml
 *   pnpm try scripts/eval/run.ts nodegoat     # just the named ones
 *   pnpm try scripts/eval/run.ts nodegoat --timeout 1200000   # 20-minute budget
 *
 * --timeout <ms> overrides PIPELINE_TIMEOUT_MS (10 minutes) for these runs. It is a
 * per-phase budget, exactly as in the pipeline: runAnalysis (load through questions) gets
 * it, and resumeWithAnswers gets a fresh one. It bounds wall-clock time, not spend: a
 * model call still in flight when the deadline fires is orphaned, not cancelled, and is
 * billed. Validated before any paid work; an invalid value exits 1 having done nothing.
 *
 * Refuses to start if any selected repo already has eval/results/<name>.json, before the
 * API key check or any network work; there is no override (move the file, or add a new
 * repo name).
 *
 * On failure, prints the stage it failed during, the pipeline's own recorded call count
 * and cost at the moment it failed (never an estimate), elapsed time and the safe error;
 * nothing is written to eval/results.
 *
 * Runs on the demo model profile (ATTACKCANVAS_MODEL_PROFILE=demo, set here regardless of
 * the shell) with every developer question answered "skipped", so a result depends only on
 * the repository. Needs ANTHROPIC_API_KEY, GITHUB_PERSONAL_ACCESS_TOKEN and Docker, plus
 * the semgrep CLI (see scripts/try-pipeline.ts). A repo that fails is reported and does not
 * stop the others; the exit code is 1 if any failed. Nothing is written for a failed repo.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { closeClient } from "@/server/mcp/githubClient";
import { closeSemgrepClient } from "@/server/mcp/semgrepClient";
import {
  MAX_TIMEOUT_MS,
  PIPELINE_TIMEOUT_MS,
  createAnalysis,
  getAnalysis,
  resumeWithAnswers,
  runAnalysis,
} from "@/server/analysis/pipeline";
import { analyseRepo, type PipelineApi } from "./analyse";
import { formatUsd } from "@/server/ai/usage";
import {
  ReposFileSchema,
  evalPaths,
  existingResultPaths,
  formatRunFailure,
  parseRunArgs,
  parseYamlWith,
  requireRepoUrl,
  selectRepos,
} from "./lib";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

const PROFILE = "demo";
const ROOT = process.cwd();
const PIPELINE: PipelineApi = { createAnalysis, runAnalysis, resumeWithAnswers, getAnalysis };

async function main(): Promise<void> {
  process.env.ATTACKCANVAS_MODEL_PROFILE = PROFILE;
  const args = parseRunArgs(process.argv.slice(2), PIPELINE_TIMEOUT_MS, MAX_TIMEOUT_MS);
  if (!args.ok) {
    console.error(args.message);
    process.exitCode = 1;
    return;
  }
  const { names, timeoutMs } = args.value;
  const config = parseYamlWith(readFileSync(`${ROOT}/eval/repos.yaml`, "utf8"), ReposFileSchema, "eval/repos.yaml");
  const repos = selectRepos(config.repos, names);
  // Fail on a blank URL before spending anything on the earlier repos.
  repos.forEach(requireRepoUrl);
  // Never replace a finished result. Checked before the API key and before any network
  // or model work, so a refused run costs nothing.
  const existing = existingResultPaths(repos, ROOT, existsSync);
  if (existing.length > 0) {
    console.error(
      `refusing to overwrite existing result(s): ${existing.join(", ")}\n` +
        "Move the file away, or add a new repo name to eval/repos.yaml for another run.",
    );
    process.exitCode = 1;
    return;
  }
  if (!process.env.ANTHROPIC_API_KEY?.trim()) {
    console.error("ANTHROPIC_API_KEY is not set. Add it to .env.local (gitignored) or export it.");
    process.exitCode = 1;
    return;
  }

  for (const repo of repos) {
    console.log(
      `\n${repo.name}: analysing ${repo.url} (profile ${PROFILE}, questions skipped, ` +
        `timeout ${(timeoutMs / 1000).toFixed(0)}s per phase)`,
    );
    try {
      const outcome = await analyseRepo(PIPELINE, repo, { timeoutMs, profile: PROFILE });
      if (!outcome.ok) {
        for (const line of formatRunFailure(outcome.failure)) console.error(line);
        process.exitCode = 1;
        continue;
      }
      const { result } = outcome;
      const out = evalPaths(ROOT, repo.name).result;
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, JSON.stringify(result, null, 2) + "\n");
      console.log(
        `${repo.name}: ${result.threatModel.threats.length} threats, ` +
          `${formatUsd(result.cost.totalUsd)} (${result.cost.calls} calls) -> eval/results/${repo.name}.json`,
      );
    } catch (error) {
      // Only the pipeline's safe message is printed, never a raw error (see try-pipeline.ts).
      console.error(`${repo.name}: FAILED ${error instanceof Error ? error.message : "unexpected error"}`);
      process.exitCode = 1;
    }
  }
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : "unexpected error");
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeClient();
    await closeSemgrepClient();
  });
