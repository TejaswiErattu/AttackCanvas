/**
 * Mini benchmark: re-run the threat engine for a few answer-key items, not the whole repo.
 * PAID on the first run for the batches it selects (typically 3 to 5, not 7 to 12); free
 * on every later run with the same prompts, because the model cache serves them.
 *
 *   ATTACKCANVAS_CHECKPOINT_DIR=.cache/checkpoints ATTACKCANVAS_MODEL_CACHE=1 \
 *     pnpm try scripts/eval/mini.ts nodegoat-a3118b6 NG-NOSQL-WHERE,NG-SSJS-EVAL
 *   ... --dry-run          print the batches that would run; no model call, no key needed
 *   ... --by-files         choose components from the answer key's source files, not hand labels
 *   ... --allow-uncached   run without ATTACKCANVAS_MODEL_CACHE=1 (every run then pays)
 *   ... --level 0-4        defaults to the level the saved result ran at
 *
 * Reads eval/results/<name>.json, eval/labels/<name>.csv and eval/expected/<name>.yaml, and
 * the scanners and architecture checkpoints in ATTACKCANVAS_CHECKPOINT_DIR (written by a run
 * made with it set: scripts/try-pipeline.ts or the eval runner). The checkpoints must come
 * from the same commit as the result, or from a run whose component ids match it; the
 * script refuses a mismatch rather than guess. It never makes the architecture call, never
 * touches GitHub, Docker or Semgrep, and honours ATTACKCANVAS_MAX_RUN_USD like any run.
 *
 * Prints recall over the chosen ids three ways (hand labels on the saved run, a location
 * proxy on the saved run, the same proxy on this run) and the cost. See miniLib.ts for why
 * the new run's recall is a proxy: no model ever labels anything.
 */

import { existsSync, readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { AiError } from "@/server/ai/claude";
import { usageLedger } from "@/server/ai/usage";
import { activeProfile, isModelProfile, type ModelProfile } from "@/server/ai/models";
import { planFor } from "@/server/ai/levels";
import { MODEL_CACHE_ENV, modelCacheEnabled } from "@/server/ai/modelCache";
import {
  CHECKPOINT_DIR_ENV,
  checkpointDir,
  deserializeArchitecture,
  readCheckpoint,
} from "@/server/analysis/checkpoints";
import { generateThreats } from "@/server/analysis/threats";
import { formatUsageLines } from "../try-threats-lib";
import {
  EvalResultSchema,
  ExpectedFileSchema,
  evalPaths,
  parseLabels,
  parseYamlWith,
  revisionMismatch,
} from "./lib";
import { expectedSources, formatMiniReport, parseMiniArgs, planMini, runMini } from "./miniLib";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

const ROOT = process.cwd();

async function main(): Promise<number> {
  const args = parseMiniArgs(process.argv.slice(2));
  const paths = evalPaths(ROOT, args.name);
  const need = [paths.result, paths.expected, ...(args.byFiles ? [] : [paths.labels])];
  const missing = need.filter((p) => !existsSync(p));
  if (missing.length > 0) throw new Error(`missing ${missing.map((p) => p.replace(`${ROOT}/`, "")).join(", ")}`);

  const result = EvalResultSchema.parse(JSON.parse(readFileSync(paths.result, "utf8")));
  const expectedText = readFileSync(paths.expected, "utf8");
  const expected = parseYamlWith(expectedText, ExpectedFileSchema, `eval/expected/${args.name}.yaml`);
  const mismatch = revisionMismatch(expected, result.threatModel.repo.ref);
  if (mismatch) throw new Error(mismatch);
  const unknown = args.ids.filter((id) => !expected.expectedThreats.some((t) => t.id === id));
  if (unknown.length > 0) throw new Error(`not in eval/expected/${args.name}.yaml: ${unknown.join(", ")}`);
  const sources = expectedSources(parseYaml(expectedText));
  const labels = existsSync(paths.labels)
    ? parseLabels(readFileSync(paths.labels, "utf8"), new Set(expected.expectedThreats.map((t) => t.id)))
    : [];

  const dir = checkpointDir();
  if (!dir) throw new Error(`${CHECKPOINT_DIR_ENV} must be set (and NODE_ENV not production)`);
  const { owner, name: repo, ref } = result.threatModel.repo;
  const scanned = readCheckpoint(dir, owner, repo, "scanners");
  if (scanned.summary.ref !== ref) {
    throw new Error(`the checkpoint was made at ${scanned.summary.ref}, but this result was scanned at ${ref}`);
  }
  const architecture = deserializeArchitecture(readCheckpoint(dir, owner, repo, "architecture").architecture);

  const level = args.level ?? result.level ?? 2;
  const profile: ModelProfile = isModelProfile(result.modelProfile) ? result.modelProfile : activeProfile();
  const plan = planFor(level, profile);
  const input = {
    args,
    model: result.threatModel,
    labels,
    sources,
    architecture,
    analysisId: `mini-${args.name}`,
    engine: {
      gaps: scanned.detector.gaps,
      routePaths: scanned.detector.routes.map((route) => route.normalizedPath),
      files: scanned.files,
      sessionCookies: scanned.detector.sessionCookies,
      model: plan.models.stride,
      maxTokens: plan.stride.maxTokens,
      thinking: plan.stride.thinking,
    },
  };

  const chosen = planMini(input);
  console.log(
    `${args.name}: ${args.ids.join(", ")} -> components ${chosen.componentIds.join(", ")}; ` +
      `${chosen.selected.length} of ${chosen.all} batches (level ${level}, profile ${profile}, model ${plan.models.stride})`,
  );
  if (args.dryRun) {
    chosen.selected.forEach((batch, i) => console.log(`  batch ${i + 1}: ${batch.join(", ")}`));
    console.log("dry run: no model call made");
    return 0;
  }
  if (!modelCacheEnabled() && !args.allowUncached) {
    throw new Error(
      `${MODEL_CACHE_ENV}=1 is not set, so every run of this script would pay for these batches again; ` +
        "set it, or pass --allow-uncached to pay each time",
    );
  }

  try {
    const report = await runMini(input, {
      generateThreats,
      cost: () => {
        const usage = usageLedger.forAnalysis(input.analysisId);
        return {
          totalUsd: usage.totalUsd,
          calls: usage.calls.length,
          cachedCalls: usage.calls.filter((c) => c.cached).length,
        };
      },
    });
    for (const line of formatMiniReport(report)) console.log(line);
    return 0;
  } catch (error) {
    console.error(error instanceof AiError ? `failed: ${error.code} ${error.message}` : `failed: ${(error as Error).name}`);
    return 1;
  } finally {
    for (const line of formatUsageLines(usageLedger.forAnalysis(input.analysisId))) console.log(line);
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : "unexpected error");
    process.exitCode = 1;
  });
