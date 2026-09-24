/**
 * Smoke test: run the threat engine (Prompt P2) over a real repository.
 *
 *   pnpm try scripts/try-threats.ts bezkoder/node-js-express-login-example
 *   pnpm try scripts/try-threats.ts <owner/repo> --fresh        # also re-infer the architecture
 *   pnpm try scripts/try-threats.ts <owner/repo> --allow-large  # more than 8 batches
 *   pnpm try scripts/try-threats.ts <owner/repo> --smoke id1,id2 # ONE batch of exactly these elements
 *
 * Loads the repository through the GitHub MCP client, runs the deterministic detectors,
 * gets an architecture draft, merges it (N2), then makes one PAID model call per batch
 * of at most two elements. Needs ANTHROPIC_API_KEY, GITHUB_PERSONAL_ACCESS_TOKEN
 * (environment or .env.local) and Docker.
 *
 * The architecture draft is reused from .debug/<repo>/architecture.draft.json when one
 * exists, which is the output of an earlier try-architecture run: the draft is what N1
 * paid for, and re-buying it would only add cost and variance to a check of P2. Pass
 * --fresh to make the N1 call as well. Semgrep and OSV are not run, so scanner evidence
 * is absent and every evidence-backed threat rests on a detector item.
 *
 * What to read in the output:
 *   - "confirmed" threats cite at least one item that is not a control gap;
 *   - "gap-only" threats cite only gap evidence. On a typical repository a quarter to
 *     a half of the threats should be gap-only: near zero means pass 2 is not firing,
 *     near all means pass 1 has too little evidence to work with;
 *   - open the cited file and line for a handful of threats and check the claim.
 *
 * This script never scores anything. Severity, confidence and priority are Prompt Q.
 */

import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { join } from "node:path";
import { AiError } from "@/server/ai/claude";
import { activeProfile, modelFor } from "@/server/ai/models";
import { usageLedger } from "@/server/ai/usage";
import {
  ARCHITECTURE_CONTEXT_TOKENS,
  inferArchitecture,
  mergeArchitecture,
} from "@/server/analysis/architecture";
import {
  buildContext,
  buildRepoFacts,
  debugDirName,
} from "@/server/analysis/context";
import {
  THREATS_CONCURRENCY,
  THREATS_TIMEOUT_MS,
  batchElements,
  generateThreats,
} from "@/server/analysis/threats";
import { THREATS_MAX_TOKENS } from "@/server/analysis/threatPrompt";
import { runDetectors } from "@/server/detect";
import { IngestError, loadRepository } from "@/server/ingest/loader";
import { closeClient } from "@/server/mcp/githubClient";
import { ArchitectureDraftSchema, type ArchitectureDraft } from "@/shared/schema";
import {
  batchLimitMessage,
  classifyThreat,
  formatUsageLines,
} from "./try-threats-lib";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

/** Set once the run knows which analysis its usage is recorded under. */
let currentAnalysisId: string | undefined;

function printUsage(): void {
  if (currentAnalysisId === undefined) return;
  console.log();
  for (const line of formatUsageLines(usageLedger.forAnalysis(currentAnalysisId))) {
    console.log(line);
  }
}

const started = performance.now();
const elapsed = () => `${((performance.now() - started) / 1000).toFixed(1)}s`;

function parseTarget(input: string): { owner: string; repo: string } {
  const cleaned = input.trim().replace(/\.git$/, "");
  const match =
    /^https?:\/\/github\.com\/([^/]+)\/([^/?#]+)/.exec(cleaned) ??
    /^([^/\s]+)\/([^/\s]+)$/.exec(cleaned);
  if (!match) {
    throw new Error(`could not read "${input}" as owner/repo or a github.com URL`);
  }
  return { owner: match[1], repo: match[2] };
}

function section(title: string, rows: string[]): void {
  console.log(`\n${title} (${rows.length})`);
  for (const row of rows) console.log(`  ${row}`);
}

async function savedDraft(
  owner: string,
  repo: string,
): Promise<ArchitectureDraft | undefined> {
  const path = join(".debug", debugDirName(owner, repo), "architecture.draft.json");
  try {
    return ArchitectureDraftSchema.parse(JSON.parse(await readFile(path, "utf8")));
  } catch {
    return undefined;
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const target = args.find((a) => !a.startsWith("--"));
  const fresh = args.includes("--fresh");
  const allowLarge = args.includes("--allow-large");
  const smokeIndex = args.indexOf("--smoke");
  const smoke =
    smokeIndex === -1
      ? undefined
      : (args[smokeIndex + 1] ?? "").split(",").filter((id) => id.length > 0);
  if (smoke !== undefined && smoke.length === 0) {
    console.error("--smoke needs a comma-separated list of element ids");
    process.exitCode = 1;
    return;
  }
  if (!target) {
    console.error(
      "usage: pnpm try scripts/try-threats.ts <owner/repo> [--fresh] [--allow-large] [--smoke id1,id2]",
    );
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
  const profile = activeProfile();
  console.log(`profile: ${profile}`);
  console.log(`model:   ${modelFor("stride", profile)}`);
  console.log(
    `limits:  ${THREATS_MAX_TOKENS} output tokens, ${THREATS_TIMEOUT_MS / 1000}s deadline, ` +
      `${THREATS_CONCURRENCY} concurrent`,
  );
  console.log("scanners: semgrep and OSV not run\n");

  console.log(`loading ${owner}/${repo} …`);
  const loaded = await loadRepository(owner, repo);
  console.log(`${loaded.files.length} files, ref ${loaded.summary.ref}`);

  const detector = runDetectors(loaded.files);
  const facts = buildRepoFacts({
    summary: loaded.summary,
    detector,
    files: loaded.files,
  });
  console.log(`${detector.gaps.length} control gaps detected`);

  const analysisId = `try-threats-${owner}-${repo}`;
  currentAnalysisId = analysisId;
  let draft = fresh ? undefined : await savedDraft(owner, repo);
  if (draft) {
    console.log("architecture: reusing the saved N1 draft (no model call)");
  } else {
    console.log("architecture: calling the model (Prompt N1) …");
    const context = buildContext(facts, ARCHITECTURE_CONTEXT_TOKENS);
    ({ draft } = await inferArchitecture({
      repo: { owner, name: repo },
      context,
      analysisId,
    }));
  }

  const merged = mergeArchitecture(draft, facts);
  console.log(
    `merged: ${merged.components.length} components, ${merged.dataFlows.length} flows, ` +
      `${merged.unknowns.length} unknowns, ${merged.evidence.length} evidence items`,
  );
  if (merged.issues.length > 0) {
    section(
      "merge issues",
      merged.issues.map((i) => `${i.code} ${i.path}: ${i.message}`),
    );
  }

  let plan = batchElements(merged);
  if (smoke) {
    const known = new Set([
      ...merged.components.map((c) => c.id),
      ...merged.dataFlows.map((f) => f.id),
    ]);
    const missing = smoke.filter((id) => !known.has(id));
    if (missing.length > 0) {
      console.error(`--smoke names unknown element(s): ${missing.join(", ")}`);
      process.exitCode = 1;
      return;
    }
    plan = [smoke];
  }
  section(
    smoke ? "smoke batch" : "batches",
    plan.map((ids, i) => `${i + 1}: ${ids.join(", ")}`),
  );
  const refusal = batchLimitMessage(plan.length, allowLarge);
  if (refusal) {
    console.error(`\n${refusal}`);
    process.exitCode = 1;
    return;
  }

  console.log(
    `\ncalling the model, ${plan.length} batch(es), at most ${THREATS_CONCURRENCY} at once …`,
  );
  const result = await generateThreats({
    architecture: merged,
    gaps: detector.gaps,
    files: loaded.files,
    analysisId,
    batches: smoke ? plan : undefined,
  });
  console.log(`completed in ${elapsed()}`);

  const byId = new Map(merged.evidence.map((e) => [e.id, e]));
  const kinds = result.threats.map((t) => classifyThreat(t.evidenceIds, byId));
  const count = (k: string) => kinds.filter((x) => x === k).length;

  console.log("\n=== threats (unscored) ===");
  result.threats.forEach((t, i) => {
    const where = [...t.componentIds, ...t.dataFlowIds].join(", ");
    console.log(`\n${t.id} [${t.stride.join("")}] ${kinds[i]}  @ ${where}`);
    console.log(`  ${t.title}`);
    console.log(`  asset: ${t.asset}`);
    console.log(`  scenario: ${t.attackScenario}`);
    console.log(`  cites: ${t.evidenceIds.join(", ") || "(none)"}`);
    for (const id of t.evidenceIds) {
      const e = byId.get(id);
      if (e?.filePath) {
        console.log(`    ${id} -> ${e.filePath}${e.lineStart ? `:${e.lineStart}` : ""}  ${e.summary}`);
      }
    }
    if (t.assumptions.length > 0) console.log(`  assumes: ${t.assumptions.join(" | ")}`);
    if (t.dependsOnUnknownIds.length > 0) {
      console.log(`  depends on: ${t.dependsOnUnknownIds.join(", ")}`);
    }
    console.log(`  impact ${t.impact}, likelihood ${t.likelihood}`);
    console.log(`  fix: ${t.mitigation.summary}${t.mitigation.codeLocation ? ` (${t.mitigation.codeLocation})` : ""}`);
  });

  section("limitations", result.limitations);
  section(
    "batches run",
    result.batches.map((b) => `${b.index + 1}: returned ${b.returned}`),
  );

  const total = result.threats.length;
  console.log("\n=== summary ===");
  console.log(`batches: ${result.batches.length} of ${plan.length} completed | elapsed ${elapsed()}`);
  console.log(
    `threats: ${total} | confirmed ${count("confirmed")} | gap-only ${count("gap-only")} | ` +
      `assumption-only ${count("assumption-only")}`,
  );
  console.log(
    `pass 2 fired: ${count("gap-only") > 0 ? "yes" : "NO (no threat cites only gap evidence)"}`,
  );
  if (total > 0) {
    console.log(
      `gap-only share: ${Math.round((100 * count("gap-only")) / total)}% (expected roughly 25-50%)`,
    );
  }

  printUsage();
}

main()
  .catch((error: unknown) => {
    // Never print the error object: an AiError's cause chain carries the API's response
    // body and headers, which can echo request content.
    console.error(`failed after ${elapsed()}`);
    if (error instanceof AiError) {
      console.error(`${error.name} [${error.code}]: ${error.message}`);
      for (const issue of error.issues) {
        console.error(`  - ${issue.path}: ${issue.message}`);
      }
    } else if (error instanceof IngestError) {
      console.error(`[${error.code}] ${error.message}`);
    } else {
      console.error(error instanceof Error ? error.message : String(error));
    }
    printUsage();
    process.exitCode = 1;
  })
  .finally(() => closeClient());
