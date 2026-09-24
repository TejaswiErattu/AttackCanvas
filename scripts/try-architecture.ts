/**
 * Smoke test: run the whole evidence pipeline over a real repository and ask the model
 * for an architecture (Prompt N1).
 *
 *   pnpm try scripts/try-architecture.ts expressjs/express
 *
 * Loads through the GitHub MCP client, runs the deterministic detectors, builds the
 * Prompt L context, then makes ONE paid model call. Needs ANTHROPIC_API_KEY,
 * GITHUB_PERSONAL_ACCESS_TOKEN (environment or .env.local) and Docker.
 *
 * Semgrep and OSV are optional inputs to buildRepoFacts and are deliberately not run
 * here: this script exists to check the architecture step, and leaving them out keeps
 * the run to one Docker container and a few seconds. The output says so.
 *
 * What to read in the output:
 *   - components, flows and boundaries should match what you know about the repository;
 *   - each unknown should name a control and a component and be answerable in one
 *     sentence;
 *   - "possible gap duplicates" should be empty. Anything listed there means the
 *     prompt's first EXPECTED CONTROLS bullet is not landing, and the model is asking
 *     about controls the detector already proved absent.
 */

import { AiError } from "@/server/ai/claude";
import { activeProfile, modelFor } from "@/server/ai/models";
import { formatUsd, usageLedger } from "@/server/ai/usage";
import {
  ARCHITECTURE_CONTEXT_TOKENS,
  inferArchitecture,
  mergeArchitecture,
} from "@/server/analysis/architecture";
import { buildContext, buildRepoFacts } from "@/server/analysis/context";
import { runDetectors } from "@/server/detect";
import { IngestError, loadRepository } from "@/server/ingest/loader";
import { closeClient } from "@/server/mcp/githubClient";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

/** Accepts "owner/repo" or a github.com URL. */
function parseTarget(input: string): { owner: string; repo: string } {
  const cleaned = input.trim().replace(/\.git$/, "");
  const match =
    /^https?:\/\/github\.com\/([^/]+)\/([^/?#]+)/.exec(cleaned) ??
    /^([^/\s]+)\/([^/\s]+)$/.exec(cleaned);

  if (!match) {
    throw new Error(
      `could not read "${input}" as owner/repo or a github.com URL`,
    );
  }
  return { owner: match[1], repo: match[2] };
}

function section(title: string, rows: string[]): void {
  console.log(`\n${title} (${rows.length})`);
  for (const row of rows) console.log(`  ${row}`);
}

/**
 * Unknowns that look like they restate a gap the detector already reported. Matched on
 * a shared significant word from the gap's control text plus a mention of the file's
 * component, which over-reports rather than under-reports on purpose: this is a prompt
 * for a human to go and read, not a check anything depends on.
 */
function gapDuplicates(
  unknowns: readonly { id: string; description: string }[],
  gaps: readonly { id: string; control: string }[],
): string[] {
  const out: string[] = [];
  for (const unknown of unknowns) {
    const description = unknown.description.toLowerCase();
    for (const gap of gaps) {
      const words = gap.control
        .toLowerCase()
        .split(/[^a-z]+/)
        .filter((word) => word.length > 4);
      if (
        words.length > 0 &&
        words.every((word) => description.includes(word))
      ) {
        out.push(`${unknown.id} restates ${gap.id} ("${gap.control}")`);
        break;
      }
    }
  }
  return out;
}

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error("usage: pnpm try scripts/try-architecture.ts <owner/repo>");
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
  console.log(`model:   ${modelFor("architecture", profile)}`);
  console.log(
    "scanners: semgrep and OSV not run (this script checks N1 only)\n",
  );

  console.log(`loading ${owner}/${repo} …`);
  const loaded = await loadRepository(owner, repo);
  console.log(`${loaded.files.length} files, ref ${loaded.summary.ref}`);

  const detector = runDetectors(loaded.files);
  const facts = buildRepoFacts({
    summary: loaded.summary,
    detector,
    files: loaded.files,
  });

  const context = buildContext(facts, ARCHITECTURE_CONTEXT_TOKENS);
  console.log(
    `context: ~${context.estimatedTokens} tokens, ` +
      `${context.includedFiles.length} files included, ` +
      `${context.droppedFiles.length} dropped, ${detector.gaps.length} gaps`,
  );

  const analysisId = `try-architecture-${owner}-${repo}`;
  console.log("\ncalling the model …");
  const { draft, usage, attempts, promptId, draftPath } =
    await inferArchitecture({
      repo: { owner, name: repo },
      context,
      analysisId,
    });

  section(
    "components",
    draft.components.map(
      (c) =>
        `${c.id.padEnd(24)} ${c.type.padEnd(17)} ${c.files.length} file(s)  ${c.name}`,
    ),
  );
  section(
    "data flows",
    draft.dataFlows.map(
      (f) =>
        `${f.sourceId} -> ${f.targetId} [${f.dataClassification}]` +
        `${f.crossesTrustBoundary ? " (crosses boundary)" : ""}  ${f.label}`,
    ),
  );
  section(
    "trust boundaries",
    draft.trustBoundaries.map((b) => `${b.name}: ${b.componentIds.join(", ")}`),
  );
  section(
    "unknowns",
    draft.unknowns.map(
      (u) => `${u.description}  [affects: ${u.affectsComponentIds.join(", ")}]`,
    ),
  );

  const crossing = draft.dataFlows.filter((f) => f.crossesTrustBoundary).length;
  console.log(
    `\n${crossing}/${draft.dataFlows.length} flows marked as crossing a boundary`,
  );

  const duplicates = gapDuplicates(draft.unknowns, detector.gaps);
  section("possible gap duplicates", duplicates);
  if (duplicates.length > 0) {
    console.log(
      "  ^ read these: an unknown restating a proved gap means the prompt's first\n" +
        "    EXPECTED CONTROLS bullet is not landing.",
    );
  }

  if (draft.unknowns.length > 12) {
    console.log(
      `\nnote: ${draft.unknowns.length} unknowns returned; the prompt asks for at most 12.`,
    );
  }
  if (draftPath) console.log(`\nraw draft: ${draftPath}`);

  // Prompt N2. Pure and free: it runs on the draft already paid for above.
  const merged = mergeArchitecture(draft, facts);
  console.log("\n=== merged (Prompt N2) ===");
  section(
    "components",
    merged.components.map(
      (c) =>
        `${c.id.padEnd(24)} ${c.type.padEnd(17)} @(${c.position?.x},${c.position?.y})  ` +
        `evidence: ${(merged.componentEvidence.get(c.id) ?? []).join(", ") || "none"}`,
    ),
  );
  section(
    "unknowns",
    merged.unknowns.map(
      (u) => `${u.description}  [affects: ${u.affectsComponentIds.join(", ")}]`,
    ),
  );
  section(
    "gap bindings",
    [...merged.gapBindings].map(
      ([gapId, componentIds]) =>
        `${gapId} -> ${componentIds.join(", ") || "(none)"}`,
    ),
  );
  section("limitations", merged.limitations);
  section(
    "issues",
    merged.issues.map((i) => `${i.code} ${i.path}: ${i.message}`),
  );
  if (merged.limitations.length === 0) {
    console.log(
      "\nnote: the merge recorded no limitations. Either the model behaved unusually\n" +
        "well or the drop logic did not run; check on a second repository.",
    );
  }

  const total = usageLedger.forAnalysis(analysisId);
  console.log(
    `\nprompt ${promptId} | attempts ${attempts} | requests ${usage.requests} | ` +
      `in ${usage.inputTokens} out ${usage.outputTokens} ` +
      `cache-read ${usage.cacheReadTokens} cache-write ${usage.cacheWriteTokens}`,
  );
  console.log(
    `cost: ${formatUsd(usage.costUsd)} (analysis total ${formatUsd(total.totalUsd)})`,
  );
}

main()
  .catch((error: unknown) => {
    // Never print the error object: an AiError's cause chain carries the API's response
    // body and headers, which can echo request content.
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
    process.exitCode = 1;
  })
  .finally(() => closeClient());
