/**
 * Local check, no model call: render every threat batch for a real repository and prove
 * that no known credential literal is in any model-bound text.
 *
 *   pnpm try scripts/verify-threat-payloads.ts bezkoder/node-js-express-login-example
 *
 * Loads the repository through the GitHub MCP client (free), runs the detectors, reuses
 * the saved architecture draft from .debug/<repo>/architecture.draft.json, merges it and
 * builds each batch's payload exactly as generateThreats does, then searches for the
 * credential values found in the sample config files.
 *
 * The values are held in memory only. Nothing here prints one: the output is counts and
 * file/field locations, plus the length of a value (which is not the value).
 */

import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { mergeArchitecture } from "@/server/analysis/architecture";
import { buildRepoFacts, debugDirName } from "@/server/analysis/context";
import { batchElements } from "@/server/analysis/threats";
import { buildThreatBatch } from "@/server/analysis/threatPrompt";
import { runDetectors } from "@/server/detect";
import { IngestError, loadRepository } from "@/server/ingest/loader";
import { closeClient } from "@/server/mcp/githubClient";
import { ArchitectureDraftSchema } from "@/shared/schema";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

/** Files whose credential-shaped literals are the known sample secrets. */
const SAMPLE_FILES = ["app/config/db.config.js", "app/config/auth.config.js"];

/** key: "value", key = 'value', "key": `value` for a key that names a credential. */
const ASSIGNMENT =
  /["'`]?([\w$-]*(?:password|passwd|pwd|secret|token|api[_-]?key)[\w$]*)["'`]?\s*[:=]\s*(["'`])(.+?)\2/i;

type Sentinel = { label: string; value: string };

function findSentinels(
  files: readonly { path: string; content: string }[],
): Sentinel[] {
  const out: Sentinel[] = [];
  for (const path of SAMPLE_FILES) {
    const file = files.find((f) => f.path === path);
    if (!file) continue;
    file.content.split("\n").forEach((line, index) => {
      const match = ASSIGNMENT.exec(line);
      if (!match) return;
      out.push({
        label: `${path}:${index + 1} key "${match[1]}" (length ${match[3].length})`,
        value: match[3],
      });
    });
  }
  return out;
}

/** Where in a payload a value occurs: the repo_file block it is in, or "element block". */
function locate(text: string, value: string): string[] {
  const where: string[] = [];
  let block = "element block";
  text.split("\n").forEach((line, index) => {
    const open = /^<repo_file path="([^"]*)">$/.exec(line);
    if (open) block = `repo_file ${open[1]}`;
    if (line === "</repo_file>") block = "element block";
    if (line.includes(value)) where.push(`line ${index + 1} in ${block}`);
  });
  return where;
}

async function scanDir(dir: string, values: readonly string[]): Promise<string[]> {
  const hits: string[] = [];
  let entries: import("node:fs").Dirent[];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return hits;
  }
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) hits.push(...(await scanDir(path, values)));
    else {
      const text = await readFile(path, "utf8").catch(() => "");
      const found = values.filter((v) => text.includes(v)).length;
      if (found > 0) hits.push(`${path} (${found} sentinel(s))`);
    }
  }
  return hits;
}

function parseTarget(input: string): { owner: string; repo: string } {
  const match = /^([^/\s]+)\/([^/\s]+)$/.exec(input.trim());
  if (!match) throw new Error(`could not read "${input}" as owner/repo`);
  return { owner: match[1], repo: match[2] };
}

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error("usage: pnpm try scripts/verify-threat-payloads.ts <owner/repo>");
    process.exitCode = 1;
    return;
  }
  const { owner, repo } = parseTarget(target);

  console.log(`loading ${owner}/${repo} (no model call) ...`);
  const loaded = await loadRepository(owner, repo);
  const detector = runDetectors(loaded.files);
  const facts = buildRepoFacts({
    summary: loaded.summary,
    detector,
    files: loaded.files,
  });

  const draftPath = join(".debug", debugDirName(owner, repo), "architecture.draft.json");
  const draft = ArchitectureDraftSchema.parse(
    JSON.parse(await readFile(draftPath, "utf8")),
  );
  const merged = mergeArchitecture(draft, facts);
  const plan = batchElements(merged);

  const sentinels = findSentinels(loaded.files);
  console.log(`\nsentinels found in the sample config files: ${sentinels.length}`);
  sentinels.forEach((s, i) => console.log(`  sentinel-${i + 1}: ${s.label}`));
  const values = sentinels.map((s) => s.value);

  // ---- every batch payload ----
  let markerTotal = 0;
  let leakTotal = 0;
  console.log(`\nbatches: ${plan.length}`);
  plan.forEach((elementIds, index) => {
    const batch = buildThreatBatch({
      architecture: merged,
      gaps: detector.gaps,
      elementIds,
      files: loaded.files,
    });
    const markers = (batch.text.match(/\[REDACTED:[a-z_]+\]/g) ?? []).length;
    markerTotal += markers;
    console.log(
      `  batch ${index + 1}: ${elementIds.join(", ")} | ${batch.text.length} chars | ` +
        `${batch.includedFiles.length} file(s) | ${markers} redaction marker(s)`,
    );
    sentinels.forEach((s, i) => {
      const where = locate(batch.text, s.value);
      leakTotal += where.length;
      if (where.length > 0) {
        console.log(`    LEAK sentinel-${i + 1}: ${where.length} occurrence(s): ${where.join("; ")}`);
      }
    });
    // Markers in the sample config files, by line, so they can be matched to the values.
    const lines = batch.text.split("\n");
    let block = "";
    lines.forEach((line, n) => {
      const open = /^<repo_file path="([^"]*)">$/.exec(line);
      if (open) block = open[1];
      if (line === "</repo_file>") block = "";
      if (SAMPLE_FILES.includes(block) && /\[REDACTED:[a-z_]+\]/.test(line)) {
        console.log(`    marker in ${block} at payload line ${n + 1}`);
      }
    });
  });

  // ---- every other model-bound structure, field by field ----
  const fields: Record<string, string> = {
    "architecture components": JSON.stringify(merged.components),
    "architecture data flows": JSON.stringify(merged.dataFlows),
    "architecture unknowns": JSON.stringify(merged.unknowns),
    "architecture limitations": JSON.stringify(merged.limitations),
    "merged evidence": JSON.stringify(merged.evidence),
    "detector gaps": JSON.stringify(detector.gaps),
    "detector evidence": JSON.stringify(detector.evidence),
  };
  console.log("\nother fields:");
  for (const [name, text] of Object.entries(fields)) {
    const hits = sentinels
      .map((s, i) => (text.includes(s.value) ? `sentinel-${i + 1}` : ""))
      .filter(Boolean);
    leakTotal += hits.length;
    console.log(`  ${name}: ${hits.length === 0 ? "clean" : `LEAK ${hits.join(", ")}`}`);
  }

  // ---- generated files ----
  const debugHits = await scanDir(".debug", values);
  console.log(
    `\ngenerated files under .debug that contain a sentinel: ${debugHits.length}`,
  );
  debugHits.forEach((h) => console.log(`  ${h}`));

  console.log(
    `\nsummary: ${plan.length} batches, ${markerTotal} redaction markers in payloads, ` +
      `${leakTotal} sentinel occurrence(s) in model-bound data`,
  );
  if (leakTotal > 0) process.exitCode = 2;
}

main()
  .catch((error: unknown) => {
    if (error instanceof IngestError) console.error(`[${error.code}] ${error.message}`);
    else console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  })
  .finally(() => closeClient());
