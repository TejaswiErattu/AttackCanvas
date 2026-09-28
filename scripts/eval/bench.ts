/**
 * The seeded bench: score the detectors (and Semgrep, when it is installed) against the
 * labelled seeded repositories in tests/fixtures/seeded/. Free and offline: no model call,
 * no GitHub, no OSV.
 *
 *   pnpm bench
 *
 * Always runs a detectors-only pass (the mode tests/bench.test.ts gates on, since it needs
 * no local binary). When `semgrep` is on PATH it also runs a detectors+Semgrep pass through
 * the same MCP client the pipeline uses (`semgrep mcp`, metrics off). Each pass runs three
 * times from a fresh load and reports whether the outputs are byte-identical.
 *
 * Writes eval/bench/results.json (no timestamp or commit, so it is byte-stable for the same
 * code) and eval/bench/report.md (dated, with the commit; anything below its notes marker
 * is kept across runs). Exits 1 if a label check fails or a pass is not deterministic.
 *
 * Fixture repositories are refused outside development and test (fixtureLoader.ts), so the
 * script is run with NODE_ENV=development by the package.json entry.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fixturesEnabled } from "@/server/ingest/fixtureLoader";
import { closeSemgrepClient, scanFiles } from "@/server/mcp/semgrepClient";
import {
  benchRow,
  mergeReport,
  renderReport,
  renderSummary,
  runBench,
  type BenchResult,
} from "./benchLib";

const OUT_DIR = join("eval", "bench");

function semgrepVersion(): string | undefined {
  const run = spawnSync("semgrep", ["--version"], { encoding: "utf8", env: { ...process.env, SEMGREP_ENABLE_VERSION_CHECK: "0" } });
  if (run.status !== 0) return undefined;
  return run.stdout.trim().split("\n").at(-1)?.trim() || "unknown version";
}

function git(args: string[]): string {
  const run = spawnSync("git", args, { encoding: "utf8" });
  return run.status === 0 ? run.stdout.trim() : "";
}

async function main(): Promise<number> {
  if (!fixturesEnabled()) {
    console.error("bench: fixture repositories load only with NODE_ENV=development or test; run `pnpm bench`.");
    return 1;
  }

  const version = semgrepVersion();
  const semgrepStatus = version ? `run (${version})` : "not on PATH, skipped";
  console.log(`semgrep: ${semgrepStatus}`);

  const results: BenchResult[] = [await runBench()];
  if (version) {
    try {
      results.push(await runBench({ scan: scanFiles }));
    } finally {
      await closeSemgrepClient();
    }
  } else {
    const skipped = results[0].run.total.skipped;
    console.log(`semgrep: ${skipped} issue(s) labelled only by a Semgrep rule were not scored`);
  }

  const commit = `${git(["rev-parse", "--short", "HEAD"]) || "unknown"}${git(["status", "--porcelain", "--untracked-files=no"]) ? "+dirty" : ""}`;
  // Local calendar date, the one a person running it would write down.
  const meta = { date: new Date().toLocaleDateString("en-CA"), commit, semgrep: semgrepStatus };

  for (const result of results) console.log(`\n${renderSummary(result)}`);
  console.log("\nbench rows:");
  for (const result of results) console.log(benchRow(result, meta));

  mkdirSync(OUT_DIR, { recursive: true });
  const json = {
    semgrep: version ? "run" : "skipped",
    modes: results.map((result) => ({ deterministic: result.deterministic, hashes: result.hashes, ...result.run })),
  };
  writeFileSync(join(OUT_DIR, "results.json"), `${JSON.stringify(json, null, 2)}\n`);
  const reportPath = join(OUT_DIR, "report.md");
  const existing = existsSync(reportPath) ? readFileSync(reportPath, "utf8") : undefined;
  writeFileSync(reportPath, mergeReport(renderReport(results, meta), existing));
  console.log(`\nwrote ${join(OUT_DIR, "results.json")} and ${reportPath}`);

  return results.every((result) => result.deterministic) ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (error: unknown) => {
    console.error(`bench: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  },
);
