/**
 * Evaluation, second labeler: pick the threats a second person labels, to measure how far
 * two people agree. No model is involved.
 *
 *   pnpm try scripts/eval/sampleSecond.ts                       # nodegoat-a3118b6
 *   pnpm try scripts/eval/sampleSecond.ts nodegoat-a3118b6 --force
 *
 * Reads the finished primary sheet eval/labels/<run>.csv, takes 20 threats stratified on
 * its label values (supported crossed with matches-an-expected-item, at least one per
 * stratum, largest remainder) with a fixed-seed shuffle, and writes
 * eval/labels/<run>.second-blank.csv: the same columns and rows, with matchesExpected,
 * supported, evidenceCorrect and notes emptied so the second labeler sees none of the
 * first one's decisions. Fill it, save it as eval/labels/<run>.second.csv, and score.ts
 * reports the agreement. The same primary sheet always yields the same sample.
 *
 * Refuses to overwrite an existing second-blank sheet (--force to replace).
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  ExpectedFileSchema,
  SECOND_SAMPLE_SEED,
  SECOND_SAMPLE_SIZE,
  blankSecondSheet,
  evalPaths,
  parseLabels,
  parseYamlWith,
  stratifiedSample,
  strataKey,
} from "./lib";

const ROOT = process.cwd();
const args = process.argv.slice(2);
const force = args.includes("--force");
const names = args.filter((a) => !a.startsWith("--"));

function main(): number {
  const run = names[0] ?? "nodegoat-a3118b6";
  if (names.length > 1 || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(run)) {
    console.error("usage: sampleSecond.ts [run] [--force]");
    return 1;
  }
  const paths = evalPaths(ROOT, run);
  for (const path of [paths.labels, paths.expected]) {
    if (!existsSync(path)) {
      console.error(`${run}: missing ${path.replace(`${ROOT}/`, "")}`);
      return 1;
    }
  }
  if (existsSync(paths.secondBlank) && !force) {
    console.error(`${run}: eval/labels/${run}.second-blank.csv already exists; not overwriting (--force to replace)`);
    return 1;
  }
  const expected = parseYamlWith(readFileSync(paths.expected, "utf8"), ExpectedFileSchema, `eval/expected/${run}.yaml`);
  const primaryCsv = readFileSync(paths.labels, "utf8");
  const labels = parseLabels(primaryCsv, new Set(expected.expectedThreats.map((t) => t.id)));
  const ids = stratifiedSample(labels, SECOND_SAMPLE_SIZE, SECOND_SAMPLE_SEED);

  mkdirSync(dirname(paths.secondBlank), { recursive: true });
  writeFileSync(paths.secondBlank, blankSecondSheet(primaryCsv, ids));

  const picked = new Set(ids);
  const tally = (rows: typeof labels) => {
    const counts = new Map<string, number>();
    for (const l of rows) counts.set(strataKey(l), (counts.get(strataKey(l)) ?? 0) + 1);
    return [...counts].sort().map(([k, n]) => `${k} ${n}`).join(", ");
  };
  console.log(`${run}: ${ids.length} of ${labels.length} threats (seed ${SECOND_SAMPLE_SEED}) -> eval/labels/${run}.second-blank.csv`);
  console.log(`  primary strata: ${tally(labels)}`);
  console.log(`  sampled strata: ${tally(labels.filter((l) => picked.has(l.threatId)))}`);
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  console.error(error instanceof Error ? error.message : "unexpected error");
  process.exitCode = 1;
}
