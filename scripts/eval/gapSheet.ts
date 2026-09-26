/**
 * Evaluation, gap precision: write the sheet a person labels to say whether each
 * gap-only threat's missing control is really missing. No model is involved and nothing is
 * judged here.
 *
 *   pnpm try scripts/eval/gapSheet.ts nodegoat-a3118b6
 *   pnpm try scripts/eval/gapSheet.ts nodegoat-a3118b6 --force   # overwrite an existing sheet
 *
 * Reads eval/results/<run>.json and writes eval/labels/<run>.gaps.csv with one row per
 * threat whose cited evidence is only control gaps (ruleId starts "gap:"). The columns
 * gapLabel (predicted_correct | predicted_wrong) and notes are left empty for a person.
 * scripts/eval/score.ts reads the filled sheet.
 *
 * Refuses to overwrite a sheet that already exists, because that would erase hand labels.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { EvalResultSchema, buildGapSheet, evalPaths, gapSheetRows } from "./lib";

const ROOT = process.cwd();
const args = process.argv.slice(2);
const force = args.includes("--force");
const names = args.filter((a) => !a.startsWith("--"));

function main(): number {
  if (names.length !== 1 || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(names[0])) {
    console.error("usage: gapSheet.ts <run> [--force]   (a run name from eval/repos.yaml, e.g. nodegoat-a3118b6)");
    return 1;
  }
  const run = names[0];
  const paths = evalPaths(ROOT, run);
  if (!existsSync(paths.result)) {
    console.error(`${run}: no result at eval/results/${run}.json`);
    return 1;
  }
  if (existsSync(paths.gaps) && !force) {
    console.error(`${run}: eval/labels/${run}.gaps.csv already exists; not overwriting (--force to replace)`);
    return 1;
  }
  const parsed = EvalResultSchema.safeParse(JSON.parse(readFileSync(paths.result, "utf8")));
  if (!parsed.success) {
    console.error(`${run}: eval/results/${run}.json is not a valid result`);
    return 1;
  }
  const model = parsed.data.threatModel;
  const rows = gapSheetRows(model);
  mkdirSync(dirname(paths.gaps), { recursive: true });
  writeFileSync(paths.gaps, buildGapSheet(model));
  const visible = rows.filter((r) => r.visible).length;
  console.log(`${run}: ${rows.length} rows (${visible} visible, ${rows.length - visible} hidden) of ${model.threats.length} threats -> eval/labels/${run}.gaps.csv`);
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  console.error(error instanceof Error ? error.message : "unexpected error");
  process.exitCode = 1;
}
