/**
 * Evaluation step 2: turn each saved result into a label sheet, eval/labels/<repo>.csv,
 * with one row per threat. No model is involved and nothing is judged here: the columns
 * matchesExpected, supported (y/n), evidenceCorrect (correct/total, e.g. 2/3) and notes are
 * left empty for a person to fill in.
 *
 *   pnpm try scripts/eval/label.ts            # every repo with a saved result
 *   pnpm try scripts/eval/label.ts nodegoat
 *   pnpm try scripts/eval/label.ts nodegoat --force   # overwrite an existing sheet
 *
 * Refuses to overwrite a sheet that already exists, because that would erase hand labels.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  EvalResultSchema,
  ReposFileSchema,
  buildLabelSheet,
  evalPaths,
  parseYamlWith,
  selectRepos,
} from "./lib";

const ROOT = process.cwd();
const args = process.argv.slice(2);
const force = args.includes("--force");

function main(): void {
  const config = parseYamlWith(readFileSync(`${ROOT}/eval/repos.yaml`, "utf8"), ReposFileSchema, "eval/repos.yaml");
  const repos = selectRepos(config.repos, args.filter((a) => !a.startsWith("--")));

  for (const repo of repos) {
    const paths = evalPaths(ROOT, repo.name);
    if (!existsSync(paths.result)) {
      console.error(`${repo.name}: no result at eval/results/${repo.name}.json (run scripts/eval/run.ts first)`);
      process.exitCode = 1;
      continue;
    }
    if (existsSync(paths.labels) && !force) {
      console.error(`${repo.name}: eval/labels/${repo.name}.csv already exists; not overwriting (--force to replace)`);
      process.exitCode = 1;
      continue;
    }
    const parsed = EvalResultSchema.safeParse(JSON.parse(readFileSync(paths.result, "utf8")));
    if (!parsed.success) {
      console.error(`${repo.name}: eval/results/${repo.name}.json is not a valid result`);
      process.exitCode = 1;
      continue;
    }
    mkdirSync(dirname(paths.labels), { recursive: true });
    writeFileSync(paths.labels, buildLabelSheet(parsed.data.threatModel));
    console.log(`${repo.name}: ${parsed.data.threatModel.threats.length} rows -> eval/labels/${repo.name}.csv`);
  }
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : "unexpected error");
  process.exitCode = 1;
}
