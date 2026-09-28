/**
 * How much do several saved runs of one repository agree? Reads eval/results/<name>.json for
 * each name and writes eval/consistency/report.md and eval/consistency/results.json.
 * Makes no model call and no network call.
 *
 *   pnpm try scripts/eval/consistency.ts nodegoat-final-r1 nodegoat-final-r2 nodegoat-final-r3
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { analyseConsistency, renderConsistencyReport } from "./consistencyLib";
import { EvalResultSchema, evalPaths } from "./lib";

const ROOT = process.cwd();

function main(): void {
  const names = process.argv.slice(2);
  if (names.length < 2 || names.some((n) => n.startsWith("--"))) {
    console.error("usage: consistency.ts <result-name> <result-name> [...]");
    process.exitCode = 1;
    return;
  }
  const results = names.map((name) => {
    const file = evalPaths(ROOT, name).result;
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      throw new Error(`cannot read eval/results/${name}.json`);
    }
    const parsed = EvalResultSchema.safeParse(raw);
    if (!parsed.success) throw new Error(`eval/results/${name}.json is not a valid result`);
    return parsed.data;
  });
  const consistency = analyseConsistency(results);
  const dir = `${ROOT}/eval/consistency`;
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}/report.md`, renderConsistencyReport(consistency, new Date().toISOString()));
  writeFileSync(`${dir}/results.json`, JSON.stringify(consistency, null, 2) + "\n");
  console.log(`wrote eval/consistency/report.md and results.json for ${names.join(", ")}`);
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : "unexpected error");
  process.exitCode = 1;
}
