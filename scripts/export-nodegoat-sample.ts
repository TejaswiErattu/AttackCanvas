/**
 * Export the saved NodeGoat threat model as an offline sample fixture. No model, GitHub or
 * Semgrep call.
 *
 *   pnpm try scripts/export-nodegoat-sample.ts
 *
 * Reads eval/results/nodegoat-a3118b6.json, validates its threat model with
 * ThreatModelSchema, checks that at least one dashboard-visible threat is evidence_backed
 * and one is assumption_dependent (so the sample shows both bases), and writes
 * fixtures/samples/nodegoat-a3118b6.json. Nothing is written when a check fails.
 *
 * Offline only. It is deliberately NOT fixtures/golden-demo.json: src/server/analysis/demo.ts
 * serves that file for whatever GOLDEN_REPO_URL names, and a real repository URL must never
 * silently return a canned result. The demo stays on the synthetic acme/acme-notes model
 * (fixtures/demo-analysis.json). Serving this snapshot would need an explicitly labelled
 * sample mode, which does not exist yet.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { ThreatModelSchema } from "@/shared/schema";
import { goldenProblems, visibleBases } from "./eval/lib";

const ROOT = process.cwd();
const SOURCE = "eval/results/nodegoat-a3118b6.json";
const TARGET = "fixtures/samples/nodegoat-a3118b6.json";

function main(): number {
  const raw = JSON.parse(readFileSync(`${ROOT}/${SOURCE}`, "utf8")) as { threatModel?: unknown };
  const parsed = ThreatModelSchema.safeParse(raw.threatModel);
  if (!parsed.success) {
    const issues = parsed.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
    console.error(`${SOURCE}: threatModel is not a valid ThreatModel:\n  ${issues.join("\n  ")}`);
    return 1;
  }
  const problems = goldenProblems(parsed.data);
  if (problems.length > 0) {
    console.error(`${SOURCE} cannot be the sample: ${problems.join("; ")}`);
    return 1;
  }
  // The parsed copy, not the raw one: the schema drops anything it does not know.
  writeFileSync(`${ROOT}/${TARGET}`, `${JSON.stringify(parsed.data, null, 2)}\n`);
  const bases = visibleBases(parsed.data);
  console.log(
    `${TARGET}: ${parsed.data.threats.length} threats; visible ${bases.evidenceBacked} evidence_backed, ${bases.assumptionDependent} assumption_dependent; ${parsed.data.questions.length} question(s)`,
  );
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  console.error(error instanceof Error ? error.message : "unexpected error");
  process.exitCode = 1;
}
