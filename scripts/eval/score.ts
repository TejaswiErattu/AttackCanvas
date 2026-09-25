/**
 * Evaluation step 3: score the hand-filled label sheets and write docs/evaluation.md.
 *
 *   pnpm try scripts/eval/score.ts            # every repo in eval/repos.yaml
 *   pnpm try scripts/eval/score.ts nodegoat
 *
 * Reads, per repo: eval/results/<repo>.json (cost), eval/labels/<repo>.csv (your labels)
 * and eval/expected/<repo>.yaml ({ expectedThreats: [{ id, description }] }). Computes
 * recall, unsupported rate, evidence accuracy and cost. Refuses to score a sheet that is not
 * fully labeled or that names an expected id that does not exist, and lists every problem.
 * Pure arithmetic on your labels; no model is called.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
  EvalResultSchema,
  ExpectedFileSchema,
  ReposFileSchema,
  computeRepoMetrics,
  evalPaths,
  parseLabels,
  parseYamlWith,
  renderEvaluationReport,
  revisionMismatch,
  selectRepos,
  type RepoMetrics,
} from "./lib";

const ROOT = process.cwd();

function main(): void {
  const config = parseYamlWith(readFileSync(`${ROOT}/eval/repos.yaml`, "utf8"), ReposFileSchema, "eval/repos.yaml");
  const repos = selectRepos(config.repos, process.argv.slice(2).filter((a) => !a.startsWith("--")));

  const metrics: RepoMetrics[] = [];
  const profiles = new Set<string>();
  const failures: string[] = [];

  for (const repo of repos) {
    const paths = evalPaths(ROOT, repo.name);
    const missing = [paths.result, paths.labels, paths.expected].filter((p) => !existsSync(p));
    if (missing.length > 0) {
      failures.push(`${repo.name}: missing ${missing.map((p) => p.replace(`${ROOT}/`, "")).join(", ")}`);
      continue;
    }
    try {
      const result = EvalResultSchema.parse(JSON.parse(readFileSync(paths.result, "utf8")));
      const expected = parseYamlWith(readFileSync(paths.expected, "utf8"), ExpectedFileSchema, `eval/expected/${repo.name}.yaml`);
      const mismatch = revisionMismatch(expected, result.threatModel.repo.ref);
      if (mismatch) throw new Error(mismatch);
      const labels = parseLabels(readFileSync(paths.labels, "utf8"), new Set(expected.expectedThreats.map((t) => t.id)));
      const inModel = new Set(result.threatModel.threats.map((t) => t.id));
      const stale = labels.filter((l) => !inModel.has(l.threatId)).map((l) => l.threatId);
      if (stale.length > 0 || labels.length !== inModel.size) {
        throw new Error(
          `label sheet does not match eval/results/${repo.name}.json (${labels.length} rows vs ${inModel.size} threats` +
            `${stale.length > 0 ? `; unknown ids ${stale.join(", ")}` : ""}); re-run label.ts --force only if you have no labels to keep`,
        );
      }
      metrics.push(computeRepoMetrics(repo.name, labels, expected, result.cost));
      profiles.add(result.modelProfile);
    } catch (error) {
      failures.push(`${repo.name}: ${error instanceof Error ? error.message : "unexpected error"}`);
    }
  }

  if (failures.length > 0) {
    console.error(`cannot score; docs/evaluation.md not written:\n${failures.map((f) => `- ${f}`).join("\n")}`);
    process.exitCode = 1;
    return;
  }

  mkdirSync(`${ROOT}/docs`, { recursive: true });
  writeFileSync(
    `${ROOT}/docs/evaluation.md`,
    renderEvaluationReport(metrics, new Date().toISOString().slice(0, 10), [...profiles]),
  );
  for (const m of metrics) {
    console.log(
      `${m.repo}: recall ${m.matched.length}/${m.expected}, unsupported ${m.unsupported}/${m.threats}, ` +
        `evidence ${m.evidenceCorrect}/${m.evidenceTotal}, cost $${m.costUsd.toFixed(4)}`,
    );
  }
  console.log("wrote docs/evaluation.md");
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : "unexpected error");
  process.exitCode = 1;
}
