/**
 * Evaluation step 3: score the hand-filled label sheets and write docs/evaluation.md.
 *
 *   pnpm try scripts/eval/score.ts            # every repo in eval/repos.yaml
 *   pnpm try scripts/eval/score.ts nodegoat
 *   pnpm try scripts/eval/score.ts nodegoat-a3118b6 --second   # also score the second labeler
 *
 * Reads, per repo: eval/results/<repo>.json (cost), eval/labels/<repo>.csv (your labels)
 * and eval/expected/<repo>.yaml ({ expectedThreats: [{ id, description }] }). Computes
 * recall, unsupported rate, evidence accuracy and cost, and found/missed per class from the
 * answer key's owasp2013 notes. Recall counts an expected item only when a row labelled
 * supported = y matches it (recalledIds in lib.ts); the per-class table uses the same set. Refuses to score a sheet that is not fully labeled or that
 * names an expected id that does not exist, and lists every problem.
 *
 * Two optional sheets add sections:
 *   eval/labels/<repo>.gaps.csv    (gapSheet.ts)     gap precision, overall and visible only.
 *                                  Skipped with a notice while no row has a gapLabel;
 *                                  refused once partially filled or out of step with the result.
 *   eval/labels/<repo>.second.csv  (sampleSecond.ts) agreement and Cohen's kappa with the
 *                                  primary labels. Read only with --second (opt-in), and then
 *                                  refused if not fully labelled. Without --second it is ignored.
 * Any other --flag is rejected.
 * Pure arithmetic on your labels; no model is called.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
  EvalResultSchema,
  ExpectedFileSchema,
  ReposFileSchema,
  compareLabelers,
  computeGapMetrics,
  computeRepoMetrics,
  evalPaths,
  gapSheetProblems,
  gapSheetStarted,
  parseGapLabels,
  parseLabels,
  parseYamlWith,
  recallByClass,
  renderEvaluationReport,
  revisionMismatch,
  secondSheetProblems,
  selectRepos,
  type RepoExtras,
  type RepoMetrics,
} from "./lib";

const ROOT = process.cwd();

const FLAGS = new Set(["--second"]);

function main(): void {
  const args = process.argv.slice(2);
  const unknown = args.filter((a) => a.startsWith("--") && !FLAGS.has(a));
  if (unknown.length > 0) throw new Error(`unknown option ${unknown.join(", ")}; usage: score.ts [repo...] [--second]`);
  const withSecond = args.includes("--second");
  const config = parseYamlWith(readFileSync(`${ROOT}/eval/repos.yaml`, "utf8"), ReposFileSchema, "eval/repos.yaml");
  const repos = selectRepos(config.repos, args.filter((a) => !a.startsWith("--")));
  const notices: string[] = [];

  const metrics: RepoMetrics[] = [];
  const extras: Record<string, RepoExtras> = {};
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
      const repoMetrics = computeRepoMetrics(repo.name, labels, expected, result.cost);
      const repoExtras: RepoExtras = { classes: recallByClass(expected, new Set(repoMetrics.matched)) };

      const gapsText = existsSync(paths.gaps) ? readFileSync(paths.gaps, "utf8") : undefined;
      if (gapsText !== undefined && !gapSheetStarted(gapsText)) {
        notices.push(`${repo.name}: eval/labels/${repo.name}.gaps.csv has no labels yet; gap precision skipped`);
      } else if (gapsText !== undefined) {
        const gapLabels = parseGapLabels(gapsText);
        const problems = gapSheetProblems(gapLabels, result.threatModel);
        if (problems.length > 0) {
          throw new Error(`gaps sheet does not match eval/results/${repo.name}.json:\n  ${problems.join("\n  ")}`);
        }
        repoExtras.gaps = computeGapMetrics(gapLabels);
      }
      if (existsSync(paths.second) && !withSecond) {
        notices.push(`${repo.name}: eval/labels/${repo.name}.second.csv ignored; pass --second to score it`);
      }
      if (withSecond && !existsSync(paths.second)) {
        throw new Error(`--second given but eval/labels/${repo.name}.second.csv does not exist`);
      }
      if (withSecond) {
        let secondLabels: ReturnType<typeof parseLabels>;
        try {
          secondLabels = parseLabels(readFileSync(paths.second, "utf8"), new Set(expected.expectedThreats.map((t) => t.id)));
        } catch (error) {
          throw new Error(`second sheet eval/labels/${repo.name}.second.csv: ${error instanceof Error ? error.message : "unreadable"}`);
        }
        const problems = secondSheetProblems(labels, secondLabels);
        if (problems.length > 0) {
          throw new Error(`second sheet does not match eval/labels/${repo.name}.csv:\n  ${problems.join("\n  ")}`);
        }
        repoExtras.labelers = compareLabelers(labels, secondLabels);
      }

      metrics.push(repoMetrics);
      extras[repo.name] = repoExtras;
      profiles.add(result.modelProfile);
    } catch (error) {
      failures.push(`${repo.name}: ${error instanceof Error ? error.message : "unexpected error"}`);
    }
  }

  for (const notice of notices) console.log(notice);
  if (failures.length > 0) {
    console.error(`cannot score; docs/evaluation.md not written:\n${failures.map((f) => `- ${f}`).join("\n")}`);
    process.exitCode = 1;
    return;
  }

  mkdirSync(`${ROOT}/docs`, { recursive: true });
  writeFileSync(
    `${ROOT}/docs/evaluation.md`,
    renderEvaluationReport(metrics, new Date().toISOString().slice(0, 10), [...profiles], extras),
  );
  for (const m of metrics) {
    console.log(
      `${m.repo}: recall ${m.matched.length}/${m.expected}, unsupported ${m.unsupported}/${m.threats}, ` +
        `evidence ${m.evidenceCorrect}/${m.evidenceTotal}, cost $${m.costUsd.toFixed(4)}`,
    );
    const gaps = extras[m.repo]?.gaps;
    if (gaps) {
      const wrong = gaps.wrongByKind.filter((k) => k.wrong > 0).map((k) => `${k.kind} ${k.wrong}`).join(", ") || "none";
      console.log(
        `${m.repo}: gap precision ${gaps.overall.correct}/${gaps.overall.n}, visible ${gaps.visible.correct}/${gaps.visible.n}; predicted_wrong by kind: ${wrong}`,
      );
    }
    const labelers = extras[m.repo]?.labelers;
    if (labelers) {
      console.log(
        `${m.repo}: second labeler agrees on ${labelers.supported.agreed}/${labelers.n} supported labels, kappa ${labelers.supported.kappa === null ? "n/a" : labelers.supported.kappa.toFixed(2)}`,
      );
    }
  }
  console.log("wrote docs/evaluation.md");
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : "unexpected error");
  process.exitCode = 1;
}
