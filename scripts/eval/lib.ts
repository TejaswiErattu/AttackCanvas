/**
 * The pure parts of the evaluation runner (scripts/eval/run.ts, label.ts, score.ts), kept
 * in their own module so tests can import them: the scripts themselves read files, call
 * paid APIs or write to disk the moment they are invoked.
 *
 * Nothing here calls a model. Every label in the CSVs is written by a person; this module
 * only lays the rows out and, later, does the arithmetic on what they filled in.
 */

import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { isHidden } from "@/server/scoring";
import { AnalysisLevelSchema, ThreatModelSchema, type AnalysisLevel, type AnalysisStage, type Evidence, type Threat, type ThreatModel } from "@/shared/schema";

// ---------------------------------------------------------------------------
// Files and config
// ---------------------------------------------------------------------------

/** A repo name becomes a file name (eval/results/<name>.json), so keep it boring. */
const REPO_NAME = /^[a-z0-9][a-z0-9-]{0,63}$/;

export const ReposFileSchema = z
  .object({
    repos: z
      .array(z.object({ name: z.string().regex(REPO_NAME), url: z.string() }))
      .min(1),
  })
  .superRefine((file, ctx) => {
    const seen = new Set<string>();
    file.repos.forEach((repo, index) => {
      if (seen.has(repo.name)) {
        ctx.addIssue({ code: "custom", path: ["repos", index, "name"], message: `duplicate repo name "${repo.name}"` });
      }
      seen.add(repo.name);
    });
  });
export type EvalRepo = z.infer<typeof ReposFileSchema>["repos"][number];

/** Ids are typed by hand into a CSV cell, so they must survive being split on ; , or space. */
const ExpectedId = z.string().regex(/^[A-Za-z0-9_.-]+$/, "use letters, digits, _ . - only");

export const ExpectedFileSchema = z
  .object({
    expectedThreats: z
      .array(
        z.object({
          id: ExpectedId,
          description: z.string().min(1),
          /** The answer key's own category (e.g. "A2", "A2/A3/A5", "SSRF (tutorial ssrf.html)"); the per-class table groups by it. */
          owasp2013: z.string().min(1).optional(),
        }),
      )
      .min(1),
    /** Commit the answer key was written against; score.ts refuses a result scanned at another ref. */
    revision: z.string().min(1).optional(),
    /** "guided" when the repo documents its own vulnerabilities in files the model sees. */
    mode: z.enum(["blind", "guided"]).optional(),
  })
  .superRefine((file, ctx) => {
    const seen = new Set<string>();
    file.expectedThreats.forEach((threat, index) => {
      if (seen.has(threat.id)) {
        ctx.addIssue({ code: "custom", path: ["expectedThreats", index, "id"], message: `duplicate id "${threat.id}"` });
      }
      seen.add(threat.id);
    });
  });
export type ExpectedFile = z.infer<typeof ExpectedFileSchema>;

/** What run.ts saves per repo and label.ts / score.ts read back. */
export const EvalResultSchema = z.object({
  repo: z.string(),
  repoUrl: z.string(),
  modelProfile: z.string(),
  ranAt: z.string(),
  /** The analysis level the run was requested at (run.ts --level). Absent in older results, which ran at 2. */
  level: AnalysisLevelSchema.optional(),
  /** Wall-clock milliseconds for the whole run. Absent in results saved before it was recorded. */
  durationMs: z.number().min(0).optional(),
  cost: z.object({ calls: z.number().int().min(0), totalUsd: z.number().min(0) }),
  threatModel: ThreatModelSchema,
  /**
   * The pipeline's diagnostics for the run (AnalysisState.diagnostics): what the merge,
   * the threat engine and the questions dropped or rebound, with ids. Absent in results
   * saved before diagnostics were split from the reader-facing limitations.
   */
  diagnostics: z.array(z.string()).optional(),
});
export type EvalResult = z.infer<typeof EvalResultSchema>;

/**
 * Null when the result was scanned at the answer key's revision (or the key names none),
 * else a printable reason. A branch name never matches a SHA: pin the run with /tree/<sha>.
 */
export function revisionMismatch(expected: ExpectedFile, scannedRef: string): string | null {
  if (!expected.revision || expected.revision === scannedRef) return null;
  return `result was scanned at "${scannedRef}" but the answer key is for "${expected.revision}"; pin the url in eval/repos.yaml to /tree/${expected.revision}`;
}

export function evalPaths(root: string, name: string) {
  return {
    result: join(root, "eval", "results", `${name}.json`),
    labels: join(root, "eval", "labels", `${name}.csv`),
    expected: join(root, "eval", "expected", `${name}.yaml`),
    /** Hand labels for the threats that cite only control gaps (gapSheet.ts). */
    gaps: join(root, "eval", "labels", `${name}.gaps.csv`),
    /** A second person's labels for a sample of the primary sheet (sampleSecond.ts). */
    second: join(root, "eval", "labels", `${name}.second.csv`),
    secondBlank: join(root, "eval", "labels", `${name}.second-blank.csv`),
  };
}

/** Parses a YAML string against a schema, with a printable reason on failure. */
export function parseYamlWith<T>(text: string, schema: z.ZodType<T>, label: string): T {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch {
    throw new Error(`${label}: not valid YAML`);
  }
  const result = schema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
    throw new Error(`${label}: ${issues.join("; ")}`);
  }
  return result.data;
}

/**
 * Result files that already exist for these repos, as paths relative to `root`. run.ts
 * refuses to start when any exist, so a finished result (a baseline) is never replaced by
 * a later run. There is no override flag: move the file away or add a new repo name.
 */
export function existingResultPaths(
  repos: readonly EvalRepo[],
  root: string,
  exists: (path: string) => boolean,
): string[] {
  return repos
    .map((repo) => evalPaths(root, repo.name).result)
    .filter(exists)
    .map((path) => path.slice(root.length + 1));
}

/** The repos to act on: all of them, or the named subset. Unknown names are an error. */
export function selectRepos(repos: readonly EvalRepo[], names: readonly string[]): EvalRepo[] {
  if (names.length === 0) return [...repos];
  const unknown = names.filter((n) => !repos.some((r) => r.name === n));
  if (unknown.length > 0) throw new Error(`not in eval/repos.yaml: ${unknown.join(", ")}`);
  return repos.filter((r) => names.includes(r.name));
}

/** A run needs a real GitHub URL; the checked-in file ships with blanks for the user to fill. */
export function requireRepoUrl(repo: EvalRepo): string {
  const url = repo.url.trim();
  if (!/^https:\/\/github\.com\/[^/\s]+\/[^/\s]+/.test(url)) {
    throw new Error(`eval/repos.yaml: "${repo.name}" needs a https://github.com/<owner>/<repo> url`);
  }
  return url;
}

// ---------------------------------------------------------------------------
// CSV (RFC 4180 subset: quoted cells, doubled quotes, embedded newlines)
// ---------------------------------------------------------------------------

/**
 * A cell that starts with one of these is run as a formula by Excel and Sheets. Threat
 * titles and file paths come from an analysed repository, i.e. untrusted text, so they are
 * defused with a leading apostrophe. The label columns the scorer reads are never written
 * with such a prefix by this module, and a person typing "y" or "3/4" is unaffected.
 */
const FORMULA_START = /^[=+\-@\t\r]/;

export function csvCell(value: string): string {
  const safe = FORMULA_START.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function toCsv(rows: readonly (readonly string[])[]): string {
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

/** Parses CSV text into rows of cells. Tolerates a BOM, CRLF or LF, and a missing final newline. */
export function parseCsv(text: string): string[][] {
  const src = text.replace(/^﻿/, "");
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  let i = 0;
  const endCell = () => {
    row.push(cell);
    cell = "";
  };
  const endRow = () => {
    endCell();
    rows.push(row);
    row = [];
  };
  while (i < src.length) {
    const ch = src[i];
    if (quoted) {
      if (ch === '"' && src[i + 1] === '"') {
        cell += '"';
        i += 2;
        continue;
      }
      if (ch === '"') quoted = false;
      else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") endCell();
    else if (ch === "\r") {
      if (src[i + 1] === "\n") i += 1;
      endRow();
    } else if (ch === "\n") endRow();
    else cell += ch;
    i += 1;
  }
  if (cell !== "" || row.length > 0) endRow();
  // Spreadsheet exports pad with fully empty lines; drop them.
  return rows.filter((r) => r.some((c) => c.trim() !== ""));
}

// ---------------------------------------------------------------------------
// Label sheet
// ---------------------------------------------------------------------------

/** Columns filled from the threat model, then the ones a person fills by hand. */
export const LABEL_COLUMNS = [
  "threatId",
  "title",
  "component",
  "stride",
  "severity",
  "confidence",
  "evidenceLocations",
  "matchesExpected",
  "supported",
  "evidenceCorrect",
  "notes",
] as const;
export type LabelColumn = (typeof LABEL_COLUMNS)[number];

/** "path:10-12", "path", or the rule id for evidence that has no file (a control gap). */
export function describeEvidenceLocation(evidence: Evidence): string {
  if (evidence.filePath) {
    if (evidence.lineStart === undefined) return evidence.filePath;
    const end = evidence.lineEnd !== undefined && evidence.lineEnd !== evidence.lineStart ? `-${evidence.lineEnd}` : "";
    return `${evidence.filePath}:${evidence.lineStart}${end}`;
  }
  return `(no file) ${evidence.ruleId ?? evidence.kind}`;
}

/**
 * One entry per cited evidence item, so the count of entries is the denominator a labeler
 * uses for evidenceCorrect ("2/3" = two of these three entries are right). An id that does
 * not resolve cannot happen in a validated ThreatModel, but is kept visible if it does.
 */
export function evidenceLocations(threat: Threat, evidenceById: ReadonlyMap<string, Evidence>): string {
  return threat.evidenceIds
    .map((id) => {
      const evidence = evidenceById.get(id);
      return `${id}: ${evidence ? describeEvidenceLocation(evidence) : "(missing)"}`;
    })
    .join(" | ");
}

export function threatToLabelRow(threat: Threat, model: ThreatModel): string[] {
  const evidenceById = new Map(model.evidence.map((e) => [e.id, e]));
  const componentNames = threat.componentIds.map(
    (id) => model.components.find((c) => c.id === id)?.name ?? id,
  );
  return [
    threat.id,
    threat.title,
    componentNames.join("; "),
    threat.stride.join(""),
    threat.severity,
    threat.confidence.toFixed(2),
    evidenceLocations(threat, evidenceById),
    "", // matchesExpected
    "", // supported
    "", // evidenceCorrect
    "", // notes
  ];
}

/** The whole sheet, header first: one row per threat, in the model's order, hand columns empty. */
export function buildLabelSheet(model: ThreatModel): string {
  return toCsv([[...LABEL_COLUMNS], ...model.threats.map((t) => threatToLabelRow(t, model))]);
}

// ---------------------------------------------------------------------------
// Reading filled labels
// ---------------------------------------------------------------------------

export type LabeledThreat = {
  threatId: string;
  /** Expected-threat ids this threat was matched to; empty = matches none. */
  matches: string[];
  supported: boolean;
  evidenceCorrect: number;
  evidenceTotal: number;
};

/**
 * Reads a filled label sheet. Blank matchesExpected means "matches nothing" (it is the
 * column's default, so it cannot also mean "not yet labeled"); supported and
 * evidenceCorrect must be filled on every row, so a half-labeled sheet cannot silently
 * skew the rates. Every problem is collected, not just the first.
 */
export function parseLabels(csvText: string, expectedIds: ReadonlySet<string>): LabeledThreat[] {
  const rows = parseCsv(csvText);
  if (rows.length === 0) throw new Error("label sheet is empty");
  const header = rows[0].map((h) => h.trim());
  const missing = LABEL_COLUMNS.filter((c) => !header.includes(c));
  if (missing.length > 0) throw new Error(`label sheet is missing column(s): ${missing.join(", ")}`);
  const col = (row: string[], name: LabelColumn) => (row[header.indexOf(name)] ?? "").trim();

  const problems: string[] = [];
  const out: LabeledThreat[] = [];
  const seen = new Set<string>();
  rows.slice(1).forEach((row, index) => {
    const threatId = col(row, "threatId");
    const where = `row ${index + 2} (${threatId || "no threatId"})`;
    if (!threatId) return void problems.push(`${where}: threatId is empty`);
    if (seen.has(threatId)) return void problems.push(`${where}: duplicate threatId`);
    seen.add(threatId);

    const matches = [...new Set(col(row, "matchesExpected").split(/[;,\s]+/).filter(Boolean))];
    const unknown = matches.filter((id) => !expectedIds.has(id));
    if (unknown.length > 0) problems.push(`${where}: matchesExpected has unknown id(s) ${unknown.join(", ")}`);

    const supportedRaw = col(row, "supported").toLowerCase();
    const supported = ["y", "yes"].includes(supportedRaw) ? true : ["n", "no"].includes(supportedRaw) ? false : null;
    if (supported === null) problems.push(`${where}: supported must be y or n, got "${supportedRaw}"`);

    const evidence = /^(\d+)\s*\/\s*(\d+)$/.exec(col(row, "evidenceCorrect"));
    if (!evidence) {
      problems.push(`${where}: evidenceCorrect must look like 2/3 (use 0/0 when no evidence is cited)`);
    } else if (Number(evidence[1]) > Number(evidence[2])) {
      problems.push(`${where}: evidenceCorrect ${evidence[1]}/${evidence[2]} has more correct than total`);
    }

    if (supported !== null && evidence && unknown.length === 0 && Number(evidence[1]) <= Number(evidence[2])) {
      out.push({
        threatId,
        matches,
        supported,
        evidenceCorrect: Number(evidence[1]),
        evidenceTotal: Number(evidence[2]),
      });
    }
  });
  if (rows.length === 1) problems.push("label sheet has no threat rows");
  if (problems.length > 0) throw new Error(`label sheet is not fully labeled:\n  ${problems.join("\n  ")}`);
  return out;
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

export type RepoMetrics = {
  repo: string;
  mode?: "blind" | "guided";
  threats: number;
  expected: number;
  /** Expected ids matched by at least one threat. */
  matched: string[];
  missed: string[];
  recall: number;
  unsupported: number;
  /** Threats labeled supported = n, over all threats. Null when there are no threats. */
  unsupportedRate: number | null;
  evidenceCorrect: number;
  evidenceTotal: number;
  /** Null when no threat cites any evidence. */
  evidenceAccuracy: number | null;
  costUsd: number;
  calls: number;
};

const ratio = (num: number, den: number): number | null => (den === 0 ? null : num / den);

/**
 * The expected ids a labelled sheet recalls: an item counts only when at least one row lists
 * it in matchesExpected AND is labelled supported = y (R1 in
 * eval/review/pending-evaluation-requirements.md). A row that matches an item but is
 * unsupported still counts toward the unsupported rate; it never recalls the item on its own.
 */
export function recalledIds(labels: readonly LabeledThreat[]): Set<string> {
  return new Set(labels.filter((l) => l.supported).flatMap((l) => l.matches));
}

export function computeRepoMetrics(
  repo: string,
  labels: readonly LabeledThreat[],
  expected: ExpectedFile,
  cost: { totalUsd: number; calls: number },
): RepoMetrics {
  const matchedSet = recalledIds(labels);
  const matched = expected.expectedThreats.map((t) => t.id).filter((id) => matchedSet.has(id));
  const missed = expected.expectedThreats.map((t) => t.id).filter((id) => !matchedSet.has(id));
  const unsupported = labels.filter((l) => !l.supported).length;
  const evidenceCorrect = labels.reduce((sum, l) => sum + l.evidenceCorrect, 0);
  const evidenceTotal = labels.reduce((sum, l) => sum + l.evidenceTotal, 0);
  return {
    repo,
    mode: expected.mode,
    threats: labels.length,
    expected: expected.expectedThreats.length,
    matched,
    missed,
    recall: matched.length / expected.expectedThreats.length,
    unsupported,
    unsupportedRate: ratio(unsupported, labels.length),
    evidenceCorrect,
    evidenceTotal,
    evidenceAccuracy: ratio(evidenceCorrect, evidenceTotal),
    costUsd: cost.totalUsd,
    calls: cost.calls,
  };
}

/** Pools counts across repos (not an average of averages), so a bigger repo weighs more. */
export function combineMetrics(all: readonly RepoMetrics[]): RepoMetrics {
  const sum = (pick: (m: RepoMetrics) => number) => all.reduce((s, m) => s + pick(m), 0);
  const expected = sum((m) => m.expected);
  const threats = sum((m) => m.threats);
  const unsupported = sum((m) => m.unsupported);
  const evidenceCorrect = sum((m) => m.evidenceCorrect);
  const evidenceTotal = sum((m) => m.evidenceTotal);
  return {
    repo: "all repos",
    threats,
    expected,
    matched: all.flatMap((m) => m.matched.map((id) => `${m.repo}/${id}`)),
    missed: all.flatMap((m) => m.missed.map((id) => `${m.repo}/${id}`)),
    recall: sum((m) => m.matched.length) / expected,
    unsupported,
    unsupportedRate: ratio(unsupported, threats),
    evidenceCorrect,
    evidenceTotal,
    evidenceAccuracy: ratio(evidenceCorrect, evidenceTotal),
    costUsd: sum((m) => m.costUsd),
    calls: sum((m) => m.calls),
  };
}

// ---------------------------------------------------------------------------
// docs/evaluation.md
// ---------------------------------------------------------------------------

const pct = (value: number | null) => (value === null ? "n/a" : `${(value * 100).toFixed(1)}%`);
const usd = (value: number) => `$${value.toFixed(4)}`;

function metricsRow(m: RepoMetrics): string {
  return (
    `| ${m.repo}${m.mode === "guided" ? " (guided)" : ""} | ${m.threats} | ${m.matched.length}/${m.expected} (${pct(m.recall)}) | ` +
    `${m.unsupported}/${m.threats} (${pct(m.unsupportedRate)}) | ` +
    `${m.evidenceCorrect}/${m.evidenceTotal} (${pct(m.evidenceAccuracy)}) | ${usd(m.costUsd)} (${m.calls} calls) |`
  );
}

export function renderEvaluationReport(
  perRepo: readonly RepoMetrics[],
  generatedAt: string,
  profiles: readonly string[],
  extras: Readonly<Record<string, RepoExtras>> = {},
): string {
  const rows = perRepo.length > 1 ? [...perRepo, combineMetrics(perRepo)] : [...perRepo];
  const missedSections = perRepo
    .filter((m) => m.missed.length > 0)
    .map((m) => `- **${m.repo}**: ${m.missed.join(", ")}`);
  const guided = perRepo.filter((m) => m.mode === "guided").map((m) => m.repo);
  return [
    "# Evaluation",
    "",
    "<!-- Generated by scripts/eval/score.ts from hand-labeled sheets. Edit only below the notes marker at the end. -->",
    "",
    Object.values(extras).some((e) => e.labelers)
      ? `Generated ${generatedAt}. Model profile: ${profiles.join(", ")}. The primary labels behind these numbers were entered by a person. The second-labeller sample was labelled by a separate, blind model session, not a person (see its section).`
      : `Generated ${generatedAt}. Model profile: ${profiles.join(", ")}. Every label behind these numbers was entered by a person; no model judged any output.`,
    "",
    ...(guided.length > 0
      ? [
          `**Guided evaluation:** ${guided.join(", ")} ship documentation of their own vulnerabilities in files the model reads, so their recall measures detection with hints, not blind discovery.`,
          "",
        ]
      : []),
    "| Repo | Threats | Recall | Unsupported | Evidence accuracy | Cost |",
    "| --- | ---: | ---: | ---: | ---: | ---: |",
    ...rows.map(metricsRow),
    "",
    "## Missed expected threats",
    "",
    ...(missedSections.length > 0 ? missedSections : ["None: every expected threat was matched."]),
    "",
    ...perRepo.flatMap((m) => renderExtras(m.repo, extras[m.repo])),
    "## Definitions",
    "",
    "- **Recall**: expected threats matched by at least one generated threat labelled `supported = y`, over expected threats. A generated threat is matched when its `matchesExpected` cell lists the expected id; a blank cell means it matches none. A match on an unsupported row does not recall the item (it counts toward Unsupported instead).",
    "- **Unsupported**: generated threats labeled `supported = n` (the cited code does not support the claim), over all generated threats. Lower is better.",
    "- **Evidence accuracy**: evidence items judged correct, over evidence items cited, summed across all threats (from each `evidenceCorrect` cell, e.g. 2/3).",
    "- **Cost**: total model spend for the run as recorded by the pipeline, at the model profile above, with every developer question skipped.",
    "- **All repos** pools the counts; it is not an average of the per-repo percentages.",
    "",
    EVAL_NOTES_MARKER,
    "",
  ].join("\n");
}

/** Everything below this line in docs/evaluation.md is hand-written and kept by score.ts. */
export const EVAL_NOTES_MARKER = "<!-- hand-written sections below are kept across runs of score.ts -->";

/** The generated report with the existing file's hand-written sections kept after the marker. Pure. */
export function mergeEvaluationReport(generated: string, existing: string | undefined): string {
  const at = existing?.indexOf(EVAL_NOTES_MARKER) ?? -1;
  const notes = at === -1 ? "" : existing!.slice(at + EVAL_NOTES_MARKER.length).replace(/^\n+/, "");
  const head = generated.slice(0, generated.indexOf(EVAL_NOTES_MARKER) + EVAL_NOTES_MARKER.length);
  return notes.trim() === "" ? `${head}\n` : `${head}\n\n${notes}`;
}

// ---------------------------------------------------------------------------
// run.ts: arguments and failure reporting
// ---------------------------------------------------------------------------

export type RunArgs = { names: string[]; timeoutMs: number; level: AnalysisLevel };

export const DEFAULT_LEVEL: AnalysisLevel = 2;

/**
 * Reads `[repo...] [--timeout <ms>] [--level <0-4>]`. The timeout defaults to `defaultMs` (the pipeline's
 * PIPELINE_TIMEOUT_MS) and is validated with the same rule try-pipeline.ts uses, before
 * any paid work starts. Any other --flag is rejected rather than silently read as a repo
 * name or ignored.
 */
export function parseRunArgs(
  argv: readonly string[],
  defaultMs: number,
  maxMs: number,
): { ok: true; value: RunArgs } | { ok: false; message: string } {
  const names: string[] = [];
  let raw: string | undefined;
  let rawLevel: string | undefined;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--timeout") {
      if (raw !== undefined) return { ok: false, message: "--timeout given more than once." };
      raw = argv[i + 1];
      if (raw === undefined || raw.startsWith("--")) return { ok: false, message: "--timeout needs a value in milliseconds." };
      i += 1;
    } else if (arg === "--level") {
      if (rawLevel !== undefined) return { ok: false, message: "--level given more than once." };
      rawLevel = argv[i + 1];
      if (rawLevel === undefined || rawLevel.startsWith("--")) return { ok: false, message: "--level needs a value from 0 to 4." };
      i += 1;
    } else if (arg.startsWith("--")) {
      return { ok: false, message: `unknown option ${arg}; usage: run.ts [repo...] [--timeout <ms>] [--level <0-4>]` };
    } else {
      names.push(arg);
    }
  }
  const level = AnalysisLevelSchema.safeParse(rawLevel === undefined ? DEFAULT_LEVEL : /^\d$/.test(rawLevel) ? Number(rawLevel) : NaN);
  if (!level.success) return { ok: false, message: `--level must be an integer from 0 to 4, got "${rawLevel}".` };
  if (raw === undefined) return { ok: true, value: { names, timeoutMs: defaultMs, level: level.data } };
  const value = Number(raw);
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(value) || value <= 0 || value > maxMs) {
    return {
      ok: false,
      message: `--timeout must be a positive integer number of milliseconds no greater than ${maxMs}, got "${raw}".`,
    };
  }
  return { ok: true, value: { names, timeoutMs: value, level: level.data } };
}

/** The order a successful job moves through; "failed" can replace any of them. */
export const STAGE_ORDER = [
  "queued",
  "loading_repo",
  "scanning",
  "mapping_architecture",
  "generating_threats",
  "awaiting_answers",
  "finalizing",
  "complete",
] as const satisfies readonly AnalysisStage[];

/** Position in STAGE_ORDER; -1 for "failed". */
function stageIndex(stage: AnalysisStage): number {
  return (STAGE_ORDER as readonly AnalysisStage[]).indexOf(stage);
}

/**
 * The last non-terminal stage a job was seen in. pipeline.ts's fail() overwrites
 * state.stage with "failed", so run.ts records every stage it observes here, both from
 * polling and from each awaited result. Stages only move forward, so a late or repeated
 * observation never moves it back.
 */
export class StageTracker {
  private seen: AnalysisStage = "queued";
  record(stage: AnalysisStage): void {
    if (stage === "failed") return;
    if (stageIndex(stage) > stageIndex(this.seen)) this.seen = stage;
  }
  get lastSeen(): AnalysisStage {
    return this.seen;
  }
}

/** The stage before `stage` in STAGE_ORDER: what had definitely finished when it failed. */
export function stageBefore(stage: AnalysisStage): AnalysisStage | null {
  const index = stageIndex(stage);
  return index > 0 ? STAGE_ORDER[index - 1] : null;
}

export type RunFailure = {
  repo: string;
  /** Last non-terminal stage observed before the job became "failed". */
  failedDuring: AnalysisStage;
  /** Which timed phase it failed in: runAnalysis, or resumeWithAnswers (fresh deadline). */
  phase: "analysis" | "resume";
  error?: { code: string; message: string };
  /** The pipeline's own ledger snapshot (fail() refreshes it), never an estimate. */
  cost: { calls: number; totalUsd: number };
  timeoutMs: number;
  elapsedMs: number;
};

/** Printable lines for a failed repo. Only the pipeline's safe error text is included. */
export function formatRunFailure(f: RunFailure): string[] {
  const before = stageBefore(f.failedDuring);
  return [
    `${f.repo}: FAILED ${f.error ? `[${f.error.code}] ${f.error.message}` : "without an error code"}`,
    `${f.repo}:   failed during: ${f.failedDuring} (last completed: ${before ?? "none"}; phase: ${f.phase})`,
    `${f.repo}:   recorded by pipeline: ${f.cost.calls} provider response(s), $${f.cost.totalUsd.toFixed(4)}`,
    `${f.repo}:   elapsed ${(f.elapsedMs / 1000).toFixed(1)}s of a ${(f.timeoutMs / 1000).toFixed(0)}s budget per phase`,
    `${f.repo}:   no result written`,
  ];
}

// ---------------------------------------------------------------------------
// Gap sheet: threats whose cited evidence is only control gaps (gapSheet.ts)
// ---------------------------------------------------------------------------

/** Evidence from a control-gap detector carries ruleId "gap:<kind>" (src/server/detect/gaps.ts). */
const GAP_RULE_PREFIX = "gap:";

export const GAP_COLUMNS = ["threatId", "title", "gapKinds", "files", "confidence", "visible", "gapLabel", "notes"] as const;
export type GapColumn = (typeof GAP_COLUMNS)[number];

/** predicted_correct: the control the gap says is missing really is missing. predicted_wrong: it is there. */
export const GAP_LABELS = ["predicted_correct", "predicted_wrong"] as const;
export type GapLabel = (typeof GAP_LABELS)[number];

const gapKindOf = (evidence: Evidence): string | undefined =>
  evidence.ruleId?.startsWith(GAP_RULE_PREFIX) ? evidence.ruleId.slice(GAP_RULE_PREFIX.length) : undefined;

/**
 * The evidence a threat cites when every item is a control gap, else null. A threat that
 * cites nothing is not gap-only, and neither is one that cites an id that does not resolve.
 */
export function gapOnlyEvidence(threat: Threat, evidenceById: ReadonlyMap<string, Evidence>): Evidence[] | null {
  if (threat.evidenceIds.length === 0) return null;
  const cited = threat.evidenceIds.map((id) => evidenceById.get(id));
  if (cited.some((e) => e === undefined || gapKindOf(e) === undefined)) return null;
  return cited as Evidence[];
}

export type GapSheetRow = {
  threatId: string;
  title: string;
  /** Distinct gap kinds the threat cites, sorted. */
  gapKinds: string[];
  /** Distinct "path:line" locations of the cited gaps, sorted. */
  files: string[];
  confidence: number;
  /** Shown on the dashboard: not below the HIDE_BELOW cutoff. */
  visible: boolean;
};

/** One row per gap-only threat, in the model's order. */
export function gapSheetRows(model: ThreatModel): GapSheetRow[] {
  const evidenceById = new Map(model.evidence.map((e) => [e.id, e]));
  const rows: GapSheetRow[] = [];
  for (const threat of model.threats) {
    const cited = gapOnlyEvidence(threat, evidenceById);
    if (!cited) continue;
    rows.push({
      threatId: threat.id,
      title: threat.title,
      gapKinds: [...new Set(cited.map((e) => gapKindOf(e) as string))].sort(),
      files: [...new Set(cited.map(describeEvidenceLocation))].sort(),
      confidence: threat.confidence,
      visible: !isHidden(threat.confidence),
    });
  }
  return rows;
}

/** The whole sheet, header first; gapLabel and notes are left empty for a person. */
export function buildGapSheet(model: ThreatModel): string {
  return toCsv([
    [...GAP_COLUMNS],
    ...gapSheetRows(model).map((r) => [
      r.threatId,
      r.title,
      r.gapKinds.join(";"),
      r.files.join(" | "),
      r.confidence.toFixed(2),
      r.visible ? "y" : "n",
      "", // gapLabel
      "", // notes
    ]),
  ]);
}

export type GapLabeled = { threatId: string; gapKinds: string[]; visible: boolean; label: GapLabel };

/**
 * Whether anyone has started labelling a gap sheet: at least one row has a gapLabel. A sheet
 * nobody has started is skipped by the scorer rather than refused, so a freshly generated
 * blank sheet never blocks ordinary scoring; a partially filled one is still refused.
 */
export function gapSheetStarted(csvText: string): boolean {
  const rows = parseCsv(csvText);
  const column = rows[0]?.map((h) => h.trim()).indexOf("gapLabel") ?? -1;
  return column !== -1 && rows.slice(1).some((row) => (row[column] ?? "").trim() !== "");
}

/**
 * Reads a filled gap sheet. Every row needs a gapLabel of predicted_correct or
 * predicted_wrong: a blank or unknown value refuses the whole sheet, so a half-labelled one
 * cannot skew the precision. Every problem is collected, not just the first.
 */
export function parseGapLabels(csvText: string): GapLabeled[] {
  const rows = parseCsv(csvText);
  if (rows.length === 0) throw new Error("gaps sheet is empty");
  const header = rows[0].map((h) => h.trim());
  const missing = GAP_COLUMNS.filter((c) => !header.includes(c));
  if (missing.length > 0) throw new Error(`gaps sheet is missing column(s): ${missing.join(", ")}`);
  const col = (row: string[], name: GapColumn) => (row[header.indexOf(name)] ?? "").trim();

  const problems: string[] = [];
  const out: GapLabeled[] = [];
  const seen = new Set<string>();
  let blank = 0;
  rows.slice(1).forEach((row, index) => {
    const threatId = col(row, "threatId");
    const where = `row ${index + 2} (${threatId || "no threatId"})`;
    if (!threatId) return void problems.push(`${where}: threatId is empty`);
    if (seen.has(threatId)) return void problems.push(`${where}: duplicate threatId`);
    seen.add(threatId);

    const gapKinds = [...new Set(col(row, "gapKinds").split(/[;,\s]+/).filter(Boolean))].sort();
    if (gapKinds.length === 0) problems.push(`${where}: gapKinds is empty`);
    const visibleRaw = col(row, "visible").toLowerCase();
    if (visibleRaw !== "y" && visibleRaw !== "n") problems.push(`${where}: visible must be y or n, got "${visibleRaw}"`);
    const label = col(row, "gapLabel").toLowerCase();
    if (label === "") {
      blank += 1;
      problems.push(`${where}: gapLabel is blank`);
    } else if (!(GAP_LABELS as readonly string[]).includes(label)) {
      problems.push(`${where}: gapLabel must be ${GAP_LABELS.join(" or ")}, got "${label}"`);
    } else if (gapKinds.length > 0 && (visibleRaw === "y" || visibleRaw === "n")) {
      out.push({ threatId, gapKinds, visible: visibleRaw === "y", label: label as GapLabel });
    }
  });
  if (rows.length === 1) problems.push("gaps sheet has no threat rows");
  if (problems.length > 0) {
    const summary = blank > 0 ? `${blank} of ${rows.length - 1} row(s) have no gapLabel` : `${problems.length} problem(s)`;
    throw new Error(`gaps sheet is not fully labeled (${summary}):\n  ${problems.join("\n  ")}`);
  }
  return out;
}

/**
 * Where a filled gap sheet disagrees with the saved result it was made from: a gap-only
 * threat missing from the sheet, a row for a threat that is not gap-only, or a kind or
 * visibility that no longer matches. The visible column is checked against the model's own
 * confidence, not trusted, so the visible-only precision cannot drift from the dashboard.
 */
export function gapSheetProblems(labels: readonly GapLabeled[], model: ThreatModel): string[] {
  const expected = new Map(gapSheetRows(model).map((r) => [r.threatId, r]));
  const problems: string[] = [];
  const inSheet = new Set(labels.map((l) => l.threatId));
  for (const id of expected.keys()) if (!inSheet.has(id)) problems.push(`${id} cites only gaps but is not in the sheet`);
  for (const label of labels) {
    const row = expected.get(label.threatId);
    if (!row) {
      problems.push(`${label.threatId} is not a gap-only threat of this result`);
      continue;
    }
    if (row.gapKinds.join(";") !== label.gapKinds.join(";")) problems.push(`${label.threatId}: gapKinds differ from the result (${row.gapKinds.join(";")})`);
    if (row.visible !== label.visible) problems.push(`${label.threatId}: visible is ${label.visible ? "y" : "n"} but the result says ${row.visible ? "y" : "n"}`);
  }
  return problems;
}

export type GapPrecision = {
  correct: number;
  wrong: number;
  /** correct + wrong: every row is labelled, so this is the number of rows. */
  n: number;
  /** correct / n; null when there are no rows. */
  precision: number | null;
};
export type GapKindTally = { kind: string; wrong: number; total: number };
export type GapMetrics = { overall: GapPrecision; visible: GapPrecision; wrongByKind: GapKindTally[] };

function precisionOf(labels: readonly GapLabeled[]): GapPrecision {
  const correct = labels.filter((l) => l.label === "predicted_correct").length;
  const n = labels.length;
  return { correct, wrong: n - correct, n, precision: ratio(correct, n) };
}

/**
 * gap_precision = predicted_correct / (predicted_correct + predicted_wrong), over every row
 * and over the visible rows only. predicted_wrong is tallied by gap kind; a threat that
 * cites several kinds counts once under each, so the kind tallies can exceed the row count.
 */
export function computeGapMetrics(labels: readonly GapLabeled[]): GapMetrics {
  const kinds = new Map<string, GapKindTally>();
  for (const label of labels) {
    for (const kind of label.gapKinds) {
      const tally = kinds.get(kind) ?? { kind, wrong: 0, total: 0 };
      tally.total += 1;
      if (label.label === "predicted_wrong") tally.wrong += 1;
      kinds.set(kind, tally);
    }
  }
  return {
    overall: precisionOf(labels),
    visible: precisionOf(labels.filter((l) => l.visible)),
    wrongByKind: [...kinds.values()].sort((a, b) => b.wrong - a.wrong || a.kind.localeCompare(b.kind)),
  };
}

// ---------------------------------------------------------------------------
// Recall by class (from the expected file)
// ---------------------------------------------------------------------------

export type ClassRow = { cls: string; expected: number; found: number; missed: number; missedIds: string[] };

/**
 * The classes an answer-key item belongs to, from its owasp2013 note: "A2/A3/A5" is three,
 * a trailing parenthetical is a note ("SSRF (tutorial ssrf.html)" is "SSRF"), and an item
 * with no note is "unclassified".
 */
export function classesOf(owasp2013: string | undefined): string[] {
  const parts = (owasp2013 ?? "")
    .replace(/\s*\(.*\)\s*$/, "")
    .split("/")
    .map((p) => p.trim())
    .filter(Boolean);
  return parts.length > 0 ? parts : ["unclassified"];
}

/** A1..A10 in numeric order, then any other class alphabetically. */
function classOrder(cls: string): [number, number, string] {
  const owasp = /^A(\d+)$/.exec(cls);
  return owasp ? [0, Number(owasp[1]), cls] : [1, 0, cls];
}

/**
 * Found and missed per class. `foundIds` must be the scorer's recalled set
 * (RepoMetrics.matched, built by recalledIds), so the table can never disagree with the
 * recall figure. An item in several classes counts in each.
 */
export function recallByClass(expected: ExpectedFile, foundIds: ReadonlySet<string>): ClassRow[] {
  const rows = new Map<string, ClassRow>();
  for (const threat of expected.expectedThreats) {
    for (const cls of classesOf(threat.owasp2013)) {
      const row = rows.get(cls) ?? { cls, expected: 0, found: 0, missed: 0, missedIds: [] };
      row.expected += 1;
      if (foundIds.has(threat.id)) row.found += 1;
      else {
        row.missed += 1;
        row.missedIds.push(threat.id);
      }
      rows.set(cls, row);
    }
  }
  return [...rows.values()].sort((a, b) => {
    const [ag, an, as] = classOrder(a.cls);
    const [bg, bn, bs] = classOrder(b.cls);
    return ag - bg || an - bn || as.localeCompare(bs);
  });
}

// ---------------------------------------------------------------------------
// Second labeler: sampling and agreement
// ---------------------------------------------------------------------------

export type Agreement = {
  n: number;
  agreed: number;
  /** agreed / n; null when n is 0. */
  agreement: number | null;
  /** Cohen's kappa; null when n is 0 or chance agreement is already 1 (nobody varied). */
  kappa: number | null;
};

/** Simple agreement and Cohen's kappa over paired categorical labels. */
export function agreementOf(pairs: readonly (readonly [string, string])[]): Agreement {
  const n = pairs.length;
  const agreed = pairs.filter(([a, b]) => a === b).length;
  const first = new Map<string, number>();
  const second = new Map<string, number>();
  for (const [a, b] of pairs) {
    first.set(a, (first.get(a) ?? 0) + 1);
    second.set(b, (second.get(b) ?? 0) + 1);
  }
  let chance = 0; // sum over categories of count_a * count_b, over n*n
  for (const [category, count] of first) chance += count * (second.get(category) ?? 0);
  const kappa = n === 0 || chance === n * n ? null : (agreed / n - chance / (n * n)) / (1 - chance / (n * n));
  return { n, agreed, agreement: ratio(agreed, n), kappa };
}

export type LabelerComparison = {
  n: number;
  /** supported (y/n): the label the unsupported rate and the sample are built on. */
  supported: Agreement;
  /**
   * False when the second sheet's matchesExpected column is entirely blank, meaning that
   * dimension was not labelled (the labeller never saw the answer key). matchesAny and
   * matchesExact are then null: a blank must not be read as "matches nothing".
   */
  matchesLabelled: boolean;
  /** Whether the row matches any expected item, or none; null when not labelled. */
  matchesAny: Agreement | null;
  /** Exact match of the whole matchesExpected set; simple agreement only; null when not labelled. */
  matchesExact: Agreement | null;
  /** Exact match of the evidenceCorrect cell (correct/total); simple agreement only. */
  evidence: Agreement;
  /** Threat ids whose supported label differs, for adjudication. */
  supportedDisagreements: string[];
};

/** Problems that stop a second sheet being compared with the primary one. */
export function secondSheetProblems(primary: readonly LabeledThreat[], second: readonly LabeledThreat[]): string[] {
  const known = new Set(primary.map((l) => l.threatId));
  const problems = second.filter((l) => !known.has(l.threatId)).map((l) => `${l.threatId} is not a threat in the primary sheet`);
  if (second.length === 0) problems.push("the second sheet has no rows");
  return problems;
}

/** A second labeller's cell meaning "this threat matches no expected item", as opposed to a blank. */
export const NO_MATCH_MARKER = "none";

export type SecondSheet = {
  labels: LabeledThreat[];
  /** False when matchesExpected is blank on every row: not labelled, not "matches nothing". */
  matchesLabelled: boolean;
};

/**
 * Reads a second labeller's sheet. It is parseLabels with one difference in how the
 * matchesExpected column is read, because a second labeller may never have opened the answer
 * key and a blank cell must not silently mean "matches nothing":
 *  - blank on every row: that dimension was not labelled (matchesLabelled false);
 *  - filled on every row: labelled, and "none" marks a row that matches no expected item;
 *  - filled on some rows and blank on others: refused, listing the blank rows.
 * Every other column, and every other problem, is handled exactly as parseLabels does. The
 * primary sheet is unaffected: there a blank cell still means "matches nothing".
 */
export function parseSecondLabels(csvText: string, expectedIds: ReadonlySet<string>): SecondSheet {
  const rows = parseCsv(csvText);
  const header = rows[0]?.map((h) => h.trim()) ?? [];
  const idCol = header.indexOf("threatId");
  const matchCol = header.indexOf("matchesExpected");
  if (rows.length < 2 || idCol === -1 || matchCol === -1) {
    // Missing columns and an empty sheet get parseLabels' own message.
    return { labels: parseLabels(csvText, expectedIds), matchesLabelled: true };
  }
  const isBlank = (row: string[]) => (row[matchCol] ?? "").trim() === "";
  const data = rows.slice(1);
  const blank = data.filter(isBlank);
  const matchesLabelled = blank.length < data.length;

  if (matchesLabelled && blank.length > 0) {
    const ids = blank.map((row) => (row[idCol] ?? "").trim() || "no threatId");
    throw new Error(
      `second sheet is not fully labeled: matchesExpected is filled on ${data.length - blank.length} of ${data.length} rows and blank on ${ids.join(", ")}. ` +
        `Fill every row (write "${NO_MATCH_MARKER}" for a threat that matches no expected item) or leave the whole column blank.`,
    );
  }
  if (!matchesLabelled) return { labels: parseLabels(csvText, expectedIds), matchesLabelled: false };

  const explicit = data.map((row) => row.map((cell, i) => (i === matchCol && cell.trim().toLowerCase() === NO_MATCH_MARKER ? "" : cell)));
  return { labels: parseLabels(toCsv([rows[0], ...explicit]), expectedIds), matchesLabelled: true };
}

/**
 * Compares a second person's labels with the primary ones, on the threats both labelled.
 * With `matchesLabelled` false the match dimensions are left out (null), not scored as
 * agreement or disagreement; supported and evidenceCorrect are compared as usual.
 */
export function compareLabelers(
  primary: readonly LabeledThreat[],
  second: readonly LabeledThreat[],
  { matchesLabelled = true }: { matchesLabelled?: boolean } = {},
): LabelerComparison {
  const byId = new Map(primary.map((l) => [l.threatId, l]));
  const pairs = second.flatMap((s) => {
    const p = byId.get(s.threatId);
    return p ? [{ p, s }] : [];
  });
  const set = (l: LabeledThreat) => [...l.matches].sort().join(";");
  const yn = (l: LabeledThreat) => (l.supported ? "y" : "n");
  const cell = (l: LabeledThreat) => `${l.evidenceCorrect}/${l.evidenceTotal}`;
  return {
    n: pairs.length,
    supported: agreementOf(pairs.map(({ p, s }) => [yn(p), yn(s)])),
    matchesLabelled,
    matchesAny: matchesLabelled
      ? agreementOf(pairs.map(({ p, s }) => [p.matches.length > 0 ? "match" : "none", s.matches.length > 0 ? "match" : "none"]))
      : null,
    matchesExact: matchesLabelled ? { ...agreementOf(pairs.map(({ p, s }) => [set(p), set(s)])), kappa: null } : null,
    evidence: { ...agreementOf(pairs.map(({ p, s }) => [cell(p), cell(s)])), kappa: null },
    supportedDisagreements: pairs.filter(({ p, s }) => p.supported !== s.supported).map(({ p }) => p.threatId),
  };
}

export const SECOND_SAMPLE_SIZE = 20;
/** Fixed, so the same primary sheet always yields the same sample. */
export const SECOND_SAMPLE_SEED = 20260925;

/** mulberry32: a small seeded generator, so a sample does not depend on Math.random. */
export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** The label values a sample is stratified on: supported (y/n) crossed with matches-an-expected-item. */
export function strataKey(label: LabeledThreat): string {
  return `${label.supported ? "supported" : "unsupported"}/${label.matches.length > 0 ? "match" : "nomatch"}`;
}

/**
 * How many of `size` each stratum gets: proportional to its share, at least one each so a
 * rare stratum is still checked, and exactly `size` in total (largest remainder, ties broken
 * by stratum name). Throws when there are more strata than `size`.
 */
export function allocateStrata(counts: ReadonlyMap<string, number>, size: number): Map<string, number> {
  const keys = [...counts.keys()].sort();
  const total = keys.reduce((sum, key) => sum + (counts.get(key) as number), 0);
  if (size > total) throw new Error(`cannot sample ${size} from ${total} rows`);
  if (size < keys.length) throw new Error(`cannot sample ${size}: there are ${keys.length} strata`);
  const ideal = new Map(keys.map((key) => [key, (size * (counts.get(key) as number)) / total]));
  const quota = new Map(keys.map((key) => [key, Math.min(counts.get(key) as number, Math.max(1, Math.floor(ideal.get(key) as number)))]));
  const sum = () => keys.reduce((s, key) => s + (quota.get(key) as number), 0);
  while (sum() < size) {
    const key = keys
      .filter((k) => (quota.get(k) as number) < (counts.get(k) as number))
      .sort((a, b) => (ideal.get(b) as number) - (quota.get(b) as number) - ((ideal.get(a) as number) - (quota.get(a) as number)) || a.localeCompare(b))[0];
    quota.set(key, (quota.get(key) as number) + 1);
  }
  while (sum() > size) {
    const key = keys
      .filter((k) => (quota.get(k) as number) > 1)
      .sort((a, b) => (quota.get(b) as number) - (ideal.get(b) as number) - ((quota.get(a) as number) - (ideal.get(a) as number)) || a.localeCompare(b))[0];
    quota.set(key, (quota.get(key) as number) - 1);
  }
  return quota;
}

const byThreatNumber = (a: string, b: string): number => a.localeCompare(b, "en", { numeric: true });

/** `size` threat ids, stratified on strataKey and drawn with a seeded shuffle, in threat-id order. */
export function stratifiedSample(labels: readonly LabeledThreat[], size: number, seed: number): string[] {
  const groups = new Map<string, string[]>();
  for (const label of labels) groups.set(strataKey(label), [...(groups.get(strataKey(label)) ?? []), label.threatId]);
  const quota = allocateStrata(new Map([...groups].map(([key, ids]) => [key, ids.length])), size);
  const random = seededRandom(seed);
  const picked: string[] = [];
  for (const key of [...groups.keys()].sort()) {
    const ids = [...(groups.get(key) as string[])].sort(byThreatNumber);
    for (let i = ids.length - 1; i > 0; i--) {
      const j = Math.floor(random() * (i + 1));
      [ids[i], ids[j]] = [ids[j], ids[i]];
    }
    picked.push(...ids.slice(0, quota.get(key) as number));
  }
  return picked.sort(byThreatNumber);
}

/** The columns a person fills in by hand: the labels and the notes. */
const HAND_COLUMNS: readonly LabelColumn[] = ["matchesExpected", "supported", "evidenceCorrect", "notes"];

/**
 * A copy of the primary sheet restricted to `ids`, with every hand-filled cell emptied so the
 * second labeler sees nothing the first decided. The columns stay, so the filled copy parses
 * with parseLabels.
 */
export function blankSecondSheet(primaryCsv: string, ids: readonly string[]): string {
  const rows = parseCsv(primaryCsv);
  const header = rows[0].map((h) => h.trim());
  const idCol = header.indexOf("threatId");
  const blank = new Set(HAND_COLUMNS.map((c) => header.indexOf(c)));
  const wanted = new Set(ids);
  const kept = rows.slice(1).filter((row) => wanted.has((row[idCol] ?? "").trim()));
  return toCsv([rows[0], ...kept.map((row) => rows[0].map((_, i) => (blank.has(i) ? "" : (row[i] ?? ""))))]);
}

// ---------------------------------------------------------------------------
// Golden demo (scripts/export-golden-demo.ts)
// ---------------------------------------------------------------------------

/** How many dashboard-visible threats rest on evidence and how many on assumptions. */
export function visibleBases(model: ThreatModel): { evidenceBacked: number; assumptionDependent: number } {
  const visible = model.threats.filter((t) => !isHidden(t.confidence));
  return {
    evidenceBacked: visible.filter((t) => t.basis === "evidence_backed").length,
    assumptionDependent: visible.filter((t) => t.basis === "assumption_dependent").length,
  };
}

/** Why a model is not fit to be the golden demo; empty when it is. */
export function goldenProblems(model: ThreatModel): string[] {
  const { evidenceBacked, assumptionDependent } = visibleBases(model);
  return [
    ...(evidenceBacked === 0 ? ["no visible evidence_backed threat"] : []),
    ...(assumptionDependent === 0 ? ["no visible assumption_dependent threat"] : []),
  ];
}

// ---------------------------------------------------------------------------
// docs/evaluation.md: the extra sections
// ---------------------------------------------------------------------------

export type RepoExtras = { classes?: ClassRow[]; gaps?: GapMetrics; labelers?: LabelerComparison };

const rate = (value: number | null): string => pct(value);
const kappaText = (value: number | null): string => (value === null ? "n/a (no variation)" : value.toFixed(2));

function agreementLine(name: string, a: Agreement, withKappa: boolean): string {
  return `- **${name}**: ${a.agreed}/${a.n} agree (${rate(a.agreement)})${withKappa ? `, Cohen's kappa ${kappaText(a.kappa)}` : ""}`;
}

/** The per-class, gap-precision and second-labeler sections for one repo; empty when it has none. */
export function renderExtras(repo: string, extras: RepoExtras | undefined): string[] {
  if (!extras) return [];
  const out: string[] = [];
  if (extras.classes && extras.classes.length > 0) {
    out.push(
      `## Recall by class: ${repo}`,
      "",
      "Classes come from the answer key's `owasp2013` note; an item in several classes counts in each. Found uses the same rule as the recall column above: a supported row must match the item.",
      "",
      "| Class | Expected | Found | Missed | Missed ids |",
      "| --- | ---: | ---: | ---: | --- |",
      ...extras.classes.map((c) => `| ${c.cls} | ${c.expected} | ${c.found} | ${c.missed} | ${c.missedIds.join(", ") || "none"} |`),
      "",
    );
  }
  if (extras.gaps) {
    const { overall, visible, wrongByKind } = extras.gaps;
    const row = (label: string, g: GapPrecision) => `| ${label} | ${g.n} | ${g.correct} | ${g.wrong} | ${rate(g.precision)} |`;
    out.push(
      `## Gap precision: ${repo}`,
      "",
      "Threats whose cited evidence is only control gaps, labelled by a person as predicted_correct (the control really is missing) or predicted_wrong. **gap_precision** = predicted_correct / (predicted_correct + predicted_wrong). Visible means confidence at or above the 0.25 dashboard cutoff.",
      "",
      "| Threats | n | predicted_correct | predicted_wrong | Gap precision |",
      "| --- | ---: | ---: | ---: | ---: |",
      row("All", overall),
      row("Visible only", visible),
      "",
      "predicted_wrong by gap kind (a threat citing several kinds counts under each):",
      "",
      "| Gap kind | predicted_wrong | Threats |",
      "| --- | ---: | ---: |",
      ...wrongByKind.map((k) => `| ${k.kind} | ${k.wrong} | ${k.total} |`),
      "",
    );
  }
  if (extras.labelers) {
    const l = extras.labelers;
    out.push(
      `## Second labeler agreement: ${repo}`,
      "",
      `A second labeller, a separate model session rather than a person, labelled ${l.n} threats from the primary sheet without seeing its labels. That is a weaker check than a second human. Agreement is the share of threats with the same label.`,
      "",
      agreementLine("supported (y/n)", l.supported, true),
      ...(l.matchesAny && l.matchesExact
        ? [
            agreementLine("matches any expected item (yes/no)", l.matchesAny, true),
            agreementLine("matchesExpected, exact set", l.matchesExact, false),
          ]
        : ["- **matchesExpected**: not labelled by the second labeller (the column is blank on every row, not \"matches nothing\"); match agreement and kappa are omitted"]),
      agreementLine("evidenceCorrect, exact cell", l.evidence, false),
      `- **Supported disagreements**: ${l.supportedDisagreements.join(", ") || "none"}`,
      "",
    );
  }
  return out;
}
