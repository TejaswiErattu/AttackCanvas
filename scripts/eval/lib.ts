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
import { ThreatModelSchema, type AnalysisStage, type Evidence, type Threat, type ThreatModel } from "@/shared/schema";

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
    expectedThreats: z.array(z.object({ id: ExpectedId, description: z.string().min(1) })).min(1),
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
  cost: z.object({ calls: z.number().int().min(0), totalUsd: z.number().min(0) }),
  threatModel: ThreatModelSchema,
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

export function computeRepoMetrics(
  repo: string,
  labels: readonly LabeledThreat[],
  expected: ExpectedFile,
  cost: { totalUsd: number; calls: number },
): RepoMetrics {
  const matchedSet = new Set(labels.flatMap((l) => l.matches));
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
): string {
  const rows = perRepo.length > 1 ? [...perRepo, combineMetrics(perRepo)] : [...perRepo];
  const missedSections = perRepo
    .filter((m) => m.missed.length > 0)
    .map((m) => `- **${m.repo}**: ${m.missed.join(", ")}`);
  const guided = perRepo.filter((m) => m.mode === "guided").map((m) => m.repo);
  return [
    "# Evaluation",
    "",
    "<!-- Generated by scripts/eval/score.ts from hand-labeled sheets. Do not edit by hand. -->",
    "",
    `Generated ${generatedAt}. Model profile: ${profiles.join(", ")}. Every label behind these numbers was entered by a person; no model judged any output.`,
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
    "## Definitions",
    "",
    "- **Recall**: expected threats matched by at least one generated threat, over expected threats. A generated threat is matched when its `matchesExpected` cell lists the expected id; a blank cell means it matches none.",
    "- **Unsupported**: generated threats labeled `supported = n` (the cited code does not support the claim), over all generated threats. Lower is better.",
    "- **Evidence accuracy**: evidence items judged correct, over evidence items cited, summed across all threats (from each `evidenceCorrect` cell, e.g. 2/3).",
    "- **Cost**: total model spend for the run as recorded by the pipeline, at the model profile above, with every developer question skipped.",
    "- **All repos** pools the counts; it is not an average of the per-repo percentages.",
    "",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// run.ts: arguments and failure reporting
// ---------------------------------------------------------------------------

export type RunArgs = { names: string[]; timeoutMs: number };

/**
 * Reads `[repo...] [--timeout <ms>]`. The timeout defaults to `defaultMs` (the pipeline's
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
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--timeout") {
      if (raw !== undefined) return { ok: false, message: "--timeout given more than once." };
      raw = argv[i + 1];
      if (raw === undefined || raw.startsWith("--")) return { ok: false, message: "--timeout needs a value in milliseconds." };
      i += 1;
    } else if (arg.startsWith("--")) {
      return { ok: false, message: `unknown option ${arg}; usage: run.ts [repo...] [--timeout <ms>]` };
    } else {
      names.push(arg);
    }
  }
  if (raw === undefined) return { ok: true, value: { names, timeoutMs: defaultMs } };
  const value = Number(raw);
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(value) || value <= 0 || value > maxMs) {
    return {
      ok: false,
      message: `--timeout must be a positive integer number of milliseconds no greater than ${maxMs}, got "${raw}".`,
    };
  }
  return { ok: true, value: { names, timeoutMs: value } };
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
