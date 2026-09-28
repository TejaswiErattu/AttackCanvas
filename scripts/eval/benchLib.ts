/**
 * The seeded bench (scripts/eval/bench.ts): score the deterministic detectors, and Semgrep
 * when it is installed, against hand-written labels for the three seeded repositories under
 * tests/fixtures/seeded/. No model is called anywhere on this path, and nothing here writes
 * to disk: bench.ts prints and writes, tests/bench.test.ts gates on the numbers.
 *
 * Each seeded repository has an expected.yaml listing planted issues (which should be
 * found) and present-but-tricky controls (which must not produce a gap). Matching is by file
 * and kind: a finding matches an issue when both sit in the same file and the finding's
 * kind (a gap kind, or a Semgrep rule id) is one the issue names. Line numbers are part of
 * the labels so a person can check them with grep (every planted item carries a
 * `SEEDED:<id>` comment), and the marker check below keeps them honest, but they are not
 * used for matching: a route-scoped gap anchors at the route, a Semgrep finding at the
 * statement, and both are the same planted issue.
 */

import { createHash } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import { parse as parseYaml } from "yaml";
import { runDetectors } from "@/server/detect";
import type { ControlGap, GapKind, GapScope } from "@/server/detect/types";
import { FIXTURE_OWNER, FIXTURE_ROOT, loadFixtureRepo } from "@/server/ingest/fixtureLoader";
import { modelBoundFiles, type LoadedFile } from "@/server/ingest/loader";
import type { RawSemgrepFinding, RedactedFile } from "@/server/mcp/semgrepClient";
import { RULE_IDS } from "@/server/mcp/semgrepRules";
import { normalizeSemgrep } from "@/server/scanners/semgrep";
import { redact } from "@/server/security/redactor";
import { Owasp2025Schema, type Evidence, type Owasp2025 } from "@/shared/schema";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Where the seeded repositories live; loadFixtureRepo's `root`. */
export const SEEDED_ROOT = join(FIXTURE_ROOT, "seeded");
export const SEEDED_REPOS = ["seeded-express", "seeded-next", "seeded-monorepo"] as const;

/** The label file inside each seeded repository. Never shown to a detector. */
export const EXPECTED_FILE = "expected.yaml";

/** An issue's SEEDED marker sits on its line or at most this many lines above it. */
export const MARKER_WINDOW = 5;

/**
 * The certainty at which the product asserts a gap rather than asking about it. A copy of
 * GAP_ASSERT_CERTAINTY (src/server/analysis/architecture.ts), kept here so the bench does
 * not import the model-calling module; tests/benchLib.test.ts checks the two agree.
 */
export const ASSERTED_CERTAINTY = 0.7;

/** Every GapKind, checked for completeness by the Record type. */
const GAP_KIND_SET: Record<GapKind, true> = {
  authz_missing: true,
  authn_missing: true,
  rate_limit_missing: true,
  csrf_missing: true,
  security_headers_missing: true,
  input_validation_missing: true,
  transport_insecure: true,
  password_storage_weak: true,
  logging_missing: true,
  error_handling_gap: true,
  cors_permissive: true,
  supply_chain_integrity: true,
  client_secret_storage: true,
};
const GAP_KINDS = Object.keys(GAP_KIND_SET) as [GapKind, ...GapKind[]];

export const CONTROL_TYPES = [
  "app-level middleware",
  "framework default",
  "barrel-imported guard",
  "cross-package guard",
] as const;

// ---------------------------------------------------------------------------
// expected.yaml
// ---------------------------------------------------------------------------

const Id = z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, "lowercase letters, digits and single hyphens");
const RepoPath = z.string().min(1).refine((p) => !p.startsWith("/") && !p.split("/").includes(".."), "a repository-relative path");

const IssueSchema = z
  .object({
    id: Id,
    class: z.string().min(1),
    owasp: Owasp2025Schema,
    file: RepoPath,
    line: z.number().int().min(1),
    gapKind: z.enum(GAP_KINDS).optional(),
    ruleId: z.enum(RULE_IDS as unknown as [string, ...string[]]).optional(),
  })
  .strict()
  .refine((issue) => issue.gapKind !== undefined || issue.ruleId !== undefined, "needs a gapKind or a ruleId");

const ControlSchema = z
  .object({
    id: Id,
    gapKind: z.enum(GAP_KINDS),
    file: RepoPath,
    how: z.string().min(1),
    type: z.enum(CONTROL_TYPES),
    review: z.string().optional(),
  })
  .strict();

export const ExpectedRepoSchema = z
  .object({
    repo: z.string().min(1),
    issues: z.array(IssueSchema).min(1),
    controls: z.array(ControlSchema),
  })
  .strict()
  .superRefine((file, ctx) => {
    const seen = new Set<string>();
    for (const item of [...file.issues, ...file.controls]) {
      if (seen.has(item.id)) ctx.addIssue({ code: "custom", message: `duplicate id "${item.id}"` });
      seen.add(item.id);
    }
  });
export type ExpectedRepo = z.infer<typeof ExpectedRepoSchema>;
export type ExpectedIssue = ExpectedRepo["issues"][number];
export type ExpectedControl = ExpectedRepo["controls"][number];

export function parseExpected(text: string, label: string): ExpectedRepo {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch {
    throw new Error(`${label}: not valid YAML`);
  }
  const result = ExpectedRepoSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
    throw new Error(`${label}: ${issues.join("; ")}`);
  }
  return result.data;
}

// ---------------------------------------------------------------------------
// SEEDED markers
// ---------------------------------------------------------------------------

const MARKER = /SEEDED:([a-z0-9]+(?:-[a-z0-9]+)*)/g;

/**
 * Problems with the labels, empty when they are sound: an issue whose marker is not on
 * its line or within MARKER_WINDOW lines above, a control whose marker is in no file, and
 * a marker that names no label.
 */
export function checkMarkers(
  files: readonly { path: string; content: string }[],
  expected: ExpectedRepo,
): string[] {
  const problems: string[] = [];
  const byPath = new Map(files.map((file) => [file.path, file.content]));

  for (const issue of expected.issues) {
    const content = byPath.get(issue.file);
    if (content === undefined) {
      problems.push(`${issue.id}: file ${issue.file} was not loaded`);
      continue;
    }
    const lines = content.split("\n");
    if (issue.line > lines.length) {
      problems.push(`${issue.id}: line ${issue.line} is past the end of ${issue.file}`);
      continue;
    }
    const window = lines.slice(Math.max(0, issue.line - 1 - MARKER_WINDOW), issue.line);
    if (!window.some((line) => line.includes(`SEEDED:${issue.id}`) && endsMarker(line, issue.id))) {
      problems.push(`${issue.id}: no SEEDED:${issue.id} marker at ${issue.file}:${issue.line} or the ${MARKER_WINDOW} lines above`);
    }
  }

  const everywhere = new Set<string>();
  for (const { content } of files) {
    for (const match of content.matchAll(MARKER)) everywhere.add(match[1]);
  }
  for (const control of expected.controls) {
    if (!everywhere.has(control.id)) problems.push(`${control.id}: no SEEDED:${control.id} marker in any file`);
  }
  const labelled = new Set([...expected.issues, ...expected.controls].map((item) => item.id));
  for (const id of [...everywhere].sort()) {
    if (!labelled.has(id)) problems.push(`SEEDED:${id} marks nothing in expected.yaml`);
  }
  return problems;
}

/** The marker is the whole id, not a prefix of a longer one. */
function endsMarker(line: string, id: string): boolean {
  return [...line.matchAll(MARKER)].some((match) => match[1] === id);
}

// ---------------------------------------------------------------------------
// Findings and matching
// ---------------------------------------------------------------------------

export type Finding = {
  source: "gap" | "semgrep";
  /** A GapKind for a gap, a rule id for Semgrep. */
  kind: string;
  file: string;
  line: number;
  scope?: GapScope;
  certainty?: number;
};

const compareFindings = (a: Finding, b: Finding): number =>
  a.file.localeCompare(b.file) ||
  a.line - b.line ||
  a.source.localeCompare(b.source) ||
  a.kind.localeCompare(b.kind);

/** Gaps and Semgrep evidence as one sorted list. */
export function toFindings(gaps: readonly ControlGap[], semgrep: readonly Evidence[]): Finding[] {
  return [
    ...gaps.map(
      (gap): Finding => ({
        source: "gap",
        kind: gap.kind,
        file: gap.file,
        line: gap.line,
        scope: gap.scope,
        certainty: gap.certainty,
      }),
    ),
    ...semgrep.map(
      (evidence): Finding => ({
        source: "semgrep",
        kind: evidence.ruleId ?? "unknown",
        file: evidence.filePath ?? "",
        line: evidence.lineStart ?? 0,
      }),
    ),
  ].sort(compareFindings);
}

export type IssueStatus = "TP" | "FN" | "skipped";

export type IssueResult = {
  id: string;
  owasp: Owasp2025;
  file: string;
  status: IssueStatus;
  /** "gap:<kind>@<line>" or "semgrep:<rule>@<line>" for each finding that matched. */
  matchedBy: string[];
};

export type ControlResult = {
  id: string;
  gapKind: GapKind;
  type: ExpectedControl["type"];
  file: string;
  falseGap: boolean;
  /** Falsified by a gap at or above ASSERTED_CERTAINTY. */
  asserted: boolean;
  gaps: string[];
};

export type ScoredFinding = Finding & {
  /** Issue ids this finding matches; empty means it is a false positive. */
  matches: string[];
  /** Matches only issues an earlier finding already matched. */
  duplicate: boolean;
  /** Control ids this gap falsifies. */
  falsifies: string[];
};

export type Counts = {
  tp: number;
  fp: number;
  fn: number;
  skipped: number;
  duplicates: number;
  /** TP / (TP + FP); null when both are 0. */
  precision: number | null;
  /** TP / (TP + FN); null when both are 0. */
  recall: number | null;
  controls: number;
  falseGaps: number;
  /** falseGaps / controls; null when there are no controls. */
  falseGapRate: number | null;
  assertedFalseGaps: number;
  assertedFalseGapRate: number | null;
};

export type RepoScore = {
  repo: string;
  issues: IssueResult[];
  controls: ControlResult[];
  findings: ScoredFinding[];
  counts: Counts;
};

const ratio = (num: number, den: number): number | null => (den === 0 ? null : num / den);
const findingKey = (f: Finding): string => `${f.source}:${f.kind}@${f.line}`;

/** The kinds an issue can be matched by in this mode. Empty means it is skipped. */
function kindsFor(issue: ExpectedIssue, semgrep: boolean): string[] {
  return [issue.gapKind, semgrep ? issue.ruleId : undefined].filter(
    (kind): kind is string => kind !== undefined,
  );
}

/**
 * A control is contradicted by a gap of its kind in its own file, or by a gap of its kind
 * that claims the whole repository lacks the control (scope "repository"), wherever that
 * gap is anchored.
 */
function falsifies(finding: Finding, control: ExpectedControl): boolean {
  return (
    finding.source === "gap" &&
    finding.kind === control.gapKind &&
    (finding.file === control.file || finding.scope === "repository")
  );
}

export function countsOf(
  issues: readonly IssueResult[],
  controls: readonly ControlResult[],
  findings: readonly ScoredFinding[],
): Counts {
  const tp = issues.filter((i) => i.status === "TP").length;
  const fn = issues.filter((i) => i.status === "FN").length;
  const fp = findings.filter((f) => f.matches.length === 0).length;
  const falseGaps = controls.filter((c) => c.falseGap).length;
  const assertedFalseGaps = controls.filter((c) => c.asserted).length;
  return {
    tp,
    fp,
    fn,
    skipped: issues.filter((i) => i.status === "skipped").length,
    duplicates: findings.filter((f) => f.duplicate).length,
    precision: ratio(tp, tp + fp),
    recall: ratio(tp, tp + fn),
    controls: controls.length,
    falseGaps,
    falseGapRate: ratio(falseGaps, controls.length),
    assertedFalseGaps,
    assertedFalseGapRate: ratio(assertedFalseGaps, controls.length),
  };
}

/**
 * Scores one repository. With `semgrep` false, an issue labelled only by a rule id is
 * "skipped": it is left out of every count, not reported as missed.
 */
export function scoreRepo(
  expected: ExpectedRepo,
  findings: readonly Finding[],
  options: { semgrep: boolean },
): RepoScore {
  const matchedIssues = new Set<string>();
  const scored: ScoredFinding[] = [...findings].sort(compareFindings).map((finding) => {
    const matches = expected.issues
      .filter(
        (issue) =>
          issue.file === finding.file && kindsFor(issue, options.semgrep).includes(finding.kind),
      )
      .map((issue) => issue.id);
    const duplicate = matches.length > 0 && matches.every((id) => matchedIssues.has(id));
    for (const id of matches) matchedIssues.add(id);
    return {
      ...finding,
      matches,
      duplicate,
      falsifies: expected.controls.filter((c) => falsifies(finding, c)).map((c) => c.id),
    };
  });

  const issues: IssueResult[] = expected.issues.map((issue) => {
    const matchedBy = scored.filter((f) => f.matches.includes(issue.id)).map(findingKey);
    const status: IssueStatus =
      kindsFor(issue, options.semgrep).length === 0 ? "skipped" : matchedBy.length > 0 ? "TP" : "FN";
    return { id: issue.id, owasp: issue.owasp, file: issue.file, status, matchedBy };
  });

  const controls: ControlResult[] = expected.controls.map((control) => {
    const against = scored.filter((f) => f.falsifies.includes(control.id));
    return {
      id: control.id,
      gapKind: control.gapKind,
      type: control.type,
      file: control.file,
      falseGap: against.length > 0,
      asserted: against.some((f) => (f.certainty ?? 0) >= ASSERTED_CERTAINTY),
      gaps: against.map((f) => `${f.file}:${f.line} certainty ${f.certainty}`),
    };
  });

  return { repo: expected.repo, issues, controls, findings: scored, counts: countsOf(issues, controls, scored) };
}

/** Pooled counts across repositories (sums, not an average of rates). */
export function totalCounts(repos: readonly RepoScore[]): Counts {
  return countsOf(
    repos.flatMap((r) => r.issues),
    repos.flatMap((r) => r.controls),
    repos.flatMap((r) => r.findings),
  );
}

export type OwaspRow = { owasp: Owasp2025; planted: number; detected: number; missed: number; skipped: number };

export function perOwasp(repos: readonly RepoScore[]): OwaspRow[] {
  const rows = new Map<Owasp2025, OwaspRow>();
  for (const issue of repos.flatMap((r) => r.issues)) {
    const row = rows.get(issue.owasp) ?? { owasp: issue.owasp, planted: 0, detected: 0, missed: 0, skipped: 0 };
    row.planted += 1;
    if (issue.status === "TP") row.detected += 1;
    else if (issue.status === "FN") row.missed += 1;
    else row.skipped += 1;
    rows.set(issue.owasp, row);
  }
  return [...rows.values()].sort((a, b) => a.owasp.localeCompare(b.owasp));
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

export type BenchMode = "detectors" | "detectors+semgrep";

export type BenchRun = {
  mode: BenchMode;
  repos: RepoScore[];
  total: Counts;
  perOwasp: OwaspRow[];
};

export type BenchResult = {
  run: BenchRun;
  /** sha256 of each run's serialised output. */
  hashes: string[];
  deterministic: boolean;
};

export type Scan = (files: RedactedFile[]) => Promise<RawSemgrepFinding[]>;

/** Splits the label file off the loaded repository; the detectors never see it. */
export function withoutExpected(files: readonly LoadedFile[]): { files: LoadedFile[]; expected: string } {
  const label = files.find((file) => file.path === EXPECTED_FILE);
  if (!label) throw new Error(`${EXPECTED_FILE} was not loaded`);
  return { files: files.filter((file) => file !== label), expected: label.content };
}

async function runRepo(name: string, scan: Scan | undefined): Promise<RepoScore> {
  const loaded = await loadFixtureRepo(FIXTURE_OWNER, name, undefined, SEEDED_ROOT);
  const { files, expected: text } = withoutExpected(loaded.files);
  const expected = parseExpected(text, `${name}/${EXPECTED_FILE}`);
  if (expected.repo !== name) throw new Error(`${name}/${EXPECTED_FILE}: repo is "${expected.repo}"`);
  const problems = checkMarkers(files, expected);
  if (problems.length > 0) throw new Error(`${name}: labels do not match the code:\n  ${problems.join("\n  ")}`);

  const detected = runDetectors(files);
  let semgrep: Evidence[] = [];
  if (scan) {
    // The pipeline's own sequence (src/server/analysis/pipeline.ts): lockfiles never go to
    // Semgrep, and what does is redacted first.
    const redacted = modelBoundFiles(files).map((f) => ({ path: f.path, content: redact(f.content, f.path).content }));
    semgrep = normalizeSemgrep(await scan(redacted));
  }
  return scoreRepo(expected, toFindings(detected.gaps, semgrep), { semgrep: scan !== undefined });
}

export async function runOnce(scan: Scan | undefined): Promise<BenchRun> {
  const repos: RepoScore[] = [];
  for (const name of SEEDED_REPOS) repos.push(await runRepo(name, scan));
  return {
    mode: scan ? "detectors+semgrep" : "detectors",
    repos,
    total: totalCounts(repos),
    perOwasp: perOwasp(repos),
  };
}

export const serializeRun = (run: BenchRun): string => `${JSON.stringify(run, null, 2)}\n`;
const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

/**
 * Runs the whole bench `runs` times, each from a fresh load, and reports whether the
 * serialised outputs are byte-identical. Pass `scan` to include Semgrep.
 */
export async function runBench(options: { scan?: Scan; runs?: number } = {}): Promise<BenchResult> {
  const outputs: string[] = [];
  let first: BenchRun | undefined;
  for (let i = 0; i < (options.runs ?? 3); i++) {
    const run = await runOnce(options.scan);
    first ??= run;
    outputs.push(serializeRun(run));
  }
  const hashes = outputs.map(sha256);
  return { run: first!, hashes, deterministic: new Set(outputs).size === 1 };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

export const NOTES_MARKER = "<!-- hand-written notes below are kept across runs -->";

const pct = (value: number | null): string => (value === null ? "n/a" : `${(value * 100).toFixed(1)}%`);
const frac = (num: number, den: number): string => `${num}/${den}`;

export type ReportMeta = { date: string; commit: string; semgrep: string };

function countsRow(label: string, c: Counts): string {
  return `| ${label} | ${c.tp} | ${c.fp} | ${c.fn} | ${c.skipped} | ${c.duplicates} | ${pct(c.precision)} | ${pct(c.recall)} | ${frac(c.falseGaps, c.controls)} (${pct(c.falseGapRate)}) | ${frac(c.assertedFalseGaps, c.controls)} |`;
}

function modeSection(result: BenchResult): string[] {
  const { run } = result;
  const lines = [
    `## Mode: ${run.mode}`,
    "",
    `Determinism: ${result.deterministic ? `identical (${result.hashes.length}/${result.hashes.length} runs, sha256 ${result.hashes[0].slice(0, 12)})` : `DIFFERENT (${result.hashes.map((h) => h.slice(0, 12)).join(", ")})`}`,
    "",
    "| Repo | TP | FP | FN | Skipped | Dup | Precision | Recall | False gaps | Asserted (≥0.7) |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ...run.repos.map((r) => countsRow(r.repo, r.counts)),
    countsRow("**total**", run.total),
    "",
    "| OWASP | Planted | Detected | Missed | Skipped |",
    "| --- | ---: | ---: | ---: | ---: |",
    ...run.perOwasp.map((row) => `| ${row.owasp} | ${row.planted} | ${row.detected} | ${row.missed} | ${row.skipped} |`),
    "",
    "### Missed issues (FN)",
    "",
  ];
  const missed = run.repos.flatMap((r) => r.issues.filter((i) => i.status === "FN").map((i) => `- ${r.repo}: \`${i.id}\` (${i.owasp}, ${i.file})`));
  lines.push(...(missed.length > 0 ? missed : ["None."]), "", "### Findings that match no planted issue (FP)", "");
  const fps = run.repos.flatMap((r) =>
    r.findings
      .filter((f) => f.matches.length === 0)
      .map(
        (f) =>
          `- ${r.repo}: ${f.source} \`${f.kind}\` at ${f.file}:${f.line}${f.certainty !== undefined ? `, certainty ${f.certainty}` : ""}${f.scope ? `, scope ${f.scope}` : ""}${f.falsifies.length > 0 ? `, **falsifies ${f.falsifies.join(", ")}**` : ""}`,
      ),
  );
  lines.push(...(fps.length > 0 ? fps : ["None."]), "", "### False gaps (controls that produced a gap)", "");
  const falseGaps = run.repos.flatMap((r) =>
    r.controls
      .filter((c) => c.falseGap)
      .map((c) => `- ${r.repo}: \`${c.id}\` (${c.gapKind}, ${c.type}): ${c.gaps.join("; ")}`),
  );
  lines.push(...(falseGaps.length > 0 ? falseGaps : ["None."]), "");
  return lines;
}

/** One paste-ready row for a before/after table when a detector fix lands. */
export function benchRow(result: BenchResult, meta: Pick<ReportMeta, "date" | "commit">): string {
  const t = result.run.total;
  return `| ${meta.date} | ${meta.commit} | ${result.run.mode} | ${t.tp}/${t.fp}/${t.fn} | ${pct(t.precision)} | ${pct(t.recall)} | ${frac(t.falseGaps, t.controls)} (${pct(t.falseGapRate)}) | ${result.deterministic ? "yes" : "NO"} |`;
}

export function renderReport(results: readonly BenchResult[], meta: ReportMeta): string {
  return [
    "# Seeded bench",
    "",
    "<!-- Generated by scripts/eval/bench.ts (pnpm bench). Edit only below the notes marker. -->",
    "",
    `Generated ${meta.date} at commit ${meta.commit}. Semgrep: ${meta.semgrep}. No model was called.`,
    "",
    "Repositories: tests/fixtures/seeded/ (labels in each expected.yaml, rules in tests/fixtures/seeded/README.md).",
    "",
    "## Definitions",
    "",
    "- A finding (a gap, or a Semgrep result) **matches** a planted issue when it is in the issue's file and its kind is the issue's `gapKind` or `ruleId`.",
    "- **TP**: planted issues matched by at least one finding. **FN**: planted issues matched by none. **FP**: findings that match no planted issue. **Dup**: matching findings whose issues an earlier finding already matched (neither TP nor FP).",
    "- **Skipped**: issues labelled only by a Semgrep rule id, in a mode that did not run Semgrep. They are left out of every count.",
    "- **Precision** = TP / (TP + FP). **Recall** = TP / (TP + FN). Totals pool the counts across repositories.",
    "- **False gap**: a control that produced a gap of its kind in its own file, or a repository-scoped gap of its kind anywhere. **False-gap rate** = false gaps / controls. **Asserted** counts only gaps at certainty ≥ 0.7, the level at which the product states a gap instead of asking about it.",
    "- **Determinism**: the whole bench runs three times from a fresh load; the serialised outputs must be byte-identical.",
    "",
    "## Bench rows",
    "",
    "| Date | Commit | Mode | TP/FP/FN | Precision | Recall | False-gap rate | Deterministic |",
    "| --- | --- | --- | --- | ---: | ---: | ---: | --- |",
    ...results.map((result) => benchRow(result, meta)),
    "",
    ...results.flatMap(modeSection),
    NOTES_MARKER,
    "",
  ].join("\n");
}

/** The generated report, with the hand-written notes of the existing one kept after the marker. */
export function mergeReport(generated: string, existing: string | undefined): string {
  const at = existing?.indexOf(NOTES_MARKER) ?? -1;
  const notes = at === -1 ? "" : existing!.slice(at + NOTES_MARKER.length).replace(/^\n+/, "");
  const head = generated.slice(0, generated.indexOf(NOTES_MARKER) + NOTES_MARKER.length);
  return notes.trim() === "" ? `${head}\n` : `${head}\n\n${notes}`;
}

/** Plain-text summary for the terminal. */
export function renderSummary(result: BenchResult): string {
  const { run } = result;
  const row = (label: string, c: Counts) =>
    `  ${label.padEnd(16)} TP ${String(c.tp).padStart(2)}  FP ${String(c.fp).padStart(2)}  FN ${String(c.fn).padStart(2)}  skipped ${c.skipped}  precision ${pct(c.precision).padStart(6)}  recall ${pct(c.recall).padStart(6)}  false gaps ${frac(c.falseGaps, c.controls)} (${pct(c.falseGapRate)})`;
  return [
    `mode: ${run.mode}`,
    ...run.repos.map((r) => row(r.repo, r.counts)),
    row("total", run.total),
    "  per OWASP class (planted / detected / missed / skipped):",
    ...run.perOwasp.map((o) => `    ${o.owasp}  ${o.planted} / ${o.detected} / ${o.missed} / ${o.skipped}`),
    `  determinism: ${result.deterministic ? "identical" : "DIFFERENT"} (${result.hashes.length} runs)`,
  ].join("\n");
}
