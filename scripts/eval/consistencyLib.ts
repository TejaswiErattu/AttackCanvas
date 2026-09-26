/**
 * The pure arithmetic behind scripts/eval/consistency.ts: how much several saved runs of the
 * same repository agree. No model call and no file access. Matching uses the same keys as
 * the dashboard's "since last run" comparison (src/client/drift.ts): components by name and
 * type, flows by source, target and label, threats by title, components and OWASP codes.
 */

import { norm, threatKey } from "@/client/drift";
import { isHidden } from "@/server/scoring";
import type { Evidence, ThreatModel } from "@/shared/schema";
import type { ThreatCardData } from "@/shared/viewModel";
import type { EvalResult } from "./lib";

export type Pair = { a: string; b: string; jaccard: number };
export type Overlap = { pairs: Pair[]; mean: number | null };

/** |A n B| / |A u B|; two empty sets are identical, so 1. */
export function jaccard<T>(a: ReadonlySet<T>, b: ReadonlySet<T>): number {
  if (a.size === 0 && b.size === 0) return 1;
  let both = 0;
  for (const x of a) if (b.has(x)) both += 1;
  return both / (a.size + b.size - both);
}

/** Every unordered pair of runs, in order, and the mean of their Jaccard values (null for fewer than two runs). */
export function pairwiseOverlap(runs: readonly { name: string; keys: ReadonlySet<string> }[]): Overlap {
  const pairs: Pair[] = [];
  for (let i = 0; i < runs.length; i += 1) {
    for (let j = i + 1; j < runs.length; j += 1) {
      pairs.push({ a: runs[i].name, b: runs[j].name, jaccard: jaccard(runs[i].keys, runs[j].keys) });
    }
  }
  return { pairs, mean: pairs.length === 0 ? null : pairs.reduce((s, p) => s + p.jaccard, 0) / pairs.length };
}

const nameOf = (model: ThreatModel) => new Map(model.components.map((c) => [c.id, c.name]));

export const componentKeys = (model: ThreatModel): Set<string> =>
  new Set(model.components.map((c) => JSON.stringify([norm(c.name), c.type])));

export function flowKeys(model: ThreatModel): Set<string> {
  const names = nameOf(model);
  return new Set(
    model.dataFlows.map((f) => JSON.stringify([norm(names.get(f.sourceId) ?? f.sourceId), norm(names.get(f.targetId) ?? f.targetId), norm(f.label)])),
  );
}

/** Visible threats (not hidden below the confidence cutoff), keyed with drift.ts's threatKey. */
export function visibleThreats(model: ThreatModel): Map<string, ThreatModel["threats"][number]> {
  const names = nameOf(model);
  const out = new Map<string, ThreatModel["threats"][number]>();
  for (const t of model.threats) {
    if (isHidden(t.confidence)) continue;
    const card = { title: t.title, componentNames: t.componentIds.map((id) => names.get(id) ?? id), owasp: t.owasp.map((code) => ({ code })) };
    const key = threatKey(card as unknown as ThreatCardData);
    if (!out.has(key)) out.set(key, t); // duplicate keys within a run collapse to the first
  }
  return out;
}

export type ThreatPresence = {
  /** Distinct visible threat keys over all runs. */
  total: number;
  inAll: number;
  /** In at least two runs but not all (two of three, when there are three). */
  inSome: number;
  inOne: number;
};

export function threatPresence(runs: readonly ReadonlyMap<string, unknown>[]): ThreatPresence {
  const count = new Map<string, number>();
  for (const run of runs) for (const key of run.keys()) count.set(key, (count.get(key) ?? 0) + 1);
  const counts = [...count.values()];
  return {
    total: counts.length,
    inAll: counts.filter((c) => c === runs.length).length,
    inSome: counts.filter((c) => c > 1 && c < runs.length).length,
    inOne: counts.filter((c) => c === 1 && runs.length > 1).length,
  };
}

export type Agreement = { matched: number; severity: number; priority: number };

/** Of the threats present in every run, how many have the same severity, and the same priority, in all of them. */
export function scoreAgreement(runs: readonly ReadonlyMap<string, ThreatModel["threats"][number]>[]): Agreement {
  const shared = runs.length === 0 ? [] : [...runs[0].keys()].filter((k) => runs.every((r) => r.has(k)));
  const same = (pick: (t: ThreatModel["threats"][number]) => string) =>
    shared.filter((k) => new Set(runs.map((r) => pick(r.get(k) as ThreatModel["threats"][number]))).size === 1).length;
  return { matched: shared.length, severity: same((t) => t.severity), priority: same((t) => t.priority) };
}

/** Visible threats per OWASP code, one row per code; a threat with two codes counts under both. */
export function owaspCounts(models: readonly ThreatModel[]): { code: string; counts: number[] }[] {
  const per = models.map((m) => {
    const counts = new Map<string, number>();
    for (const t of visibleThreats(m).values()) for (const code of t.owasp) counts.set(code, (counts.get(code) ?? 0) + 1);
    return counts;
  });
  const codes = [...new Set(per.flatMap((c) => [...c.keys()]))].sort();
  return codes.map((code) => ({ code, counts: per.map((c) => c.get(code) ?? 0) }));
}

// ---------------------------------------------------------------------------
// Deterministic evidence
// ---------------------------------------------------------------------------

/** Evidence produced without a model: detectors (including control gaps), Semgrep and OSV. */
const DETERMINISTIC_SOURCES: readonly Evidence["source"][] = ["detector", "semgrep", "osv"];

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined).sort(([x], [y]) => x.localeCompare(y));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** Sorted, id-free fingerprints of the deterministic evidence: ids are minted per run, so they are left out. */
export function deterministicEvidence(model: ThreatModel): string[] {
  return model.evidence
    .filter((e) => DETERMINISTIC_SOURCES.includes(e.source))
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    .map(({ id: _id, ...rest }) => stable(rest))
    .sort();
}

export type EvidenceCheck = {
  identical: boolean;
  /** Deterministic evidence items per run. */
  counts: number[];
  /** Items not present (with multiplicity) in every run. */
  differing: number;
};

export function compareEvidence(models: readonly ThreatModel[]): EvidenceCheck {
  const lists = models.map(deterministicEvidence);
  const tally = lists.map((l) => {
    const m = new Map<string, number>();
    for (const x of l) m.set(x, (m.get(x) ?? 0) + 1);
    return m;
  });
  const items = new Set(lists.flat());
  let differing = 0;
  for (const item of items) {
    const per = tally.map((m) => m.get(item) ?? 0);
    if (Math.min(...per) !== Math.max(...per)) differing += 1;
  }
  return { identical: differing === 0, counts: lists.map((l) => l.length), differing };
}

// ---------------------------------------------------------------------------
// Whole report
// ---------------------------------------------------------------------------

export type Stat = { min: number; max: number; mean: number };

/** Null when there are no values (an older result with no recorded duration). */
export function statOf(values: readonly number[]): Stat | null {
  if (values.length === 0) return null;
  return { min: Math.min(...values), max: Math.max(...values), mean: values.reduce((s, v) => s + v, 0) / values.length };
}

export type Consistency = {
  runs: { name: string; level: number | null; ranAt: string; calls: number; costUsd: number; durationMs: number | null }[];
  components: Overlap;
  flows: Overlap;
  threats: { visiblePerRun: number[]; presence: ThreatPresence; agreement: Agreement };
  owasp: { code: string; counts: number[] }[];
  evidence: EvidenceCheck;
  calls: Stat | null;
  costUsd: Stat | null;
  durationMs: Stat | null;
};

export function analyseConsistency(results: readonly EvalResult[]): Consistency {
  const models = results.map((r) => r.threatModel);
  const threats = models.map(visibleThreats);
  const named = (pick: (m: ThreatModel) => Set<string>) => results.map((r) => ({ name: r.repo, keys: pick(r.threatModel) }));
  const durations = results.flatMap((r) => (r.durationMs === undefined ? [] : [r.durationMs]));
  return {
    runs: results.map((r) => ({ name: r.repo, level: r.level ?? null, ranAt: r.ranAt, calls: r.cost.calls, costUsd: r.cost.totalUsd, durationMs: r.durationMs ?? null })),
    components: pairwiseOverlap(named(componentKeys)),
    flows: pairwiseOverlap(named(flowKeys)),
    threats: { visiblePerRun: threats.map((t) => t.size), presence: threatPresence(threats), agreement: scoreAgreement(threats) },
    owasp: owaspCounts(models),
    evidence: compareEvidence(models),
    calls: statOf(results.map((r) => r.cost.calls)),
    costUsd: statOf(results.map((r) => r.cost.totalUsd)),
    durationMs: durations.length === results.length ? statOf(durations) : null,
  };
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

const pct = (n: number, d: number) => (d === 0 ? "n/a" : `${((n / d) * 100).toFixed(1)}%`);
const dec = (v: number | null) => (v === null ? "n/a" : v.toFixed(3));
const statRow = (label: string, s: Stat | null, f: (v: number) => string) =>
  s ? `| ${label} | ${f(s.min)} | ${f(s.max)} | ${f(s.mean)} |` : `| ${label} | n/a | n/a | n/a |`;

export function renderConsistencyReport(c: Consistency, generatedAt: string): string {
  const names = c.runs.map((r) => r.name);
  const overlap = (title: string, o: Overlap) => [
    `## ${title}`,
    "",
    "| Pair | Jaccard |",
    "| --- | ---: |",
    ...o.pairs.map((p) => `| ${p.a} / ${p.b} | ${dec(p.jaccard)} |`),
    `| **mean** | **${dec(o.mean)}** |`,
    "",
  ];
  const p = c.threats.presence;
  const a = c.threats.agreement;
  return [
    "# Consistency across runs",
    "",
    "<!-- Generated by scripts/eval/consistency.ts from saved results. No model was called. Do not edit by hand. -->",
    "",
    `Generated ${generatedAt}. Runs: ${names.join(", ")}.`,
    "",
    "| Run | Level | Ran at | Visible threats |",
    "| --- | ---: | --- | ---: |",
    ...c.runs.map((r, i) => `| ${r.name} | ${r.level ?? "not recorded"} | ${r.ranAt} | ${c.threats.visiblePerRun[i]} |`),
    "",
    ...overlap("Components (name + type)", c.components),
    ...overlap("Data flows (source + target + label)", c.flows),
    "## Threats",
    "",
    "Visible threats only (confidence 0.25 or more), matched with the key the dashboard's drift view uses: title, component names, OWASP codes.",
    "",
    `- Distinct visible threats over all runs: ${p.total}`,
    `- Present in all ${names.length} runs: ${p.inAll} (${pct(p.inAll, p.total)})`,
    `- Present in some but not all (at least two): ${p.inSome} (${pct(p.inSome, p.total)})`,
    `- Present in only one run: ${p.inOne} (${pct(p.inOne, p.total)})`,
    `- Of the ${a.matched} present in all runs: same severity in ${a.severity} (${pct(a.severity, a.matched)}), same priority in ${a.priority} (${pct(a.priority, a.matched)})`,
    "",
    "## OWASP categories (visible threats)",
    "",
    `| Category | ${names.join(" | ")} |`,
    `| --- | ${names.map(() => "---:").join(" | ")} |`,
    ...c.owasp.map((o) => `| ${o.code} | ${o.counts.join(" | ")} |`),
    "",
    "## Deterministic evidence",
    "",
    `Detector (including control-gap), Semgrep and OSV items, compared without ids. Items per run: ${c.evidence.counts.join(", ")}.`,
    "",
    c.evidence.identical
      ? "**Identical across all runs.**"
      : `**NOT identical: ${c.evidence.differing} distinct item(s) are missing from at least one run.** Investigate before trusting the model comparison.`,
    "",
    "## Calls, cost and duration",
    "",
    "| Measure | Min | Max | Mean |",
    "| --- | ---: | ---: | ---: |",
    statRow("Model calls", c.calls, (v) => v.toFixed(1)),
    statRow("Cost (USD)", c.costUsd, (v) => `$${v.toFixed(4)}`),
    statRow("Duration", c.durationMs, (v) => `${(v / 60000).toFixed(1)} min`),
    "",
    ...(c.durationMs === null ? ["Duration is n/a when any run was saved before run.ts recorded it.", ""] : []),
  ].join("\n");
}
