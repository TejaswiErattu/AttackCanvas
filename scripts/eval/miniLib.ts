/**
 * The logic of scripts/eval/mini.ts, kept apart so tests can import it: the script itself
 * can make paid model calls the moment it is invoked.
 *
 * The mini benchmark re-runs the threat engine for a few answer-key items only. From a
 * saved result and its hand labels it finds the components whose threats recalled those
 * items, takes the STRIDE batches that hold those components from a saved architecture
 * checkpoint, and runs just those batches. Nothing here labels anything: the recall it
 * prints for the new run is a LOCATION PROXY (a threat cites evidence inside the code the
 * answer key points at), printed beside the same proxy and the hand-labelled recall on the
 * saved run, so the proxy can be judged against the labels it stands in for.
 */

import { z } from "zod";
import { batchElements, type ThreatEngineInput, type ThreatEngineResult } from "@/server/analysis/threats";
import type { MergedArchitecture } from "@/server/analysis/architecture";
import type { Evidence, Threat, ThreatModel } from "@/shared/schema";
import { recalledIds, type LabeledThreat } from "./lib";

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

export type MiniArgs = {
  name: string;
  ids: string[];
  /** Pick components by the answer key's source files instead of by hand labels. */
  byFiles: boolean;
  dryRun: boolean;
  allowUncached: boolean;
  level?: 0 | 1 | 2 | 3 | 4;
};

const FLAGS = new Set(["--by-files", "--dry-run", "--allow-uncached"]);
export const MINI_USAGE =
  "usage: mini.ts <result-name> <ID[,ID...]> [--by-files] [--dry-run] [--allow-uncached] [--level 0-4]";

/** Throws a printable message. The ids are a comma or space separated list. */
export function parseMiniArgs(argv: readonly string[]): MiniArgs {
  const positional: string[] = [];
  const flags = new Set<string>();
  let level: number | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--level") level = Number(argv[++i]);
    else if (arg.startsWith("--")) {
      if (!FLAGS.has(arg)) throw new Error(`unknown option ${arg}; ${MINI_USAGE}`);
      flags.add(arg);
    } else positional.push(arg);
  }
  if (positional.length < 2) throw new Error(MINI_USAGE);
  const [name, ...rest] = positional;
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)) throw new Error(`"${name}" is not a result name (lowercase letters, digits, hyphens)`);
  const ids = [...new Set(rest.flatMap((part) => part.split(/[;,\s]+/)).filter(Boolean))];
  if (ids.length === 0) throw new Error(MINI_USAGE);
  if (level !== undefined && ![0, 1, 2, 3, 4].includes(level)) throw new Error("--level must be 0, 1, 2, 3 or 4");
  return {
    name,
    ids,
    byFiles: flags.has("--by-files"),
    dryRun: flags.has("--dry-run"),
    allowUncached: flags.has("--allow-uncached"),
    ...(level === undefined ? {} : { level: level as MiniArgs["level"] }),
  };
}

// ---------------------------------------------------------------------------
// Answer-key locations
// ---------------------------------------------------------------------------

export type SourceRange = { path: string; start?: number; end?: number };

/**
 * "https://github.com/o/r/blob/<ref>/app/x.js#L31-L34 ; https://.../blob/<ref>/y.js" as
 * ranges. A link that is not a /blob/<ref>/<path> URL contributes nothing.
 */
export function parseSourceRanges(source: string): SourceRange[] {
  const out: SourceRange[] = [];
  for (const part of source.split(/\s*;\s*/)) {
    const match = /\/blob\/[^/]+\/([^#\s]+)(?:#L(\d+)(?:-L(\d+))?)?/.exec(part.trim());
    if (!match) continue;
    const start = match[2] === undefined ? undefined : Number(match[2]);
    const end = match[3] === undefined ? start : Number(match[3]);
    out.push({ path: match[1], ...(start === undefined ? {} : { start, end }) });
  }
  return out;
}

const SourcesSchema = z.object({
  expectedThreats: z.array(z.object({ id: z.string(), source: z.string().optional() }).loose()),
});

/** id -> where the answer key says the weakness lives. ExpectedFileSchema drops `source`. */
export function expectedSources(raw: unknown): Map<string, SourceRange[]> {
  const parsed = SourcesSchema.parse(raw);
  return new Map(parsed.expectedThreats.map((t) => [t.id, t.source ? parseSourceRanges(t.source) : []]));
}

/** True when `evidence` sits inside `range`: same file, and overlapping lines when both have them. */
export function evidenceInRange(evidence: Evidence, range: SourceRange): boolean {
  if (evidence.filePath !== range.path) return false;
  if (range.start === undefined || evidence.lineStart === undefined) return true;
  const end = evidence.lineEnd ?? evidence.lineStart;
  return evidence.lineStart <= (range.end ?? range.start) && end >= range.start;
}

// ---------------------------------------------------------------------------
// Choosing components and batches
// ---------------------------------------------------------------------------

/** Ids of components that a supported, hand-labelled threat tied to one of `ids` names. */
export function componentsByLabels(
  model: ThreatModel,
  labels: readonly LabeledThreat[],
  ids: readonly string[],
): string[] {
  const wanted = new Set(ids);
  const byThreat = new Map(model.threats.map((t) => [t.id, t]));
  const out = new Set<string>();
  for (const label of labels) {
    if (!label.supported || !label.matches.some((id) => wanted.has(id))) continue;
    for (const componentId of byThreat.get(label.threatId)?.componentIds ?? []) out.add(componentId);
  }
  return [...out].sort();
}

/** Ids of components whose files include a file the answer key points at for one of `ids`. */
export function componentsByFiles(
  architecture: Pick<MergedArchitecture, "components">,
  sources: ReadonlyMap<string, readonly SourceRange[]>,
  ids: readonly string[],
): string[] {
  const paths = new Set(ids.flatMap((id) => (sources.get(id) ?? []).map((r) => r.path)));
  return architecture.components
    .filter((c) => c.files.some((file) => paths.has(file)))
    .map((c) => c.id)
    .sort();
}

/**
 * The STRIDE batches of the whole architecture that hold at least one of `componentIds`,
 * in the order a full run would run them. Batches are never re-cut, so each is the same
 * text a full run sends, and a model cache entry from one is a hit for the other.
 */
export function selectBatches(
  architecture: Pick<MergedArchitecture, "components" | "dataFlows">,
  componentIds: readonly string[],
): { all: number; selected: string[][] } {
  const all = batchElements(architecture);
  const wanted = new Set(componentIds);
  return { all: all.length, selected: all.filter((batch) => batch.some((id) => wanted.has(id))) };
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/**
 * Answer-key ids a set of threats reaches by location: a threat counts for an id when one
 * of its cited evidence items lies inside a range the key gives for it. An id the key gives
 * no range for can never be found this way and is returned in `unlocatable`.
 */
export function proxyRecall(
  threats: readonly Pick<Threat, "evidenceIds">[],
  evidence: readonly Evidence[],
  sources: ReadonlyMap<string, readonly SourceRange[]>,
  ids: readonly string[],
): { found: string[]; unlocatable: string[] } {
  const byId = new Map(evidence.map((e) => [e.id, e]));
  const cited = threats.flatMap((t) => t.evidenceIds.flatMap((id) => byId.get(id) ?? []));
  const found: string[] = [];
  const unlocatable: string[] = [];
  for (const id of ids) {
    const ranges = sources.get(id) ?? [];
    if (ranges.length === 0) unlocatable.push(id);
    else if (cited.some((e) => ranges.some((r) => evidenceInRange(e, r)))) found.push(id);
  }
  return { found, unlocatable };
}

/** The chosen ids the hand labels recall on the saved run. */
export function labelledRecall(labels: readonly LabeledThreat[], ids: readonly string[]): string[] {
  const recalled = recalledIds(labels);
  return ids.filter((id) => recalled.has(id));
}

export type MiniReport = {
  ids: string[];
  batches: { run: number; of: number };
  components: string[];
  newThreats: number;
  labelledSaved: string[];
  proxySaved: string[];
  proxyNew: string[];
  unlocatable: string[];
  costUsd: number;
  calls: number;
  cachedCalls: number;
};

export function formatMiniReport(r: MiniReport): string[] {
  const of = (found: readonly string[]) => `${found.length}/${r.ids.length}` + (found.length ? ` (${found.join(", ")})` : "");
  return [
    `batches: ran ${r.batches.run} of ${r.batches.of} (components ${r.components.join(", ") || "none"})`,
    `new threats from those batches: ${r.newThreats}`,
    `recall over ${r.ids.join(", ")}:`,
    `  saved run, hand labels:        ${of(r.labelledSaved)}`,
    `  saved run, location proxy:     ${of(r.proxySaved)}`,
    `  this run, location proxy:      ${of(r.proxyNew)}`,
    ...(r.unlocatable.length
      ? [`  no source location in the answer key for: ${r.unlocatable.join(", ")} (proxy cannot score these)`]
      : []),
    "  The proxy is not hand-labelled recall: it counts a threat that cites evidence inside the code the key points at.",
    `cost: $${r.costUsd.toFixed(4)} (${r.calls} response(s), ${r.cachedCalls} from the model cache)`,
  ];
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export type MiniInput = {
  args: MiniArgs;
  model: ThreatModel;
  labels: readonly LabeledThreat[];
  sources: ReadonlyMap<string, readonly SourceRange[]>;
  architecture: MergedArchitecture;
  engine: Omit<ThreatEngineInput, "architecture" | "batches" | "analysisId">;
  analysisId: string;
};

export type MiniPlan = { componentIds: string[]; all: number; selected: string[][] };

/** What would run, with no model call. Throws a printable reason when nothing can. */
export function planMini(input: Pick<MiniInput, "args" | "model" | "labels" | "sources" | "architecture">): MiniPlan {
  const { args, model, labels, sources, architecture } = input;
  const known = new Set(architecture.components.map((c) => c.id));
  let componentIds = args.byFiles
    ? componentsByFiles(architecture, sources, args.ids)
    : componentsByLabels(model, labels, args.ids);
  const missing = componentIds.filter((id) => !known.has(id));
  if (missing.length > 0) {
    throw new Error(
      `the architecture checkpoint has no component ${missing.join(", ")}, so it was not made by the run that produced ` +
        `this result; label that run, or pass --by-files to choose components from the answer key's source files`,
    );
  }
  componentIds = componentIds.filter((id) => known.has(id));
  if (componentIds.length === 0) {
    throw new Error(
      args.byFiles
        ? `no component's files include a file the answer key gives for ${args.ids.join(", ")}`
        : `no supported, labelled threat matches ${args.ids.join(", ")}, so no component is known; try --by-files`,
    );
  }
  const { all, selected } = selectBatches(architecture, componentIds);
  return { componentIds, all, selected };
}

export async function runMini(
  input: MiniInput,
  deps: {
    generateThreats: (input: ThreatEngineInput) => Promise<ThreatEngineResult>;
    cost: () => { totalUsd: number; calls: number; cachedCalls: number };
  },
): Promise<MiniReport> {
  const plan = planMini(input);
  const result = await deps.generateThreats({
    ...input.engine,
    architecture: input.architecture,
    batches: plan.selected,
    analysisId: input.analysisId,
  });
  const ids = input.args.ids;
  const savedProxy = proxyRecall(input.model.threats, input.model.evidence, input.sources, ids);
  const newProxy = proxyRecall(result.threats, input.architecture.evidence, input.sources, ids);
  const cost = deps.cost();
  return {
    ids,
    batches: { run: plan.selected.length, of: plan.all },
    components: plan.componentIds,
    newThreats: result.threats.length,
    labelledSaved: labelledRecall(input.labels, ids),
    proxySaved: savedProxy.found,
    proxyNew: newProxy.found,
    unlocatable: newProxy.unlocatable,
    costUsd: cost.totalUsd,
    calls: cost.calls,
    cachedCalls: cost.cachedCalls,
  };
}
