/**
 * The threat engine (Prompt P2).
 *
 * P1 wrote the prompt and the payload for ONE batch of elements. This module runs every
 * batch: it splits the merged architecture into small batches, calls the model for each
 * with at most three in flight, throws away any threat whose references do not resolve,
 * merges near-duplicates, and gives what survives stable ids.
 *
 * It scores nothing and builds no ThreatModel. Severity, confidence, basis and priority
 * come from src/server/scoring, run by Prompt Q over what this returns.
 *
 * Determinism is the organising constraint. The model returns threats in whatever order
 * it likes and batches finish in whatever order the network likes, and none of that may
 * reach the output: batches are built from sorted ids, results are collected by batch
 * index, dedupe clusters over a canonically sorted list, and ids are assigned last from a
 * total order. Two runs over logically identical input give identical ids and ordering.
 *
 * Nothing is repaired. A reference that does not resolve drops the whole threat, with a
 * limitation saying which reference and why; the engine never substitutes, guesses or
 * invents an identifier.
 */

import { z } from "zod";
import { AiError, callStructured, type ClaudeDeps } from "@/server/ai/claude";
import { loadPrompt } from "@/server/ai/prompts";
import type { CallUsage } from "@/server/ai/usage";
import type { MergedArchitecture } from "@/server/analysis/architecture";
import { oneLine } from "@/server/analysis/context";
import {
  STRIDE_ORDER,
  THREATS_CONTEXT_TOKENS,
  THREATS_MAX_TOKENS,
  THREATS_PROMPT_NAME,
  THREATS_PROMPT_VERSION,
  assertBatchClean,
  buildThreatBatch,
  type ThreatBatch,
} from "@/server/analysis/threatPrompt";
import type { ControlGap } from "@/server/detect/types";
import type { LoadedFile } from "@/server/ingest/loader";
import { isPositiveObservation } from "@/server/scoring";
import { stripCrossRouteGapCitations, type RemovedCitation } from "@/server/analysis/routeScope";
import {
  DraftThreatSchema,
  type DraftThreat,
  type Evidence,
} from "@/shared/schema";

// ---------------------------------------------------------------------------
// Knobs
// ---------------------------------------------------------------------------

/**
 * Elements per batch. The prompt allows up to four; two keeps each non-streaming reply
 * short enough to finish (four elements never completed live), keeps the model focused,
 * and caps the damage of one bad response.
 */
export const THREATS_BATCH_SIZE = 2;

/** Calls in flight at once. */
export const THREATS_CONCURRENCY = 3;

/**
 * Per-call deadline for a STRIDE batch. A four-element batch can ask for up to six
 * categories across two passes, and a non-streaming reply of that size outlives the
 * client's 120 s default (a live run timed out at exactly that deadline).
 */
export const THREATS_TIMEOUT_MS = 300_000;

/**
 * Extended thinking is disabled for threat calls (and for architecture and question calls:
 * ARCHITECTURE_THINKING, QUESTIONS_THINKING).
 */
export const THREATS_THINKING = { type: "disabled" } as const;

/** Two threats merge when the Jaccard similarity of their token sets is at least this. */
export const DEDUPE_THRESHOLD = 0.6;

/** Cap on the words of model-written text echoed into a limitation. */
const LIMITATION_TITLE_CHARS = 80;

/**
 * The model returns an object, not a bare array: the client sends the schema as a
 * structured-output contract, and the architecture draft is an object for the same
 * reason. The wrapper is local to this module; the shared DraftThreatSchema is untouched.
 */
export const ThreatBatchResponseSchema = z.object({
  threats: z.array(DraftThreatSchema),
});
export type ThreatBatchResponse = z.infer<typeof ThreatBatchResponseSchema>;

/** The JSON Schema for the response. The client makes it API-compatible (`toApiSchema`). */
export const threatBatchJsonSchema = z.toJSONSchema(
  ThreatBatchResponseSchema,
) as Record<string, unknown>;

// ---------------------------------------------------------------------------
// Public shape
// ---------------------------------------------------------------------------

/** A draft threat with the id this engine gave it. Still unscored. */
export type EngineThreat = DraftThreat & { id: string };

export type BatchReport = {
  index: number;
  elementIds: string[];
  /** Threats the model returned, before validation. */
  returned: number;
};

export type ThreatEngineInput = {
  architecture: MergedArchitecture;
  /** The detector's gaps, the same list mergeArchitecture bound. */
  gaps: readonly ControlGap[];
  /**
   * Normalized paths of the detector's routes, used to tell which route a threat names
   * (routeScope.ts). Optional: without it only the gaps' own routes are known, which is
   * more conservative (fewer threats read as naming a different route).
   */
  routePaths?: readonly string[];
  files: readonly LoadedFile[];
  analysisId: string;
  /**
   * Run exactly these batches instead of batching the whole architecture. For a smoke
   * test of one call; nothing in the pipeline sets it.
   */
  batches?: readonly (readonly string[])[];
  /** Test seam, passed straight to callStructured. Nothing in production sets it. */
  deps?: Partial<ClaudeDeps>;
  promptDir?: string;
  maxTokens?: number;
  /** Per-batch input budget in tokens. Defaults to THREATS_CONTEXT_TOKENS. */
  budgetTokens?: number;
  concurrency?: number;
  /**
   * Checked immediately before each batch starts. Once it returns false no further batch
   * (so no further provider request) starts; batches already in flight finish, since the
   * client cannot abort a call, and the run then throws a TIMEOUT AiError rather than
   * return a partial threat list. The pipeline passes its deadline and cancel flag here.
   */
  shouldContinue?: () => boolean;
};

export type ThreatEngineResult = {
  threats: EngineThreat[];
  /** The evidence the surviving threats cite, in the architecture's order. */
  evidence: Evidence[];
  /** Everything dropped, failed or worth knowing, in a deterministic order. */
  limitations: string[];
  batches: BatchReport[];
  /** One entry per successful call, in batch order. */
  usage: CallUsage[];
  /** "threats.v1". Recorded alongside whatever the threats become. */
  promptId: string;
};

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

/** Code-unit order. Locale-independent, so ids sort the same on every machine. */
export function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(cmp);
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

// ---------------------------------------------------------------------------
// 1. Batching
// ---------------------------------------------------------------------------

/**
 * Splits every component and data flow into batches of at most `size`, each element in
 * exactly one batch.
 *
 * Units are built first: a component followed by the flows it is the source of, so a flow
 * is reasoned about beside the component that emits it. Units are taken in id order and
 * each is placed whole in the FIRST batch with room for it, or in a new batch when none
 * has. A unit larger than a batch (a component with more than size-1 outgoing flows) is
 * split into consecutive chunks, the first holding the component; full chunks are
 * batches of their own and a short trailing chunk is a batch later units may fill.
 * "Where possible" is as far as the constraint goes, since an element may appear once.
 *
 * First-fit rather than strictly sequential packing, so a short batch is topped up by a
 * later small unit instead of being left at one element: the saved 14-element bezkoder
 * architecture needs 7 batches, the minimum, where sequential packing needs 8. It is
 * still deterministic, since the units, their order and the rule are fixed.
 *
 * A flow whose source is not a component (a merged architecture should not contain one)
 * is packed after the units rather than dropped.
 *
 * Input order is irrelevant: ids are sorted before anything else happens.
 */
export function batchElements(
  architecture: Pick<MergedArchitecture, "components" | "dataFlows">,
  size: number = THREATS_BATCH_SIZE,
): string[][] {
  if (!Number.isInteger(size) || size < 1) {
    throw new Error(`batch size must be a positive integer, got ${size}`);
  }

  const componentIds = sortedUnique(architecture.components.map((c) => c.id));
  const known = new Set(componentIds);
  const flowsBySource = new Map<string, string[]>();
  const orphanFlows: string[] = [];
  for (const flow of [...architecture.dataFlows].sort((a, b) => cmp(a.id, b.id))) {
    if (known.has(flow.sourceId)) {
      flowsBySource.set(flow.sourceId, [
        ...(flowsBySource.get(flow.sourceId) ?? []),
        flow.id,
      ]);
    } else {
      orphanFlows.push(flow.id);
    }
  }

  const units: string[][] = [
    ...componentIds.map((id) => [id, ...(flowsBySource.get(id) ?? [])]),
    ...orphanFlows.map((id) => [id]),
  ];

  const batches: string[][] = [];
  const place = (unit: string[]) => {
    const room = batches.find((batch) => batch.length + unit.length <= size);
    if (room) room.push(...unit);
    else batches.push([...unit]);
  };

  for (const unit of units) {
    if (unit.length <= size) place(unit);
    else for (const part of chunk(unit, size)) place(part);
  }
  return batches;
}

// ---------------------------------------------------------------------------
// 2. Concurrency
// ---------------------------------------------------------------------------

/**
 * Runs `task` over `items` with at most `limit` in flight and returns the results in the
 * order of `items`, however the tasks finish. The first rejection (lowest index wins, so
 * the choice does not depend on timing) stops new tasks from starting, waits for those
 * already running, and is then rethrown.
 */
/** Thrown by runPool when `shouldStart` stopped it before every item had started. */
export class PoolStoppedError extends Error {
  constructor(readonly started: number, readonly total: number) {
    super(`stopped after starting ${started} of ${total} tasks`);
    this.name = "PoolStoppedError";
  }
}

export async function runPool<T, R>(
  items: readonly T[],
  limit: number,
  task: (item: T, index: number) => Promise<R>,
  shouldStart: () => boolean = () => true,
): Promise<R[]> {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new Error(`concurrency must be a positive integer, got ${limit}`);
  }
  const results = new Array<R>(items.length);
  const errors = new Map<number, unknown>();
  let next = 0;
  let stopped = false;
  let halted = false;

  const worker = async () => {
    while (!stopped) {
      if (next >= items.length) return;
      // Before claiming an item: a halted pool never starts another task.
      if (!shouldStart()) {
        stopped = true;
        halted = true;
        return;
      }
      const index = next++;
      try {
        results[index] = await task(items[index], index);
      } catch (error) {
        errors.set(index, error);
        stopped = true;
      }
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, () => worker()),
  );
  if (errors.size > 0) {
    throw errors.get(Math.min(...errors.keys()));
  }
  if (halted) throw new PoolStoppedError(next, items.length);
  return results;
}

// ---------------------------------------------------------------------------
// 3. Reference validation
// ---------------------------------------------------------------------------

/**
 * What a batch's model was shown, element by element, and so all a threat may cite. Each
 * key is the id of an element in the batch; its value is what that element's block listed:
 * its own evidence ids plus its gaps' evidence ids, or the unknowns that affect it.
 */
export type Offered = {
  evidence: ReadonlyMap<string, ReadonlySet<string>>;
  unknowns: ReadonlyMap<string, ReadonlySet<string>>;
};

function offeredBy(batch: ThreatBatch): Offered {
  return {
    evidence: new Map(
      batch.elements.map((e) => [
        e.id,
        new Set([...e.evidenceIds, ...e.gaps.map((g) => g.evidenceId)]),
      ]),
    ),
    unknowns: new Map(batch.elements.map((e) => [e.id, new Set(e.unknownIds)])),
  };
}

/** Every id offered to the given elements (all of the batch's when `elementIds` is omitted). */
function offeredTo(
  byElement: ReadonlyMap<string, ReadonlySet<string>>,
  elementIds: readonly string[] = [...byElement.keys()],
): Set<string> {
  return new Set(elementIds.flatMap((id) => [...(byElement.get(id) ?? [])]));
}

/**
 * The reasons a threat cannot stand, empty when it can.
 *
 * Component and flow ids must exist in the architecture, and at least one must belong to
 * this batch: a threat about only elements the model was never given is not something it
 * could have reasoned about. Evidence and unknown ids must be ones shown under one of the
 * threat's OWN elements in this batch, which is stricter than "exists" and stricter than
 * "somewhere in the batch": evidence listed under another element, even one that shares
 * the batch, supports that element and not this threat, and citing it would make an
 * unsupported threat read as evidence-backed. An id shown nowhere in the batch reads "not
 * found"; one shown only under another element says so. A threat must also cite evidence
 * or state an assumption (prompts/threats.v1.md), or nothing supports it.
 */
export function referenceIssues(
  threat: DraftThreat,
  architecture: Pick<MergedArchitecture, "components" | "dataFlows">,
  offered: Offered,
): string[] {
  const componentIds = new Set(architecture.components.map((c) => c.id));
  const flowIds = new Set(architecture.dataFlows.map((f) => f.id));
  const elements = [...threat.componentIds, ...threat.dataFlowIds];
  // The threat's own elements that are in this batch: only their blocks count as support.
  const own = elements.filter((id) => offered.evidence.has(id));
  const issues: string[] = [];

  const missing = (label: string, ids: readonly string[], ok: (id: string) => boolean) => {
    const bad = sortedUnique(ids.filter((id) => !ok(id)));
    if (bad.length > 0) issues.push(`${label} not found: ${bad.join(", ")}`);
  };
  const cited = (
    label: string,
    ids: readonly string[],
    byElement: ReadonlyMap<string, ReadonlySet<string>>,
  ) => {
    const inBatch = offeredTo(byElement);
    const ownIds = offeredTo(byElement, own);
    missing(label, ids, (id) => inBatch.has(id));
    const borrowed = sortedUnique(ids.filter((id) => inBatch.has(id) && !ownIds.has(id)));
    if (borrowed.length > 0) {
      issues.push(`${label} offered only to another element of the batch: ${borrowed.join(", ")}`);
    }
  };

  missing("componentIds", threat.componentIds, (id) => componentIds.has(id));
  missing("dataFlowIds", threat.dataFlowIds, (id) => flowIds.has(id));
  cited("evidenceIds", threat.evidenceIds, offered.evidence);
  cited("dependsOnUnknownIds", threat.dependsOnUnknownIds, offered.unknowns);

  if (elements.length === 0) {
    issues.push("names no component or data flow");
  } else if (own.length === 0) {
    issues.push("names no element from its batch");
  }

  if (threat.evidenceIds.length === 0 && threat.assumptions.length === 0) {
    issues.push("cites no evidence and states no assumption");
  } else if (
    threat.evidenceIds.length === 0 &&
    threat.assumptions.every(isPlaceholderAssumption)
  ) {
    issues.push("is a placeholder: cites no evidence and its only assumptions are placeholders");
  }
  return issues;
}

/** Whole-text stand-ins the model writes instead of a premise: "N/A", "TBD", "see above". */
const PLACEHOLDER_TEXT =
  /^(?:n\/?a|none|null|nil|tbd|tba|todo|unknown|placeholder|removed|duplicate|same as above|as above|see above|not applicable|no assumptions?|-+|\.+|\?+)$/i;

/** At most this many words for "placeholder" inside the text to mark the whole thing. */
const PLACEHOLDER_MAX_WORDS = 6;

/**
 * True when an assumption states no premise at all (prompts/threats.v1.md, "What an
 * assumption is"). Deliberately narrow, since it decides a drop: the whole text must be a
 * known stand-in, or be short and say "placeholder" ("duplicate placeholder, removed"
 * was seen live). A real sentence that happens to mention a placeholder value is longer
 * than that and is kept.
 */
export function isPlaceholderAssumption(text: string): boolean {
  const trimmed = text.trim().replace(/[.!]+$/, "").trim();
  if (trimmed.length < 3) return true;
  if (PLACEHOLDER_TEXT.test(trimmed)) return true;
  const words = trimmed.split(/\s+/).length;
  return words <= PLACEHOLDER_MAX_WORDS && /\bplaceholder\b/i.test(trimmed);
}

/** Route-scoped gaps shown in a batch: evidence id -> the route the gap is about. */
function gapRouteByEvidenceId(batch: ThreatBatch): Map<string, string> {
  const out = new Map<string, string>();
  for (const element of batch.elements) {
    for (const gap of element.gaps) {
      if (gap.routeScoped && gap.routePath !== undefined) out.set(gap.evidenceId, gap.routePath);
    }
  }
  return out;
}

function describeRemovedCitation(threat: DraftThreat, index: number, r: RemovedCitation): string {
  const title = oneLine(threat.title, LIMITATION_TITLE_CHARS);
  return (
    `Removed citation ${r.evidenceId} from threat "${title}" in batch ${index + 1}: ` +
    `the gap is about ${r.gapRoute}, the threat names ${r.threatRoutes.join(", ")}.`
  );
}

function describeDrop(threat: DraftThreat, index: number, issues: string[]): string {
  const title = oneLine(threat.title, LIMITATION_TITLE_CHARS);
  return `Dropped threat "${title}" from batch ${index + 1}: ${issues.join("; ")}.`;
}

// ---------------------------------------------------------------------------
// 4. Deduplication
// ---------------------------------------------------------------------------

/**
 * Words that carry no meaning about a threat. Removing them keeps two unrelated threats
 * from looking alike because both say "the attacker can send a request to the API"; it
 * deliberately removes NO security vocabulary, so "injection" or "token" still count.
 */
const STOPWORDS = new Set(
  (
    "a an and are as at be been but by can could does for from had has have how if in into is it its " +
    "may might no not of on or so such than that the their them then there these they this those " +
    "to was were which who will with would you your"
  ).split(" "),
);

/** Lowercase alphanumeric words, stopwords removed, as a set. */
export function tokenize(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((word) => word.length > 0 && !STOPWORDS.has(word)),
  );
}

/** |A intersect B| / |A union B|. Two empty sets are not similar: there is nothing to compare. */
export function jaccard(a: ReadonlySet<string>, b: ReadonlySet<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  let shared = 0;
  for (const word of a) if (b.has(word)) shared++;
  return shared / (a.size + b.size - shared);
}

function similarityText(t: DraftThreat): string {
  return `${t.title} ${t.attackScenario}`;
}

function elementIdsOf(t: DraftThreat): string[] {
  return sortedUnique([...t.componentIds, ...t.dataFlowIds]);
}

/** The parts of a data flow the relationship rule reads. */
export type FlowEnds = { id: string; sourceId: string; targetId: string };

/**
 * Whether two threats are about the same part of the system, so that similar wording is
 * more likely one problem than two. True when they share a component, share a data flow,
 * or one cites a flow whose source or target is a component the other cites (a component
 * and a connected flow are two views of the same exposure).
 *
 * Symmetric by construction: the last rule is checked in both directions. It is a
 * precondition for merging, never a reason to: the token similarity still has to clear
 * the threshold, so identical wording about two unconnected parts does not merge.
 */
export function areRelated(
  a: DraftThreat,
  b: DraftThreat,
  flows: ReadonlyMap<string, FlowEnds>,
): boolean {
  if (a.componentIds.some((id) => b.componentIds.includes(id))) return true;
  if (a.dataFlowIds.some((id) => b.dataFlowIds.includes(id))) return true;
  const touches = (x: DraftThreat, y: DraftThreat) =>
    x.dataFlowIds.some((id) => {
      const flow = flows.get(id);
      return (
        flow !== undefined &&
        (y.componentIds.includes(flow.sourceId) ||
          y.componentIds.includes(flow.targetId))
      );
    });
  return touches(a, b) || touches(b, a);
}

/** Canonical form: arrays de-duplicated and sorted, so nothing depends on model order. */
export function normalizeThreat(t: DraftThreat): DraftThreat {
  return {
    ...t,
    stride: STRIDE_ORDER.filter((s) => t.stride.includes(s)),
    owasp: sortedUnique(t.owasp) as DraftThreat["owasp"],
    cwe: sortedUnique(t.cwe),
    componentIds: sortedUnique(t.componentIds),
    dataFlowIds: sortedUnique(t.dataFlowIds),
    evidenceIds: sortedUnique(t.evidenceIds),
    assumptions: sortedUnique(t.assumptions),
    dependsOnUnknownIds: sortedUnique(t.dependsOnUnknownIds),
  };
}

/** A total order over threats: element, category, then the whole record as a tiebreak. */
function orderKey(t: DraftThreat): [string, number, string] {
  const first = STRIDE_ORDER.findIndex((s) => t.stride.includes(s));
  return [elementIdsOf(t)[0] ?? "", first === -1 ? STRIDE_ORDER.length : first, JSON.stringify(t)];
}

export function compareThreats(a: DraftThreat, b: DraftThreat): number {
  const [ea, sa, ja] = orderKey(a);
  const [eb, sb, jb] = orderKey(b);
  return cmp(ea, eb) || sa - sb || cmp(ja, jb);
}

/**
 * Whether a threat cites at least one positive observation: not a control gap, an
 * inference or an assumption -- scoring's own test for `basis`, imported rather than
 * restated so the two cannot drift. Citing an id that is not in `evidence` counts as no
 * support at all.
 */
function isEvidenceBacked(
  t: DraftThreat,
  evidenceById: ReadonlyMap<string, Evidence>,
): boolean {
  return t.evidenceIds.some((id) => {
    const e = evidenceById.get(id);
    return e !== undefined && isPositiveObservation(e);
  });
}

/** The threat that speaks for a group: evidence-backed first, then the canonical order. */
function pickWinner(
  group: readonly DraftThreat[],
  evidenceById: ReadonlyMap<string, Evidence>,
): DraftThreat {
  return [...group].sort(
    (a, b) =>
      Number(isEvidenceBacked(b, evidenceById)) -
        Number(isEvidenceBacked(a, evidenceById)) || compareThreats(a, b),
  )[0];
}

/**
 * Merges a group into one threat. The winner's wording, mitigation and asset stand.
 * References, categories and mappings are the union of the group. Impact and likelihood
 * are the group's maximum, each with the reason written for that maximum (the winner's on
 * a tie), so a number is never left beside an explanation of a different one.
 */
function mergeGroup(
  group: readonly DraftThreat[],
  evidenceById: ReadonlyMap<string, Evidence>,
): DraftThreat {
  const winner = pickWinner(group, evidenceById);
  const ordered = [winner, ...group.filter((t) => t !== winner).sort(compareThreats)];
  const top = (key: "impact" | "likelihood") =>
    ordered.reduce((best, t) => (t[key] > best[key] ? t : best), ordered[0]);
  const impact = top("impact");
  const likelihood = top("likelihood");
  const union = <K extends keyof DraftThreat>(key: K) =>
    ordered.flatMap((t) => t[key] as unknown as string[]);

  return normalizeThreat({
    ...winner,
    stride: union("stride") as DraftThreat["stride"],
    owasp: union("owasp") as DraftThreat["owasp"],
    cwe: union("cwe"),
    componentIds: union("componentIds"),
    dataFlowIds: union("dataFlowIds"),
    evidenceIds: union("evidenceIds"),
    assumptions: union("assumptions"),
    dependsOnUnknownIds: union("dependsOnUnknownIds"),
    impact: impact.impact,
    impactReason: impact.impactReason,
    likelihood: likelihood.likelihood,
    likelihoodReason: likelihood.likelihoodReason,
  });
}

/**
 * Merges near-duplicate threats.
 *
 * Two threats are duplicates when their title-plus-scenario token sets have Jaccard
 * similarity of at least the threshold AND they are related (see areRelated): they share
 * a component or a flow, or one cites a flow that touches a component the other cites.
 * The relationship condition is what stops the same wording about two unconnected parts
 * of the system from collapsing into one threat that names neither properly.
 *
 * Duplicates are grouped by connected components over a canonically sorted list, not by
 * a running "merge into the first match", so the result does not depend on the order the
 * model returned threats in. The cost is that similarity is transitive: A~B and B~C group
 * A with C even if A and C alone would not match. That is deliberate; an order-dependent
 * answer is the worse failure.
 */
export function dedupeThreats(
  threats: readonly DraftThreat[],
  evidence: readonly Evidence[],
  flows: readonly FlowEnds[] = [],
  threshold: number = DEDUPE_THRESHOLD,
): DraftThreat[] {
  const evidenceById = new Map(evidence.map((e) => [e.id, e]));
  const flowById = new Map(flows.map((f) => [f.id, f]));
  const sorted = threats.map(normalizeThreat).sort(compareThreats);
  const words = sorted.map((t) => tokenize(similarityText(t)));

  const parent = sorted.map((_, i) => i);
  const find = (i: number): number => {
    while (parent[i] !== i) {
      parent[i] = parent[parent[i]];
      i = parent[i];
    }
    return i;
  };

  for (let i = 0; i < sorted.length; i++) {
    for (let j = i + 1; j < sorted.length; j++) {
      if (
        areRelated(sorted[i], sorted[j], flowById) &&
        jaccard(words[i], words[j]) >= threshold
      ) {
        parent[find(j)] = find(i);
      }
    }
  }

  const groups = new Map<number, DraftThreat[]>();
  sorted.forEach((t, i) => {
    const root = find(i);
    groups.set(root, [...(groups.get(root) ?? []), t]);
  });
  return [...groups.values()]
    .map((group) => (group.length === 1 ? group[0] : mergeGroup(group, evidenceById)))
    .sort(compareThreats);
}

// ---------------------------------------------------------------------------
// 5. Stable ids
// ---------------------------------------------------------------------------

/** threat-1, threat-2, ... in the canonical order. */
export function assignIds(threats: readonly DraftThreat[]): EngineThreat[] {
  return [...threats]
    .sort(compareThreats)
    .map((threat, index) => ({ ...threat, id: `threat-${index + 1}` }));
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

type BatchOutcome = {
  report: BatchReport;
  threats: DraftThreat[];
  limitations: string[];
  usage: CallUsage;
};

/**
 * Generates threats for a merged architecture.
 *
 * Fail-fast: any failed batch fails the run and no partial result is returned. A batch
 * that cannot be completed (validation failed twice, rate limit, timeout, transport, a
 * secret caught before sending) means the threat list would silently be missing that
 * batch's elements, and an incomplete list reads as "nothing found there". Batches
 * already in flight are allowed to finish, since the client offers no way to cancel a
 * call, but none is started after the first failure and their results are discarded.
 * The same holds once `input.shouldContinue` returns false (the pipeline's deadline or
 * cancel flag): no further batch starts, and the run throws TIMEOUT instead of returning.
 */
export async function generateThreats(
  input: ThreatEngineInput,
): Promise<ThreatEngineResult> {
  const { architecture } = input;
  const prompt = loadPrompt(
    THREATS_PROMPT_NAME,
    THREATS_PROMPT_VERSION,
    input.promptDir,
  );
  const batches = (input.batches ?? batchElements(architecture)).map((b) => [...b]);
  const knownPaths = new Set([
    ...(input.routePaths ?? []),
    ...input.gaps.flatMap((g) => (g.routePath === undefined ? [] : [g.routePath])),
  ]);

  const outcomes = await runPool(
    batches,
    input.concurrency ?? THREATS_CONCURRENCY,
    async (elementIds, index): Promise<BatchOutcome> => {
      const batch = buildThreatBatch({
        architecture,
        gaps: input.gaps,
        elementIds,
        files: input.files,
        budgetTokens: input.budgetTokens ?? THREATS_CONTEXT_TOKENS,
      });

      // Fail closed: nothing is sent if the payload still holds a credential.
      assertBatchClean(batch);

      const { value, usage } = await callStructured({
        stage: "stride",
        system: prompt.text,
        user: batch.text,
        schema: ThreatBatchResponseSchema,
        jsonSchema: threatBatchJsonSchema,
        maxTokens: input.maxTokens ?? THREATS_MAX_TOKENS,
        timeoutMs: THREATS_TIMEOUT_MS,
        // Reasoning tokens count against max_tokens, and on a live two-element batch they
        // used all 12,000 of them and left none for the JSON. Off for threat calls only;
        // the output limit and the prompt are unchanged.
        thinking: THREATS_THINKING,
        // One dump per batch and attempt in development: batches no longer overwrite each other.
        dumpKey: `b${String(index).padStart(2, "0")}`,
        analysisId: input.analysisId,
        deps: input.deps,
      });

      const offered = offeredBy(batch);
      const gapRoutes = gapRouteByEvidenceId(batch);
      const kept: DraftThreat[] = [];
      const limitations: string[] = [];
      for (const returned of value.threats) {
        // Before reference validation, so a threat left with no support is dropped by the
        // existing "cites no evidence and states no assumption" rule.
        const { threat, removed } = stripCrossRouteGapCitations(returned, gapRoutes, knownPaths);
        for (const r of removed) limitations.push(describeRemovedCitation(threat, index, r));
        const issues = referenceIssues(threat, architecture, offered);
        if (issues.length === 0) kept.push(threat);
        else limitations.push(describeDrop(threat, index, issues));
      }
      for (const id of batch.unresolvedIds) {
        limitations.push(`Batch ${index + 1} named unknown element ${id}.`);
      }
      return {
        report: { index, elementIds, returned: value.threats.length },
        threats: kept,
        limitations: limitations.sort(cmp),
        usage,
      };
    },
    input.shouldContinue,
  ).catch((cause: unknown) => {
    // Some batches never ran: fail closed, never return a partial threat list.
    if (cause instanceof PoolStoppedError) {
      throw new AiError("TIMEOUT", `stride: stopped before all batches started (${cause.message})`, {
        cause,
      });
    }
    throw cause;
  });

  const evidence = architecture.evidence;
  const threats = assignIds(
    dedupeThreats(
      outcomes.flatMap((o) => o.threats),
      evidence,
      architecture.dataFlows,
    ),
  );

  const cited = new Set(threats.flatMap((t) => t.evidenceIds));
  return {
    threats,
    evidence: evidence.filter((e) => cited.has(e.id)),
    limitations: outcomes.flatMap((o) => o.limitations),
    batches: outcomes.map((o) => o.report),
    usage: outcomes.map((o) => o.usage),
    promptId: prompt.id,
  };
}
