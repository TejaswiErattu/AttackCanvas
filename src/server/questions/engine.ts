/**
 * Pure logic for developer question selection (Prompt M). Nothing here calls the model
 * or does I/O -- src/server/questions/index.ts is the orchestrator that wraps this with
 * the callStructured call. Splitting it out lets each ranking factor, the linking rule,
 * and the fact-based drop be tested directly, without assembling a whole
 * SelectQuestionsInput per case.
 *
 * CLAUDE.md rule 2: severity, confidence and priority are computed in src/server/scoring,
 * never by a model. The value formula below is the same discipline applied to which
 * questions get asked -- the model only ever words the (at most 3) survivors.
 */

import type { Component } from "@/shared/schema";
import type { EvidenceKind, Severity, Threat, Unknown } from "@/shared/schema";
import type { ControlGap, Deployment } from "@/server/detect/types";

// ---------------------------------------------------------------------------
// Knobs
// ---------------------------------------------------------------------------

/** At most this many questions are ever selected. */
export const MAX_QUESTIONS = 3;

/** A candidate whose raw value is below this is not worth a developer's time. */
export const MIN_VALUE = 1.5;

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * gapUnknowns (src/server/analysis/architecture.ts) mints a gap-derived unknown's id as
 * `unknown-${gap.id}`, de-duplicated with a `-2`, `-3`, ... suffix via uniqueId. Matching
 * that shape is how this module tells a gap-derived unknown from a model-authored one,
 * since MergedArchitecture keeps no separate flag. If that id convention ever changes,
 * this regex must change with it.
 */
const GAP_UNKNOWN_ID = /^unknown-(gap-\d+)(?:-\d+)?$/;

/** The gap behind a gap-derived unknown id, or undefined for a model-authored one. */
export function gapFor(
  unknownId: string,
  gaps: readonly ControlGap[],
): ControlGap | undefined {
  const match = GAP_UNKNOWN_ID.exec(unknownId);
  if (!match) return undefined;
  return gaps.find((g) => g.id === match[1]);
}

// ---------------------------------------------------------------------------
// 1. Linking: which threats an unknown affects
// ---------------------------------------------------------------------------

export type LinkedUnknown = {
  unknown: Unknown;
  /** Threats that name this unknown in `dependsOnUnknownIds`. Sorted. */
  dependentThreatIds: string[];
  /**
   * Sorted union of `dependentThreatIds` and threats on a component this unknown
   * affects (`Threat.componentIds` intersects `Unknown.affectsComponentIds`).
   */
  affectedThreatIds: string[];
};

/**
 * For each unknown, the threats that depend on it directly plus the threats on a
 * component it affects. A threat that only shares a component (not a direct
 * `dependsOnUnknownIds` reference) still counts toward whether the unknown is worth
 * asking about, but NOT toward which threats an answer is allowed to re-score --
 * that distinction is why both id lists are returned. See
 * src/server/questions/index.ts's `QuestionEffects.appliesToThreatIds`.
 */
export function linkUnknowns(
  unknowns: readonly Unknown[],
  threats: readonly Threat[],
): LinkedUnknown[] {
  return unknowns.map((unknown): LinkedUnknown => {
    const dependent = threats.filter((t) =>
      t.dependsOnUnknownIds.includes(unknown.id),
    );
    const dependentThreatIds = [...dependent.map((t) => t.id)].sort(cmp);
    const componentLinked = threats.filter(
      (t) =>
        !t.dependsOnUnknownIds.includes(unknown.id) &&
        t.componentIds.some((id) => unknown.affectsComponentIds.includes(id)),
    );
    const affectedThreatIds = [
      ...new Set([...dependentThreatIds, ...componentLinked.map((t) => t.id)]),
    ].sort(cmp);
    return { unknown, dependentThreatIds, affectedThreatIds };
  });
}

// ---------------------------------------------------------------------------
// 2. Dropping unknowns the repository's own facts already answer
// ---------------------------------------------------------------------------

/**
 * Wording that marks an unknown as being about whether something is exposed/reachable.
 * Narrow on purpose: the only exposure fact the detectors carry today is Compose's
 * published ports (src/server/detect/deployment.ts), so this only ever fires for that.
 */
const EXPOSURE_WORDING = /\b(expos\w*|reachable|publicl\w*|internet|internal network)\b/i;

function normalizeServiceName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

/**
 * True when `unknown` asks about exposure and deployment facts already show every
 * component it affects is a Compose service with no published host port -- i.e.
 * reachable only on the internal Compose network. Conservative: any component that
 * cannot be matched by normalized name to a Compose service, or that has one, keeps
 * the unknown (returns false). Written as a single rule rather than a table because
 * there is exactly one fact of this kind today; more can be added the same way.
 */
export function answeredByFacts(
  unknown: Unknown,
  components: readonly Component[],
  deployment: readonly Deployment[],
): boolean {
  if (unknown.affectsComponentIds.length === 0) return false;
  if (!EXPOSURE_WORDING.test(unknown.description)) return false;

  const nameById = new Map(components.map((c) => [c.id, normalizeServiceName(c.name)]));
  const composeByName = new Map(
    deployment
      .filter((d) => d.kind === "compose")
      .map((d) => [normalizeServiceName(d.name), d] as const),
  );

  return unknown.affectsComponentIds.every((componentId) => {
    const name = nameById.get(componentId);
    if (!name) return false;
    const service = composeByName.get(name);
    return service !== undefined && service.ports.length === 0;
  });
}

// ---------------------------------------------------------------------------
// 3. The value formula (pure ranking)
// ---------------------------------------------------------------------------

/** max severity among `threats`, mapped to a weight; 0 when `threats` is empty. */
export function severityWeightOf(threats: readonly Threat[]): number {
  return threats.reduce(
    (best, t) => Math.max(best, SEVERITY_WEIGHT[t.severity]),
    0,
  );
}

/** 1 - mean confidence of `threats`; 0 when `threats` is empty (no reach, no uncertainty to resolve). */
export function uncertaintyWeightOf(threats: readonly Threat[]): number {
  if (threats.length === 0) return 0;
  const mean = threats.reduce((sum, t) => sum + t.confidence, 0) / threats.length;
  return 1 - mean;
}

/**
 * `value = maxSeverityWeight * uncertainty * log2(1 + affectedCount)`, exactly as
 * specified. Raw and unbounded above (unlike the old formula, this is not clamped to
 * [0, 1]) -- MIN_VALUE and the cap of MAX_QUESTIONS are what keep it meaningful, and
 * `toStoredValueScore` below is what fits it into the frozen 0..1 contract field.
 */
export function valueOf(affected: readonly Threat[]): number {
  if (affected.length === 0) return 0;
  return (
    severityWeightOf(affected) *
    uncertaintyWeightOf(affected) *
    Math.log2(1 + affected.length)
  );
}

/** Whether a candidate clears the bar to be worth asking about: raw value >= MIN_VALUE. */
export function qualifiesForQuestion(valueScore: number): boolean {
  return valueScore >= MIN_VALUE;
}

/**
 * Fits an unbounded raw value into `DeveloperQuestion.valueScore`'s frozen 0..1 range
 * (src/shared/schema/question.ts). 8 is a generous ceiling: the highest realistic raw
 * value is critical (4) * full uncertainty (1) * log2(1 + a handful of threats), well
 * under 8 for any question that actually gets asked (capped at MAX_QUESTIONS = 3
 * winners, each usually citing a small number of threats).
 */
const VALUE_SCORE_CEILING = 8;

export function toStoredValueScore(raw: number): number {
  return Math.min(1, Math.max(0, raw / VALUE_SCORE_CEILING));
}

export type Candidate = {
  unknown: Unknown;
  /** The gap behind this unknown, when it is gap-derived. */
  gap?: ControlGap;
  /** dependsOnUnknownIds threats union component-linked threats. Sorted. */
  affectedThreatIds: string[];
  /** dependsOnUnknownIds threats only. Sorted. What an answer is allowed to re-score. */
  dependentThreatIds: string[];
  /** Raw value formula output -- NOT clamped to 0..1. See toStoredValueScore. */
  valueScore: number;
};

/**
 * Ranks every unknown by raw valueScore, highest first, ties broken by unknown id so
 * the order never depends on input order. Pure: no model, no I/O, no threshold or cap
 * applied -- callers filter with qualifiesForQuestion and slice to MAX_QUESTIONS
 * themselves (src/server/questions/index.ts does, after also dropping unknowns facts
 * already answer).
 */
export function rankCandidates(
  unknowns: readonly Unknown[],
  threats: readonly Threat[],
  gaps: readonly ControlGap[],
): Candidate[] {
  const linked = linkUnknowns(unknowns, threats);
  const byId = new Map(threats.map((t) => [t.id, t]));
  const candidates = linked.map(({ unknown, dependentThreatIds, affectedThreatIds }): Candidate => {
    const affected = affectedThreatIds
      .map((id) => byId.get(id))
      .filter((t): t is Threat => t !== undefined);
    return {
      unknown,
      gap: gapFor(unknown.id, gaps),
      affectedThreatIds,
      dependentThreatIds,
      valueScore: valueOf(affected),
    };
  });
  return candidates.sort(
    (a, b) => b.valueScore - a.valueScore || cmp(a.unknown.id, b.unknown.id),
  );
}

// ---------------------------------------------------------------------------
// 4. Skip bookkeeping
// ---------------------------------------------------------------------------

export type SkipReason =
  | "no_affected_threats"
  | "answered_by_facts"
  | "below_threshold"
  | "over_cap"
  | "no_usable_draft"
  | "no_cautious_default";

export type SkippedReason = {
  unknownId: string;
  reason: SkipReason;
  detail?: string;
};

/**
 * Runs the full selection pipeline short of the model call: rank, drop unknowns with no
 * affected threats, drop unknowns facts already answer, drop below MIN_VALUE, cap at
 * MAX_QUESTIONS. Every drop is recorded in `skipped`, in the order the candidate would
 * otherwise have ranked.
 */
export function selectCandidates(
  unknowns: readonly Unknown[],
  threats: readonly Threat[],
  gaps: readonly ControlGap[],
  components: readonly Component[],
  deployment: readonly Deployment[],
): { winners: Candidate[]; skipped: SkippedReason[] } {
  const ranked = rankCandidates(unknowns, threats, gaps);
  const skipped: SkippedReason[] = [];
  const eligible: Candidate[] = [];

  for (const candidate of ranked) {
    if (candidate.affectedThreatIds.length === 0) {
      skipped.push({ unknownId: candidate.unknown.id, reason: "no_affected_threats" });
      continue;
    }
    if (answeredByFacts(candidate.unknown, components, deployment)) {
      skipped.push({ unknownId: candidate.unknown.id, reason: "answered_by_facts" });
      continue;
    }
    if (!qualifiesForQuestion(candidate.valueScore)) {
      skipped.push({ unknownId: candidate.unknown.id, reason: "below_threshold" });
      continue;
    }
    eligible.push(candidate);
  }

  const winners = eligible.slice(0, MAX_QUESTIONS);
  for (const dropped of eligible.slice(MAX_QUESTIONS)) {
    skipped.push({ unknownId: dropped.unknown.id, reason: "over_cap" });
  }
  return { winners, skipped };
}

// ---------------------------------------------------------------------------
// 5. Precomputed option effects (unchanged formula from the original build)
// ---------------------------------------------------------------------------

export type OptionMeaning =
  | "control_absent"
  | "control_present"
  | "partial"
  | "not_applicable";

export const OPTION_MEANINGS: readonly OptionMeaning[] = [
  "control_absent",
  "control_present",
  "partial",
  "not_applicable",
];

export type CertaintyResolution = "confirms_gap" | "clears_gap" | "no_change";

export type OptionEffect = {
  /** Index into the question's `options`, or -1 for the skip/unsure default. */
  optionIndex: number;
  likelihoodDelta: number;
  impactDelta: number;
  addsEvidenceKind: EvidenceKind;
  certaintyResolution: CertaintyResolution;
  /**
   * Why the deltas apply, in words -- appended to a threat's likelihoodReason /
   * impactReason when an answer moves that score (src/server/analysis/answers.ts).
   * Fixed text from MEANING_EFFECT, never model-written.
   */
  reason?: string;
};

type MeaningEffect = {
  likelihoodDelta: number;
  impactDelta: number;
  resolution: CertaintyResolution;
  reason: string;
};

/**
 * What each option meaning does to a threat, before the gap-derived/no_change gate below.
 * `control_absent` raises likelihood (the worrying condition is confirmed); `control_present`
 * and `not_applicable` lower risk; `partial` changes nothing on its own.
 */
export const MEANING_EFFECT: Record<OptionMeaning, MeaningEffect> = {
  control_absent: {
    likelihoodDelta: 1,
    impactDelta: 0,
    resolution: "confirms_gap",
    reason: "the developer confirmed the control is absent",
  },
  control_present: {
    likelihoodDelta: -1,
    impactDelta: 0,
    resolution: "clears_gap",
    reason: "the developer confirmed a control is in place",
  },
  partial: {
    likelihoodDelta: 0,
    impactDelta: 0,
    resolution: "no_change",
    reason: "the developer described a partial control",
  },
  not_applicable: {
    likelihoodDelta: -1,
    impactDelta: -1,
    resolution: "clears_gap",
    reason: "the developer said the exposure does not apply",
  },
};

/**
 * One OptionEffect per meaning, index-aligned. `certaintyResolution` is only ever
 * `confirms_gap` or `clears_gap` for a gap-derived question -- there is no gap for a
 * model-authored question's answer to confirm or clear, so every option there resolves
 * to `no_change`.
 */
export function effectsFor(
  meanings: readonly OptionMeaning[],
  isGapDerived: boolean,
): OptionEffect[] {
  return meanings.map((meaning, optionIndex) => {
    const base = MEANING_EFFECT[meaning];
    return {
      optionIndex,
      likelihoodDelta: base.likelihoodDelta,
      impactDelta: base.impactDelta,
      addsEvidenceKind: "developer_answer",
      certaintyResolution: isGapDerived ? base.resolution : "no_change",
      reason: base.reason,
    };
  });
}

/** likelihoodDelta + impactDelta: positive means the option would raise combined risk. */
export function combinedDelta(o: OptionEffect): number {
  return o.likelihoodDelta + o.impactDelta;
}

/**
 * CAUTIOUS DEFAULTS. Applied on skip or "unsure"; must never make results look safer
 * than they are.
 *
 * The default is always a REAL option's effect, exactly as effectsFor computed it from
 * the fixed meaning table -- never an invented or zeroed-out one. Among the options whose
 * combined delta is >= 0 (an option that would only ever raise or hold risk, never lower
 * it), the one whose resolution is `confirms_gap` -- the gap standing -- is preferred
 * when one exists, since that is the most conservative reading of "the developer did not
 * say the control is there". Failing that, the eligible option with the greatest
 * combined delta wins, ties broken by option index so the choice is deterministic.
 *
 * When NO option's combined delta is >= 0 -- every real answer to this question would
 * read as safer than doing nothing -- there is no cautious default to give. Returns
 * undefined, and the caller drops the whole question rather than defaulting to
 * something unsafe.
 */
export function defaultEffectFor(
  options: readonly OptionEffect[],
): OptionEffect | undefined {
  const eligible = options.filter((o) => combinedDelta(o) >= 0);
  if (eligible.length === 0) return undefined;

  const gapStanding = eligible.filter((o) => o.certaintyResolution === "confirms_gap");
  const pool = gapStanding.length > 0 ? gapStanding : eligible;
  const winner = pool.reduce((top, o) => (combinedDelta(o) > combinedDelta(top) ? o : top));

  // `addsEvidenceKind` is "assumption", not "developer_answer": a skip is not an answer,
  // and "assumption" is the one EvidenceKind scoring/index.ts already treats as never
  // making a threat evidence_backed (isPositive excludes it). Everything else -- the
  // deltas and the resolution -- is copied unchanged from the real winning option.
  return {
    ...winner,
    optionIndex: -1,
    addsEvidenceKind: "assumption",
    reason: "the developer skipped or was unsure, so the cautious default applies",
  };
}
