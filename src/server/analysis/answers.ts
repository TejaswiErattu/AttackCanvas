/**
 * Applies developer answers (Prompt M's questions, answered) to a ThreatModel.
 *
 * selectQuestions (src/server/questions) picked at most 3 questions and precomputed, per
 * option, exactly what answering it does to a threat -- the `QuestionEffects` sidecar map.
 * This module is the other half: given the developer's actual answers, it looks up each
 * effect, edits evidence and assumptions on the affected threats only, and re-scores them
 * with src/server/scoring (never reinventing that math, per CLAUDE.md rule 2).
 *
 * Every question in the model ends up either answered or defaulted: one with no usable
 * answer -- omitted, answered with conflicting values, or "answered" with a missing or
 * out-of-range option -- takes exactly the cautious skip/unsure default an explicit
 * "skipped" gets, so no way of (not) answering can look safer than skipping.
 *
 * A threat not named in any of the model's questions' `affectedThreatIds` is untouched --
 * same object, not just equal value -- so its confidence is provably unchanged.
 */

import { dedupe, note, userLimitations, type Note } from "@/server/analysis/limitations";
import { normalizeThreat } from "@/server/analysis/threats";
import type { QuestionEffects } from "@/server/questions";
import type { ControlGap } from "@/server/detect/types";
import { scoreThreat } from "@/server/scoring";
import { gapEvidenceId } from "@/server/analysis/context";
import type {
  DeveloperQuestion,
  DraftThreat,
  Evidence,
  Threat,
  ThreatModel,
} from "@/shared/schema";

// ---------------------------------------------------------------------------
// Public shape
// ---------------------------------------------------------------------------

export type AnswerStatus = "answered" | "skipped" | "unsure";

export type DeveloperAnswer = {
  questionId: string;
  status: AnswerStatus;
  /** Index into the question's `options`. Required, and must be in range, when `status` is "answered". */
  optionIndex?: number;
};

export type ApplyAnswersInput = {
  model: ThreatModel;
  /** questions.v1's sidecar: one entry per question in `model.questions`. */
  effects: ReadonlyMap<string, QuestionEffects>;
  /** The same gaps the analysis bound, so a gap-derived question can find its gap's evidence id. */
  gaps: readonly ControlGap[];
  answers: readonly DeveloperAnswer[];
};

export type ApplyAnswersResult = {
  model: ThreatModel;
  /**
   * Diagnostics produced while applying answers (a dropped threat, a bad answer), with
   * question and threat ids. The model's own `limitations` gains only the reader-facing
   * sentences built from `notes` (src/server/analysis/limitations.ts).
   */
  limitations: string[];
  notes: Note[];
};

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function clampScore(n: number): number {
  return Math.min(5, Math.max(1, n));
}

/**
 * True when an assumption's text names `unknownId` as a whole token, e.g. "per the
 * unknown-csp-header unknown". This is how an assumption is tied to the question that
 * resolves it without a schema link (CLAUDE.md rule 1): an answered question's unknownId
 * is matched against the text, and "unknown-csp" never matches "unknown-csp-header".
 * An assumption that paraphrases the unknown without its id is not recognised and keeps
 * its -0.15; the prompt tells the model to put unknowns in dependsOnUnknownIds instead.
 */
export function namesUnknown(text: string, unknownId: string): boolean {
  const escaped = unknownId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![\\w-])${escaped}(?![\\w-])`).test(text);
}

/** Folds one option's deltas, and the reason for any it moves, into `changes`. */
function addEffect(changes: ThreatChanges, effect: QuestionEffects["default"], via: string): void {
  changes.deltaImpact += effect.impactDelta;
  changes.deltaLikelihood += effect.likelihoodDelta;
  const note = `${via}: ${effect.reason ?? "applied the option's effect"}`;
  if (effect.likelihoodDelta !== 0) changes.likelihoodReasons.push(note);
  if (effect.impactDelta !== 0) changes.impactReasons.push(note);
}

/** `reason` with each note appended, or `reason` itself when there are none. */
function withNotes(reason: string, notes: readonly string[]): string {
  return notes.length === 0 ? reason : `${reason} Answer applied: ${notes.join("; ")}.`;
}

function answerEvidenceId(questionId: string): string {
  return `ev-answer-${questionId}`;
}

// ---------------------------------------------------------------------------
// Per-threat accumulation
// ---------------------------------------------------------------------------

/** Everything the answered or defaulted questions do to one threat, gathered before anything is applied. */
type ThreatChanges = {
  addEvidenceIds: Set<string>;
  removeEvidenceIds: Set<string>;
  addAssumptions: string[];
  /** Unknown ids an applied (not skipped) answer resolved; assumptions naming them are dropped. */
  resolvedUnknownIds: Set<string>;
  deltaImpact: number;
  deltaLikelihood: number;
  /** Effect reasons for the score(s) an answer moved, appended to the threat's reason fields. */
  likelihoodReasons: string[];
  impactReasons: string[];
};

function newChanges(): ThreatChanges {
  return {
    addEvidenceIds: new Set(),
    removeEvidenceIds: new Set(),
    addAssumptions: [],
    resolvedUnknownIds: new Set(),
    deltaImpact: 0,
    deltaLikelihood: 0,
    likelihoodReasons: [],
    impactReasons: [],
  };
}

function changesFor(
  byThreatId: Map<string, ThreatChanges>,
  threatId: string,
): ThreatChanges {
  const existing = byThreatId.get(threatId);
  if (existing) return existing;
  const created = newChanges();
  byThreatId.set(threatId, created);
  return created;
}

/**
 * Folds one answered question into `byThreatId` and `newEvidence`. Handles the "answered"
 * path: a developer_answer Evidence item, the option's deltas, and the certaintyResolution
 * gate on a gap-derived question:
 *   - `confirms_gap` / `no_change`: the developer_answer is cited by the threat, so it
 *     earns its `+0.30` (plus `+0.10` second-source when it lands beside the gap).
 *   - `clears_gap`: the answer says the control IS there, which clears the gap rather than
 *     supporting the threat, so it is never cited -- only the gap evidence id is removed
 *     and the deltas applied. Citing it here would let "the control is present" inflate
 *     confidence that a vulnerability exists, the opposite of what the answer says. The
 *     Evidence item is still recorded in `newEvidence` for the audit trail; it simply ends
 *     up cited by nothing and is dropped from the final model like any other uncited item.
 *
 * Returns false, having applied nothing, when `optionIndex` names no option; the caller
 * then applies the skip default instead.
 */
function applyAnswered(
  question: DeveloperQuestion,
  effect: QuestionEffects,
  optionIndex: number,
  gapById: ReadonlyMap<string, ControlGap>,
  byThreatId: Map<string, ThreatChanges>,
  newEvidence: Map<string, Evidence>,
  limitations: Note[],
): boolean {
  const optionEffect = effect.options[optionIndex];
  if (!optionEffect) {
    limitations.push(note("answer_not_applied", `Answer to "${question.id}" named option ${optionIndex}, which the question does not have; it was treated as skipped.`),
    );
    return false;
  }

  const evidenceId = answerEvidenceId(question.id);
  const chosen = question.options[optionIndex];
  newEvidence.set(evidenceId, {
    id: evidenceId,
    kind: "developer_answer",
    source: "developer",
    summary: `Developer: ${question.text} -> ${chosen}`,
  });

  const clearsGap = optionEffect.certaintyResolution === "clears_gap";
  const gap = effect.gapId ? gapById.get(effect.gapId) : undefined;

  for (const threatId of effect.appliesToThreatIds) {
    const changes = changesFor(byThreatId, threatId);
    changes.resolvedUnknownIds.add(question.unknownId);
    if (!clearsGap) changes.addEvidenceIds.add(evidenceId);
    addEffect(changes, optionEffect, `"${chosen}"`);
    if (clearsGap && gap) {
      changes.removeEvidenceIds.add(gapEvidenceId(gap));
    }
  }
  return true;
}

/**
 * Folds one skipped or "unsure" question into `byThreatId`: the precomputed cautious
 * default's deltas apply, and `defaultAssumption` is recorded -- no evidence is added and
 * any gap evidence already cited is left exactly where it is.
 */
function applyDefaulted(
  question: DeveloperQuestion,
  effect: QuestionEffects,
  byThreatId: Map<string, ThreatChanges>,
): void {
  for (const threatId of effect.appliesToThreatIds) {
    const changes = changesFor(byThreatId, threatId);
    changes.addAssumptions.push(question.defaultAssumption);
    addEffect(changes, effect.default, "no answer");
  }
}

// ---------------------------------------------------------------------------
// applyAnswers
// ---------------------------------------------------------------------------

/** Value equality for two answers to the same question: status and chosen option, nothing else. */
function sameAnswer(a: DeveloperAnswer, b: DeveloperAnswer): boolean {
  return a.status === b.status && a.optionIndex === b.optionIndex;
}

/**
 * `group`'s distinct answers by VALUE (status + optionIndex), in first-occurrence order.
 * N copies of the exact same answer collapse to one entry; two answers that differ in
 * status or optionIndex are two entries. Object identity never matters -- only what the
 * answer says.
 */
function distinctAnswers(group: readonly DeveloperAnswer[]): DeveloperAnswer[] {
  const distinct: DeveloperAnswer[] = [];
  for (const answer of group) {
    if (!distinct.some((d) => sameAnswer(d, answer))) distinct.push(answer);
  }
  return distinct;
}

/**
 * Groups `answers` by questionId and resolves each group to at most one canonical answer,
 * order-independently:
 *   - every copy in the group is the same answer (by value): applied once, however many
 *     copies were given;
 *   - the group holds two or more genuinely different answers (differing status or
 *     optionIndex, however many copies of each): a real conflict. None of the answers is
 *     resolved -- applyAnswers gives that question the skip default instead, like any
 *     question left without a usable answer -- and exactly one limitation is recorded.
 *
 * Question ids are visited in sorted order and the result Map is built in that order, so
 * which questions resolve, which conflict, and what the conflict limitations say depend
 * only on the SET of question ids and answer values present in `answers` -- never on the
 * order `answers` lists them in. `limitations` receives one entry per conflicting group,
 * already in the sort-stable order the caller will sort again with everything else.
 */
function resolveAnswers(
  answers: readonly DeveloperAnswer[],
  limitations: Note[],
): Map<string, DeveloperAnswer> {
  // push, not a re-spread per answer: re-copying the group each time was quadratic in
  // the number of answers sharing a questionId.
  const groups = new Map<string, DeveloperAnswer[]>();
  for (const answer of answers) {
    const group = groups.get(answer.questionId);
    if (group) group.push(answer);
    else groups.set(answer.questionId, [answer]);
  }

  const resolved = new Map<string, DeveloperAnswer>();
  for (const questionId of [...groups.keys()].sort(cmp)) {
    const distinct = distinctAnswers(groups.get(questionId)!);
    if (distinct.length === 1) {
      resolved.set(questionId, distinct[0]);
      continue;
    }
    limitations.push(note("answer_not_applied", `Answer to "${questionId}" was ignored: ${distinct.length} conflicting answers were given for it; it was treated as skipped.`),
    );
  }
  return resolved;
}

export function applyAnswers(input: ApplyAnswersInput): ApplyAnswersResult {
  const { model } = input;
  const questionsById = new Map(model.questions.map((q) => [q.id, q]));
  const gapById = new Map(input.gaps.map((g) => [g.id, g]));
  const gapByEvidenceId = new Map(
    input.gaps.map((g) => [gapEvidenceId(g), g] as const),
  );

  const limitations: Note[] = [];
  const byThreatId = new Map<string, ThreatChanges>();
  const newEvidence = new Map<string, Evidence>();
  /** Questions this call already applied an answer or a default to (or reported). */
  const handled = new Set<string>();

  for (const answer of resolveAnswers(input.answers, limitations).values()) {
    const question = questionsById.get(answer.questionId);
    if (!question) {
      limitations.push(note("internal", `Answer to unknown question "${answer.questionId}" was ignored.`),
      );
      continue;
    }
    handled.add(question.id);
    const effect = input.effects.get(answer.questionId);
    if (!effect) {
      limitations.push(note("internal", `Answer to "${answer.questionId}" was ignored: no QuestionEffects entry for it.`),
      );
      continue;
    }

    if (answer.status === "answered") {
      if (answer.optionIndex === undefined) {
        limitations.push(note("answer_not_applied", `Answer to "${question.id}" was marked "answered" with no option chosen; it was treated as skipped.`),
        );
        applyDefaulted(question, effect, byThreatId);
        continue;
      }
      const applied = applyAnswered(
        question,
        effect,
        answer.optionIndex,
        gapById,
        byThreatId,
        newEvidence,
        limitations,
      );
      if (!applied) applyDefaulted(question, effect, byThreatId);
    } else {
      applyDefaulted(question, effect, byThreatId);
    }
  }

  // Every question still without an applied answer -- omitted from `answers`, or given
  // only conflicting ones (resolveAnswers already recorded why) -- takes the same cautious
  // default an explicit "skipped" does. Skipping it entirely would leave its threats
  // looking safer than a skip: no default assumption, none of the default's deltas.
  const answeredIds = new Set(input.answers.map((a) => a.questionId));
  for (const question of model.questions) {
    if (handled.has(question.id)) continue;
    const effect = input.effects.get(question.id);
    if (!effect) {
      limitations.push(note("internal", `Question "${question.id}" got no usable answer and has no QuestionEffects entry; nothing was applied.`),
      );
      continue;
    }
    applyDefaulted(question, effect, byThreatId);
    if (!answeredIds.has(question.id)) {
      limitations.push(note("internal", `No answer was given for "${question.id}"; it was treated as skipped.`));
    }
  }

  // Evidence available for re-scoring: everything the model already had, plus this
  // call's new developer_answer items. Existing ids always win on a collision, since a
  // developer_answer id is derived from the question id and never coined twice.
  const evidenceById = new Map(model.evidence.map((e) => [e.id, e]));
  for (const [id, e] of newEvidence) {
    if (!evidenceById.has(id)) evidenceById.set(id, e);
  }
  const evidencePool = [...evidenceById.values()];

  const droppedThreatIds = new Set<string>();
  const threats: Threat[] = [];

  for (const threat of model.threats) {
    const changes = byThreatId.get(threat.id);
    if (!changes) {
      // Not named by any question that was answered or defaulted: untouched, same reference.
      threats.push(threat);
      continue;
    }

    const evidenceIds = [
      ...threat.evidenceIds.filter((id) => !changes.removeEvidenceIds.has(id)),
      ...changes.addEvidenceIds,
    ];
    const assumptions = [
      ...threat.assumptions.filter(
        (text) => ![...changes.resolvedUnknownIds].some((id) => namesUnknown(text, id)),
      ),
      ...changes.addAssumptions,
    ];

    if (evidenceIds.length === 0 && assumptions.length === 0) {
      droppedThreatIds.add(threat.id);
      limitations.push(note("threat_ruled_out_by_answer", `Dropped threat "${threat.title}" (${threat.id}): a developer answer cleared its only evidence and assumptions.`, threat.title),
      );
      continue;
    }

    // Named field-by-field rather than `{ ...threat }` with the scored fields destructured
    // away: DraftThreat is exactly ThreatSchema.omit(the scored fields), so listing what a
    // draft actually carries reads directly against that contract instead of naming five
    // fields we do NOT want.
    const draft: DraftThreat = normalizeThreat({
      title: threat.title,
      stride: threat.stride,
      owasp: threat.owasp,
      cwe: threat.cwe,
      componentIds: threat.componentIds,
      dataFlowIds: threat.dataFlowIds,
      asset: threat.asset,
      attackScenario: threat.attackScenario,
      dependsOnUnknownIds: threat.dependsOnUnknownIds,
      impactReason: withNotes(threat.impactReason, changes.impactReasons),
      likelihoodReason: withNotes(threat.likelihoodReason, changes.likelihoodReasons),
      mitigation: threat.mitigation,
      evidenceIds,
      assumptions,
      impact: clampScore(threat.impact + changes.deltaImpact),
      likelihood: clampScore(threat.likelihood + changes.deltaLikelihood),
    });
    threats.push(scoreThreat(draft, threat.id, evidencePool, gapByEvidenceId).threat);
  }

  // Kept in the final evidence array: everything still cited by a surviving threat, plus
  // every developer_answer item this call minted -- including a clears_gap one, which is
  // cited by nothing (see applyAnswered) but stays for the audit trail of what was asked
  // and answered. Anything else uncited (typically a gap evidence id a clears_gap answer
  // just removed, with nothing left citing it) is dropped, same as assemble.ts.
  const citedEvidenceIds = new Set(threats.flatMap((t) => t.evidenceIds));
  const keptEvidenceIds = new Set([...citedEvidenceIds, ...newEvidence.keys()]);
  const evidence = evidencePool
    .filter((e) => keptEvidenceIds.has(e.id))
    .sort((a, b) => cmp(a.id, b.id));

  const remainingThreatIds = new Set(threats.map((t) => t.id));
  const questions =
    droppedThreatIds.size === 0
      ? model.questions
      : model.questions.map((q) => ({
          ...q,
          affectedThreatIds: q.affectedThreatIds.filter((id) =>
            remainingThreatIds.has(id),
          ),
        }));

  // Sorted so the result never depends on `input.answers`' order or on `model.threats`'
  // iteration order for a drop -- two calls over logically identical input, differently
  // ordered, produce byte-identical limitations.
  const sorted = [...limitations].sort((a, b) => cmp(a.detail, b.detail));
  const sortedLimitations = sorted.map((n) => n.detail);

  return {
    model: {
      ...model,
      threats,
      evidence,
      questions,
      // Reader-facing sentences only; the diagnostic lines are returned separately.
      limitations: dedupe([...model.limitations, ...userLimitations(sorted)]),
    },
    limitations: sortedLimitations,
    notes: sorted,
  };
}
