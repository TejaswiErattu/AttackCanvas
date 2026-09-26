/**
 * Developer question selection (Prompt M).
 *
 * Everything upstream is deterministic except the wording: mergeArchitecture (Prompt N2)
 * produced up to 12 Unknowns, and the threat engine (Prompt P2) plus scoring gave every
 * threat a `dependsOnUnknownIds` list and a scored `confidence`. This module decides
 * which of those Unknowns are worth asking about, ranks them by how much an answer would
 * sharpen the model, and asks Prompt M for wording only. The value formula, the ranking,
 * the cap of three, and what each answer option DOES to a threat are all pure code
 * (CLAUDE.md rule 2) and live in src/server/questions/engine.ts; the model never sees or
 * influences a number.
 *
 * `DeveloperQuestionSchema` has no field for what an option does to a threat, and the
 * contract is frozen (CLAUDE.md rule 1). So the effects are returned in a sidecar map,
 * `effects`, the same pattern `MergedArchitecture` already uses for `componentEvidence`
 * and `flowEvidence`: everything a contract type has no room for, kept beside it instead
 * of inside it.
 */

import { z } from "zod";
import { callStructured, type ClaudeDeps } from "@/server/ai/claude";
import { loadPrompt } from "@/server/ai/prompts";
import type { CallUsage } from "@/server/ai/usage";
import type { ModelId } from "@/server/ai/models";
import type { ControlGap, Deployment } from "@/server/detect/types";
import {
  CandidateQuestionSchema,
  type Component,
  type DeveloperQuestion,
  type Threat,
  type Unknown,
} from "@/shared/schema";
import {
  MAX_QUESTIONS,
  MEANING_EFFECT,
  MIN_VALUE,
  SEVERITY_WEIGHT,
  answeredByFacts,
  combinedDelta,
  defaultEffectFor,
  effectsFor,
  gapFor,
  linkUnknowns,
  qualifiesForQuestion,
  rankCandidates,
  selectCandidates,
  severityWeightOf,
  toStoredValueScore,
  uncertaintyWeightOf,
  valueOf,
  type Candidate,
  type CertaintyResolution,
  type LinkedUnknown,
  type OptionEffect,
  type OptionMeaning,
  type SkipReason,
  type SkippedReason,
} from "@/server/questions/engine";

// Re-exported so existing callers (pipeline.ts, tests) keep importing everything from
// "@/server/questions" -- engine.ts is an internal split, not a new public entry point.
export {
  MAX_QUESTIONS,
  MEANING_EFFECT,
  MIN_VALUE,
  SEVERITY_WEIGHT,
  answeredByFacts,
  combinedDelta,
  defaultEffectFor,
  effectsFor,
  gapFor,
  linkUnknowns,
  qualifiesForQuestion,
  rankCandidates,
  selectCandidates,
  severityWeightOf,
  toStoredValueScore,
  uncertaintyWeightOf,
  valueOf,
};
export type {
  Candidate,
  CertaintyResolution,
  LinkedUnknown,
  OptionEffect,
  OptionMeaning,
  SkipReason,
  SkippedReason,
};

// ---------------------------------------------------------------------------
// Knobs
// ---------------------------------------------------------------------------

export const QUESTIONS_PROMPT_NAME = "questions";
export const QUESTIONS_PROMPT_VERSION = 1;

/** A handful of short questions; nowhere near the budget threats or architecture need. */
export const QUESTIONS_MAX_TOKENS = 4000;

/**
 * Extended thinking is disabled for question calls, as for architecture and threat calls
 * (ARCHITECTURE_THINKING, THREATS_THINKING). With the parameter omitted the model thinks
 * adaptively, and reasoning tokens count against QUESTIONS_MAX_TOKENS: on the other two
 * stages they used a whole 12,000-token budget and left none for the JSON, and 4,000
 * leaves far less room. The call only words questions; code decides everything else.
 */
export const QUESTIONS_THINKING = { type: "disabled" } as const;

// ---------------------------------------------------------------------------
// Public shape
// ---------------------------------------------------------------------------

export type QuestionEffects = {
  questionId: string;
  unknownId: string;
  /** The gap id, present iff this question is gap-derived. */
  gapId?: string;
  /** One entry per option, index-aligned with the question's `options`. */
  options: OptionEffect[];
  /** Applied when the developer skips the question or answers "unsure". */
  default: OptionEffect;
  /**
   * Threats an applied answer is allowed to re-score: those naming this question's
   * unknown in `dependsOnUnknownIds` only, NOT the wider `affectedThreatIds` a
   * component-only link also contributes to the value formula. See
   * src/server/questions/engine.ts's LinkedUnknown for why the two lists differ.
   */
  appliesToThreatIds: string[];
};

export type SelectQuestionsInput = {
  /** Defaults to modelFor("questions"); the pipeline passes its level plan's. */
  model?: ModelId;
  unknowns: readonly Unknown[];
  /** Scored threats -- the value formula needs each one's confidence. */
  threats: readonly Threat[];
  /** The same gaps mergeArchitecture bound, so a gap-derived unknown can be told apart. */
  gaps: readonly ControlGap[];
  /** For answeredByFacts's component-name lookup. Defaults to []. */
  components?: readonly Component[];
  /** Deployment facts (Compose published ports, etc). Defaults to []. */
  deployment?: readonly Deployment[];
  analysisId: string;
  /** Test seam, passed straight to callStructured. Nothing in production sets it. */
  deps?: Partial<ClaudeDeps>;
  promptDir?: string;
  maxTokens?: number;
};

export type SelectQuestionsResult = {
  questions: DeveloperQuestion[];
  /** questionId -> its option effects. Has exactly one entry per returned question. */
  effects: Map<string, QuestionEffects>;
  limitations: string[];
  /** Every unknown this run considered but did not ask about, and why. For debugging and README. */
  skippedReasons: SkippedReason[];
  /** Present only when the model was actually called (an empty result may skip it). */
  usage?: CallUsage;
  /** "questions.v1". Absent when nothing qualified and no call was made. */
  promptId?: string;
};

// ---------------------------------------------------------------------------
// The model call (wording only)
// ---------------------------------------------------------------------------

const OPTION_MEANING_VALUES = [
  "control_absent",
  "control_present",
  "partial",
  "not_applicable",
] as const;
const OptionMeaningSchema = z.enum(OPTION_MEANING_VALUES);

/**
 * What Prompt M returns: a CandidateQuestion (the shared contract type) plus one
 * OptionMeaning per option. The wrapper is local to this module; CandidateQuestionSchema
 * itself is untouched, same as ThreatBatchResponseSchema in src/server/analysis/threats.ts.
 */
export const QuestionDraftSchema = CandidateQuestionSchema.extend({
  optionMeanings: z.array(OptionMeaningSchema).min(2).max(4),
});
export type QuestionDraft = z.infer<typeof QuestionDraftSchema>;

export const QuestionsResponseSchema = z.object({
  questions: z.array(QuestionDraftSchema),
});
export type QuestionsResponse = z.infer<typeof QuestionsResponseSchema>;

export const questionsJsonSchema = z.toJSONSchema(
  QuestionsResponseSchema,
) as Record<string, unknown>;

function unknownBlock(candidate: Candidate): string {
  const lines = [
    `### UNKNOWN ${candidate.unknown.id}`,
    `Description: ${candidate.unknown.description}`,
    `Affects: ${candidate.unknown.affectsComponentIds.join(", ") || "(none)"}`,
  ];
  if (candidate.gap) {
    lines.push(
      `Control gap: ${candidate.gap.control} (certainty ${candidate.gap.certainty.toFixed(2)})`,
      `Expected because: ${candidate.gap.expectation}`,
    );
  }
  return lines.join("\n");
}

function buildUserMessage(candidates: readonly Candidate[]): string {
  return `## UNKNOWNS\n\n${candidates.map(unknownBlock).join("\n\n")}\n`;
}

/** A draft is usable when it claims one of the offered unknowns, once, with meanings that pair 1:1 with its options. */
function validDrafts(
  drafts: readonly QuestionDraft[],
  offered: ReadonlySet<string>,
  limitations: string[],
): Map<string, QuestionDraft> {
  const byUnknown = new Map<string, QuestionDraft>();
  for (const draft of drafts) {
    if (!offered.has(draft.unknownId)) {
      limitations.push(
        `Dropped a question for unknown "${draft.unknownId}": it was not one of the unknowns offered.`,
      );
    } else if (draft.optionMeanings.length !== draft.options.length) {
      limitations.push(
        `Dropped the question for unknown "${draft.unknownId}": it has ${draft.options.length} option(s) but ${draft.optionMeanings.length} optionMeanings.`,
      );
    } else if (byUnknown.has(draft.unknownId)) {
      limitations.push(
        `Dropped a second question for unknown "${draft.unknownId}"; the first one is kept.`,
      );
    } else {
      byUnknown.set(draft.unknownId, draft);
    }
  }
  return byUnknown;
}

// ---------------------------------------------------------------------------
// selectQuestions
// ---------------------------------------------------------------------------

/**
 * Selects at most MAX_QUESTIONS developer questions from `unknowns`, asks Prompt M to
 * word the winners, and returns each one's precomputed option effects alongside it.
 *
 * Nothing qualifying (every candidate dropped -- no affected threats, answered by facts,
 * below MIN_VALUE, or over the cap) returns an empty result with no model call: the
 * caller goes straight to results, per the brief.
 */
export async function selectQuestions(
  input: SelectQuestionsInput,
): Promise<SelectQuestionsResult> {
  const { winners, skipped } = selectCandidates(
    input.unknowns,
    input.threats,
    input.gaps,
    input.components ?? [],
    input.deployment ?? [],
  );
  const skippedReasons = [...skipped];

  if (winners.length === 0) {
    return { questions: [], effects: new Map(), limitations: [], skippedReasons };
  }

  const prompt = loadPrompt(
    QUESTIONS_PROMPT_NAME,
    QUESTIONS_PROMPT_VERSION,
    input.promptDir,
  );

  const { value, usage } = await callStructured({
    stage: "questions",
    system: prompt.text,
    user: buildUserMessage(winners),
    schema: QuestionsResponseSchema,
    jsonSchema: questionsJsonSchema,
    maxTokens: input.maxTokens ?? QUESTIONS_MAX_TOKENS,
    thinking: QUESTIONS_THINKING,
    model: input.model,
    analysisId: input.analysisId,
    deps: input.deps,
  });

  const limitations: string[] = [];
  const offered = new Set(winners.map((c) => c.unknown.id));
  const draftByUnknown = validDrafts(value.questions, offered, limitations);

  type Prepared = {
    candidate: Candidate;
    draft: QuestionDraft;
    optionEffects: OptionEffect[];
    defaultEffect: OptionEffect;
  };
  const prepared: Prepared[] = [];

  for (const candidate of winners) {
    const draft = draftByUnknown.get(candidate.unknown.id);
    if (!draft) {
      limitations.push(
        `No usable question was returned for unknown "${candidate.unknown.id}"; it was skipped.`,
      );
      skippedReasons.push({ unknownId: candidate.unknown.id, reason: "no_usable_draft" });
      continue;
    }

    const optionEffects = effectsFor(draft.optionMeanings, candidate.gap !== undefined);
    const defaultEffect = defaultEffectFor(optionEffects);
    if (!defaultEffect) {
      limitations.push(
        `Dropped the question for unknown "${candidate.unknown.id}": every option's effect would lower risk, so no cautious default exists.`,
      );
      skippedReasons.push({ unknownId: candidate.unknown.id, reason: "no_cautious_default" });
      continue;
    }

    prepared.push({ candidate, draft, optionEffects, defaultEffect });
  }

  // Ids are assigned last, in ranked order, so a drop above never leaves a gap
  // (question-1, question-3 with no question-2) in the ids actually returned.
  const questions: DeveloperQuestion[] = [];
  const effects = new Map<string, QuestionEffects>();
  prepared.forEach(({ candidate, draft, optionEffects, defaultEffect }, index) => {
    const questionId = `question-${index + 1}`;
    questions.push({
      id: questionId,
      text: draft.text,
      whyAsking: draft.whyAsking,
      options: draft.options,
      allowsUnsure: draft.allowsUnsure,
      affectedThreatIds: candidate.affectedThreatIds,
      unknownId: candidate.unknown.id,
      defaultAssumption: draft.defaultAssumption,
      valueScore: toStoredValueScore(candidate.valueScore),
    });
    effects.set(questionId, {
      questionId,
      unknownId: candidate.unknown.id,
      ...(candidate.gap ? { gapId: candidate.gap.id } : {}),
      options: optionEffects,
      default: defaultEffect,
      appliesToThreatIds: candidate.dependentThreatIds,
    });
  });

  return { questions, effects, limitations, skippedReasons, usage, promptId: prompt.id };
}
