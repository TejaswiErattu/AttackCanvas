/**
 * Text-answer front door to applyAnswers (src/server/analysis/answers.ts).
 *
 * The analysis module speaks in option indexes and statuses; a caller holding the
 * developer's raw reply ("Public on the internet", "skip", "unsure") speaks in strings.
 * This adapter translates one to the other and delegates -- evidence, deltas, assumption
 * bookkeeping and re-scoring all stay in the one implementation, so there is a single
 * place that decides what an answer does (CLAUDE.md rule 2).
 */

import {
  applyAnswers as applyIndexedAnswers,
  type DeveloperAnswer,
} from "@/server/analysis/answers";
import type { QuestionEffects } from "@/server/questions";
import type { ControlGap } from "@/server/detect/types";
import { validateThreatModel, type ThreatModel } from "@/shared/schema";

/** Everything applyAnswers needs to know about the analysis the questions came from. */
export type AnswerState = {
  model: ThreatModel;
  /** selectQuestions's sidecar: one entry per question in `model.questions`. */
  effects: ReadonlyMap<string, QuestionEffects>;
  gaps: readonly ControlGap[];
};

export type TextAnswer = {
  questionId: string;
  /** An option's text, or the sentinel "skip" / "unsure". */
  answer: string;
};

function normalize(text: string): string {
  return text.trim().toLowerCase();
}

/** Thrown when an answer string names no option, or more than one, of its question. */
export class AnswerValidationError extends Error {
  constructor(
    readonly questionId: string,
    message: string,
  ) {
    super(message);
    this.name = "AnswerValidationError";
  }
}

const RESERVED = new Set(["skip", "unsure"]);

/**
 * Only the explicit sentinels "skip" and "unsure" (any case) are statuses, and so the only
 * strings that reach the cautious default. Anything else must match exactly one of the
 * question's options by trimmed, case-insensitive text. Throws AnswerValidationError when
 * the question does not exist (`options` undefined), when one of its options is itself
 * worded "skip" or "unsure" (it could never be told apart from the sentinel), or when the
 * answer matches no option or several -- so a typo, a stale id or an ambiguous option can
 * never quietly read as a choice or as a skip.
 */
export function toDeveloperAnswer(
  answer: TextAnswer,
  options: readonly string[] | undefined,
): DeveloperAnswer {
  if (options === undefined) {
    throw new AnswerValidationError(
      answer.questionId,
      `Answer to "${answer.questionId}" names a question this model does not have.`,
    );
  }
  const reserved = options.findIndex((o) => RESERVED.has(normalize(o)));
  if (reserved !== -1) {
    throw new AnswerValidationError(
      answer.questionId,
      `Question "${answer.questionId}" option ${reserved} ("${options[reserved]}") uses a reserved answer value; "skip" and "unsure" cannot be selectable options.`,
    );
  }

  const wanted = normalize(answer.answer);
  if (wanted === "skip") return { questionId: answer.questionId, status: "skipped" };
  if (wanted === "unsure") return { questionId: answer.questionId, status: "unsure" };

  const matches = options.flatMap((o, index) => (normalize(o) === wanted ? [index] : []));
  if (matches.length === 0) {
    throw new AnswerValidationError(
      answer.questionId,
      `Answer "${answer.answer}" to "${answer.questionId}" matches none of its options (${options
        .map((o) => `"${o}"`)
        .join(", ")}); use one of them, "skip" or "unsure".`,
    );
  }
  if (matches.length > 1) {
    throw new AnswerValidationError(
      answer.questionId,
      `Answer "${answer.answer}" to "${answer.questionId}" is ambiguous: options ${matches.join(
        " and ",
      )} have the same text once case and spacing are ignored.`,
    );
  }
  return { questionId: answer.questionId, status: "answered", optionIndex: matches[0] };
}

/**
 * Applies the developer's answers and returns the re-scored, re-validated model. Throws
 * AnswerValidationError for an unknown question id, a reserved option, or an answer string
 * that is unknown or ambiguous, and a plain
 * Error if the result fails ThreatModelSchema -- that would be a bug here, not bad input.
 */
export function applyAnswers(
  state: AnswerState,
  answers: readonly TextAnswer[],
): ThreatModel {
  const optionsById = new Map(state.model.questions.map((q) => [q.id, q.options]));
  const result = applyIndexedAnswers({
    model: state.model,
    effects: state.effects,
    gaps: state.gaps,
    answers: answers.map((a) => toDeveloperAnswer(a, optionsById.get(a.questionId))),
  });

  const validation = validateThreatModel(result.model);
  if (!validation.ok) {
    const detail = validation.issues.map((i) => `${i.path}: ${i.message}`).join("; ");
    throw new Error(`applyAnswers produced an invalid ThreatModel: ${detail}`);
  }
  return validation.data;
}
