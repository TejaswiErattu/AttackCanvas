"use client";

/**
 * Developer questions, shown while the analysis sits at "awaiting_answers".
 *
 * The questions, their wording, their options and their default assumptions are all
 * produced by the backend (src/server/questions) and rendered verbatim. This panel decides
 * nothing about which questions matter; it only collects a choice per question and posts
 * the shape POST /api/analyze/[id]/answers already accepts:
 *   { questionId, status: "answered" | "skipped" | "unsure", optionIndex? }
 *
 * A question left untouched is submitted as "skipped", which is exactly what the backend
 * expects — it then applies the question's own `defaultAssumption`, so skipping is a real,
 * documented answer rather than missing data. Nothing here is hardcoded: 0-3 questions,
 * their options and whether "not sure" is allowed all come from the server.
 *
 * Each question is a fieldset with a legend and native radio inputs (visually hidden, with
 * styled labels), so the whole panel is keyboard-operable and reads correctly in a screen
 * reader; the focus ring moves to the label of the focused radio.
 */

import { useState } from "react";
import type { AnalysisError, QuestionData } from "@/shared/viewModel";
import type { AnswerSubmission } from "@/client/useAnalysis";
import ErrorState from "@/components/ErrorState";

type Choice = { status: AnswerSubmission["status"]; optionIndex?: number };

type QuestionPanelProps = {
  questions: readonly QuestionData[];
  submitting: boolean;
  error?: AnalysisError | null;
  onSubmit: (answers: AnswerSubmission[]) => void;
};

export default function QuestionPanel({
  questions,
  submitting,
  error,
  onSubmit,
}: QuestionPanelProps) {
  const [choices, setChoices] = useState<Record<string, Choice>>({});
  const items = Array.isArray(questions) ? questions : [];

  const select = (questionId: string, choice: Choice) => {
    setChoices((previous) => ({ ...previous, [questionId]: choice }));
  };

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    // One entry per question, in the order the backend sent them. An untouched question
    // becomes "skipped" so the array is never empty and never partial.
    const answers: AnswerSubmission[] = items.map((question) => {
      const choice = choices[question.id] ?? { status: "skipped" as const };
      return choice.status === "answered" && typeof choice.optionIndex === "number"
        ? {
            questionId: question.id,
            status: "answered",
            optionIndex: choice.optionIndex,
          }
        : { questionId: question.id, status: choice.status };
    });
    onSubmit(answers);
  };

  if (items.length === 0) return null;

  const optionRow = (id: string, name: string, label: React.ReactNode, checked: boolean, onChange: () => void) => (
    <div key={id} className="relative">
      <input
        id={id}
        type="radio"
        name={name}
        className="peer sr-only"
        checked={checked}
        onChange={onChange}
        disabled={submitting}
      />
      <label
        htmlFor={id}
        className="flex cursor-pointer items-start gap-3 rounded-xl border border-line bg-ink/50 px-4 py-3 text-sm text-fg transition-colors hover:border-line-strong peer-checked:border-mint peer-checked:bg-mint-deep/70 peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-mint peer-disabled:cursor-not-allowed peer-disabled:opacity-60"
      >
        <span
          aria-hidden="true"
          className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border ${
            checked ? "border-mint" : "border-line-strong"
          }`}
        >
          {checked ? <span className="h-2 w-2 rounded-full bg-mint" /> : null}
        </span>
        <span>{label}</span>
      </label>
    </div>
  );

  return (
    <section
      aria-labelledby="question-panel-heading"
      className="w-full rounded-2xl border border-line bg-surface/70 p-5 sm:p-6"
    >
      <h2 id="question-panel-heading" className="font-display text-2xl font-semibold text-fg">
        A few questions to sharpen the analysis
      </h2>
      <p className="mt-2 text-sm text-muted">
        The repository could not settle these. Answering is optional: anything you skip, or
        mark as unsure, uses the default assumption shown under the question.
      </p>

      {error ? (
        <div className="mt-4">
          <ErrorState error={error} compact />
        </div>
      ) : null}

      <form onSubmit={handleSubmit} className="mt-6 space-y-5">
        {items.map((question) => {
          const choice = choices[question.id];
          const name = `question-${question.id}`;
          const options: readonly string[] = Array.isArray(question.options)
            ? question.options
            : [];
          const skipped = choice === undefined || choice.status === "skipped";
          return (
            <fieldset
              key={question.id}
              className="min-w-0 rounded-2xl border border-line bg-ink-2/60 p-4 sm:p-5"
            >
              <legend className="rounded-full border border-line bg-surface px-3 py-0.5 font-mono text-[11px] uppercase tracking-wider text-muted">
                Question {question.index} of {question.total}
              </legend>

              <p className="mt-2 text-base font-semibold text-fg">{question.text}</p>
              <p className="mt-1 text-sm text-muted">{question.whyAsking}</p>

              <div className="mt-4 grid gap-2">
                {options.map((option, optionIndex) =>
                  optionRow(
                    `${name}-option-${optionIndex}`,
                    name,
                    option,
                    choice?.status === "answered" && choice.optionIndex === optionIndex,
                    () => select(question.id, { status: "answered", optionIndex }),
                  ),
                )}

                {question.allowsUnsure
                  ? optionRow(
                      `${name}-unsure`,
                      name,
                      <>I&apos;m not sure</>,
                      choice?.status === "unsure",
                      () => select(question.id, { status: "unsure" }),
                    )
                  : null}

                {optionRow(
                  `${name}-skip`,
                  name,
                  "Skip this question",
                  skipped,
                  () => select(question.id, { status: "skipped" }),
                )}
              </div>

              <p className="mt-4 border-l-2 border-line-strong pl-3 text-xs text-subtle">
                If skipped: {question.defaultAssumption}
              </p>
            </fieldset>
          );
        })}

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded-full bg-mint px-6 py-3 text-sm font-semibold text-ink transition-colors hover:bg-mint-strong disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
        >
          {submitting ? "Submitting\u2026" : "Submit answers and finish"}
        </button>
      </form>
    </section>
  );
}
