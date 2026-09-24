"use client";

/**
 * The real backend stage progression.
 *
 * Every label comes from the server's own `stageLabel` / STAGE_LABELS, and the numeric
 * progress comes from the server's `stageIndex` / `stageCount` — this component invents no
 * progress of its own and never fakes movement between polls. A stage the backend has not
 * reported is simply not marked done.
 *
 * The step list below mirrors the adapter's STAGE_SEQUENCE (src/client/adapter.ts), which
 * is private to that module. It is used only to draw the checklist; the percentage bar and
 * the "step N of M" text are always the server's numbers, so if the two ever drift the
 * displayed progress still follows the backend.
 *
 * STAGE_DETAIL is fixed explanatory copy describing what each real pipeline stage does
 * (src/server/analysis/pipeline.ts). It is not status: it never claims a stage finished.
 */

import { STAGE_LABELS } from "@/shared/labels";
import type { AnalysisStage } from "@/shared/schema";

const STAGE_SEQUENCE: readonly AnalysisStage[] = [
  "queued",
  "loading_repo",
  "scanning",
  "mapping_architecture",
  "generating_threats",
  "awaiting_answers",
  "finalizing",
  "complete",
];

export const STAGE_DETAIL: Record<AnalysisStage, string> = {
  queued: "The analysis has been accepted and is about to start.",
  loading_repo:
    "Reading the repository read-only, filtering files and redacting secrets before anything reaches a model.",
  scanning:
    "Running deterministic detectors, Semgrep and OSV dependency checks, and looking for missing controls.",
  mapping_architecture:
    "Inferring components, data flows and trust boundaries from the facts gathered so far.",
  generating_threats:
    "Raising STRIDE threats per element and mapping them to OWASP Top 10:2025 and CWE. Scores come from fixed rules.",
  awaiting_answers:
    "A few answers from you would change specific ratings. Answering is optional.",
  finalizing: "Applying your answers and validating the final threat model.",
  complete: "The threat model is ready.",
  failed: "The analysis stopped.",
};

type StageProgressProps = {
  stage: AnalysisStage;
  stageLabel: string;
  stageIndex: number;
  stageCount: number;
};

export default function StageProgress({
  stage,
  stageLabel,
  stageIndex,
  stageCount,
}: StageProgressProps) {
  const failed = stage === "failed";
  const currentPosition = STAGE_SEQUENCE.indexOf(stage);
  const total = stageCount > 0 ? stageCount : STAGE_SEQUENCE.length;
  const percent = failed
    ? 100
    : Math.min(100, Math.max(0, Math.round((stageIndex / total) * 100)));

  return (
    <section
      aria-labelledby="stage-progress-heading"
      className="w-full rounded-2xl border border-line bg-surface/70 p-5 sm:p-6"
    >
      <h2 id="stage-progress-heading" className="sr-only">
        Analysis progress
      </h2>

      <div className="flex flex-wrap items-baseline justify-between gap-2">
        {/* aria-live so a screen reader announces each real stage change. */}
        <p aria-live="polite" className="font-display text-xl font-semibold text-fg">
          {failed ? STAGE_LABELS.failed : stageLabel}
        </p>
        {!failed && stageIndex > 0 ? (
          <span className="font-mono text-xs text-subtle">
            Step {stageIndex} of {total}
          </span>
        ) : null}
      </div>
      <p className="mt-1 text-sm text-muted">{STAGE_DETAIL[stage]}</p>

      <div
        role="progressbar"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Analysis progress"
        className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-surface-3"
      >
        <div
          className={`h-full rounded-full transition-[width] duration-500 ${
            failed ? "bg-sev-critical" : "bg-mint"
          }`}
          style={{ width: `${percent}%` }}
        />
      </div>

      <ol className="mt-6 space-y-1">
        {STAGE_SEQUENCE.map((step, position) => {
          const done = !failed && currentPosition > position;
          const current = !failed && currentPosition === position;
          return (
            <li
              key={step}
              aria-current={current ? "step" : undefined}
              className={`flex gap-3 rounded-xl px-3 py-2.5 ${current ? "bg-mint-deep/60" : ""}`}
            >
              <span
                aria-hidden="true"
                className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border font-mono text-[11px] font-semibold ${
                  done
                    ? "border-mint bg-mint text-ink"
                    : current
                      ? "border-mint text-mint"
                      : "border-line-strong text-subtle"
                }`}
              >
                {done ? "✓" : position + 1}
              </span>
              <span className="min-w-0">
                <span
                  className={`block text-sm ${
                    current ? "font-semibold text-fg" : done ? "text-muted" : "text-subtle"
                  }`}
                >
                  {STAGE_LABELS[step]}
                  {current ? <span className="sr-only"> (current step)</span> : null}
                  {done ? <span className="sr-only"> (done)</span> : null}
                </span>
                {current ? (
                  <span className="mt-0.5 block text-xs text-muted">{STAGE_DETAIL[step]}</span>
                ) : null}
              </span>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
