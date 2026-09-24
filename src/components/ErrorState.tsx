"use client";

/**
 * Renders one API error using the copy the backend already supplied.
 *
 * `title` and `message` come from src/shared/labels.ts's ERROR_COPY via the route, so this
 * component invents no wording of its own and never shows a raw upstream message
 * (CLAUDE.md rule 8). `canRetry` is the backend's own judgement: the retry button only
 * appears when the server says the request is worth repeating AND the caller passed
 * `onRetry`. Callers must not pass `onRetry` for a terminal failed analysis: retry() only
 * resumes polling the same id, which would just re-read the same failure.
 */

import type { AnalysisError } from "@/shared/viewModel";

type ErrorStateProps = {
  error: AnalysisError;
  onRetry?: () => void;
  /** Optional secondary action, e.g. "Start over" back to the landing page. */
  children?: React.ReactNode;
  /** A compact banner above content that is still shown, rather than a full panel. */
  compact?: boolean;
};

export default function ErrorState({ error, onRetry, children, compact = false }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={`rounded-2xl border border-sev-critical/40 bg-sev-critical-soft/50 ${compact ? "p-4" : "p-6"}`}
    >
      <div className="flex items-start gap-3">
        <span
          aria-hidden="true"
          className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-sev-critical/60 font-mono text-xs font-bold text-sev-critical"
        >
          !
        </span>
        <div className="min-w-0">
          <h2 className={`font-display font-semibold text-fg ${compact ? "text-base" : "text-lg"}`}>
            {error.title}
          </h2>
          <p className="mt-1 text-sm text-muted">{error.message}</p>
          <p className="mt-2 text-xs text-subtle">
            Error code: <span className="font-mono">{error.code}</span>
          </p>
          {(error.canRetry && onRetry) || children ? (
            <div className="mt-4 flex flex-wrap items-center gap-3">
              {error.canRetry && onRetry ? (
                <button
                  type="button"
                  onClick={onRetry}
                  className="rounded-full bg-fg px-4 py-2 text-sm font-semibold text-ink hover:bg-fg/85"
                >
                  Try again
                </button>
              ) : null}
              {children}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
