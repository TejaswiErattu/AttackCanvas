"use client";

/**
 * Orchestrates one analysis page: poll, show progress, ask questions, show the dashboard.
 *
 * All state comes from useAnalysis, which mirrors the backend's own stage machine. This
 * component only decides what to show for the current phase:
 *
 *   loading / active    progress
 *   awaiting_answers    the backend's developer questions, beside the progress
 *   submitting          the same, with the question panel disabled
 *   complete            the dashboard, built from the server's view model
 *   failed              the analysis's own error (snapshot.error), with "Start over" only
 *   error               a request error; retryable ones keep polling in the background
 *
 * Two kinds of error, handled separately (docs/frontend-integration.md):
 *   - a request error (`error`): a retryable one is a banner over whatever was last shown,
 *     with "Try again"; a non-retryable one (an expired id's 404) offers only Start over.
 *   - a failed analysis (`snapshot.error`): terminal on the server. retry() would only
 *     re-read the same failure, so it is never offered; the user starts a new analysis.
 */

import Link from "next/link";
import { useAnalysis, type AnswerSubmission } from "@/client/useAnalysis";
import Dashboard from "@/components/Dashboard";
import ErrorState from "@/components/ErrorState";
import QuestionPanel from "@/components/QuestionPanel";
import SectionLabel from "@/components/SectionLabel";
import StageProgress from "@/components/StageProgress";

type AnalysisViewProps = {
  analysisId: string;
};

function StartOverLink({ children = "Start over" }: { children?: React.ReactNode }) {
  return (
    <Link
      href="/"
      className="rounded-full border border-line-strong px-4 py-2 text-sm font-medium text-fg hover:border-mint hover:text-mint"
    >
      {children}
    </Link>
  );
}

function WorkspaceHeader({ title, analysisId }: { title: string; analysisId: string }) {
  return (
    <div className="mb-8">
      <SectionLabel>Analysis workspace</SectionLabel>
      <h1 className="mt-4 break-words font-display text-3xl font-semibold tracking-tight text-fg sm:text-4xl">
        {title}
      </h1>
      <p className="mt-2 font-mono text-xs text-subtle">
        Analysis <span className="break-all">{analysisId}</span>
      </p>
    </div>
  );
}

export default function AnalysisView({ analysisId }: AnalysisViewProps) {
  const { phase, snapshot, error, submitAnswers, retry } = useAnalysis(analysisId);

  const handleSubmit = (answers: AnswerSubmission[]) => {
    void submitAnswers(answers);
  };

  // A hard request failure (an expired or unknown id): nothing to resume, so Start over.
  if (phase === "error" && error && !error.canRetry) {
    return (
      <div className="mx-auto max-w-2xl">
        <WorkspaceHeader title="This analysis is unavailable" analysisId={analysisId} />
        <ErrorState error={error}>
          <StartOverLink />
        </ErrorState>
      </div>
    );
  }

  if (!snapshot) {
    return (
      <div className="mx-auto max-w-2xl">
        <WorkspaceHeader title="Connecting to your analysis" analysisId={analysisId} />
        <div className="rounded-2xl border border-line bg-surface/70 p-6">
          <p aria-live="polite" className="text-base font-medium text-fg">
            Loading analysis&hellip;
          </p>
          <p className="mt-1 text-sm text-muted">
            Fetching the current stage from the server.
          </p>
        </div>
        {error ? (
          <div className="mt-6">
            <ErrorState error={error} onRetry={retry} compact />
          </div>
        ) : null}
      </div>
    );
  }

  const repoName = snapshot.view?.repo?.fullName;

  // A transient request problem; the hook keeps polling underneath.
  const banner =
    phase === "error" && error ? (
      <div className="mb-6">
        <ErrorState error={error} onRetry={retry} compact />
      </div>
    ) : null;

  if (snapshot.stage === "failed") {
    return (
      <div className="mx-auto max-w-2xl">
        <WorkspaceHeader title={repoName ?? "The analysis stopped"} analysisId={analysisId} />
        {snapshot.error ? (
          // No onRetry: a failed analysis is final on the server (see the header).
          <ErrorState error={snapshot.error}>
            <StartOverLink>Start a new analysis</StartOverLink>
          </ErrorState>
        ) : (
          <div role="alert" className="rounded-2xl border border-line bg-surface/70 p-6">
            <p className="text-base font-medium text-fg">The analysis stopped.</p>
            <div className="mt-4">
              <StartOverLink>Start a new analysis</StartOverLink>
            </div>
          </div>
        )}
      </div>
    );
  }

  if (snapshot.stage === "complete" && snapshot.view) {
    return (
      <div>
        {banner}
        <Dashboard
          view={snapshot.view}
          basisCounts={snapshot.basisCounts}
          hiddenSummary={snapshot.hiddenSummary}
        />
        <div className="mt-12 flex justify-center">
          <StartOverLink>Analyze another repository</StartOverLink>
        </div>
      </div>
    );
  }

  const awaitingAnswers =
    (phase === "awaiting_answers" || phase === "submitting") &&
    snapshot.questions.length > 0;

  const progress = (
    <StageProgress
      stage={snapshot.stage}
      stageLabel={snapshot.stageLabel}
      stageIndex={snapshot.stageIndex}
      stageCount={snapshot.stageCount}
    />
  );

  if (awaitingAnswers) {
    return (
      <div>
        <WorkspaceHeader title={repoName ?? "Your analysis"} analysisId={analysisId} />
        {banner}
        <div className="grid gap-8 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
          <QuestionPanel
            questions={snapshot.questions}
            submitting={phase === "submitting"}
            // Set by `answers_failed`, which returns the phase to awaiting_answers.
            error={error}
            onSubmit={handleSubmit}
          />
          <div className="lg:sticky lg:top-24 lg:self-start">{progress}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl">
      <WorkspaceHeader title={repoName ?? "Analyzing your repository"} analysisId={analysisId} />
      {banner}
      {progress}
      <p className="mt-4 text-center text-xs text-subtle">
        This page updates on its own. You can leave it open; refreshing picks up where the
        analysis is.
      </p>
    </div>
  );
}
