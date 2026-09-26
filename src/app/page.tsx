"use client";

/**
 * Landing page: pick a public GitHub repository and an analysis level, then start.
 *
 * Submitting posts the frozen AnalysisRequest shape ({ repoUrl, analysisLevel }) to the
 * existing POST /api/analyze and navigates to /analyze/<id>. The URL is sent exactly as
 * typed: validation belongs to the server (AnalysisRequestSchema, then parseGitHubUrl), and
 * duplicating it here would only risk the two disagreeing. The field is type="url" so the
 * browser can help, but the server's answer is the one that counts.
 *
 * Errors are rendered from the API's own `{ error: { code, title, message, canRetry } }`
 * body, so the wording a user sees is the backend's ERROR_COPY -- including the 429 a user
 * hits after five analyses in an hour.
 *
 * The graphic beside the form is an illustration (HeroIllustration), not a result.
 */

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ANALYSIS_LEVEL_LABELS } from "@/shared/schema";
import { formatCostRange } from "@/shared/levelCost";
import type { AnalysisError } from "@/shared/viewModel";
import { readApiError } from "@/client/useAnalysis";
import ErrorState from "@/components/ErrorState";
import HeroIllustration from "@/components/HeroIllustration";
import SectionLabel from "@/components/SectionLabel";

const LEVELS = [0, 1, 2, 3, 4] as const;

const LEVEL_HINTS: Record<number, string> = {
  0: "Fastest pass over the most important files.",
  1: "Core entry points and obvious controls.",
  2: "Balanced depth; a good default.",
  3: "Wider file coverage and more threat detail.",
  4: "Broadest coverage; slowest and most expensive.",
};

/** What the pipeline actually does, in order. Descriptive copy, not data. */
const STEPS = [
  {
    title: "Read, never run",
    body: "The repository is loaded read-only. Files are filtered, and secrets are redacted before anything reaches a model.",
  },
  {
    title: "Scan with deterministic tools",
    body: "Detectors, Semgrep and OSV dependency checks find concrete evidence and missing controls.",
  },
  {
    title: "Model the architecture",
    body: "Components, data flows and trust boundaries are mapped, then STRIDE threats are raised per element.",
  },
  {
    title: "Score with rules, not guesses",
    body: "Severity, confidence and priority come from fixed scoring rules. Anything uncertain is labelled as such.",
  },
];

export default function HomePage() {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState("");
  const [analysisLevel, setAnalysisLevel] = useState<number>(2);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<AnalysisError | null>(null);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setStarting(true);
    setError(null);
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: repoUrl.trim(), analysisLevel }),
      });
      const json: unknown = await response.json().catch(() => null);

      if (!response.ok) {
        setError(
          readApiError(json, response.status) ?? {
            code: "AI_FAILURE",
            title: "Could not start the analysis",
            message: "Something went wrong starting the analysis. Please try again.",
            canRetry: true,
          },
        );
        setStarting(false);
        return;
      }

      const analysisId =
        typeof json === "object" && json !== null && "analysisId" in json
          ? (json as { analysisId: unknown }).analysisId
          : null;

      if (typeof analysisId !== "string" || analysisId === "") {
        setError({
          code: "AI_FAILURE",
          title: "Could not start the analysis",
          message: "The service did not return an analysis id. Please try again.",
          canRetry: true,
        });
        setStarting(false);
        return;
      }

      router.push(`/analyze/${encodeURIComponent(analysisId)}`);
    } catch {
      setError({
        code: "NETWORK_ERROR",
        title: "Connection problem",
        message:
          "We couldn't reach the analysis service. Check your connection and retry.",
        canRetry: true,
      });
      setStarting(false);
    }
  };

  return (
    <main id="main" className="flex-1">
      <section className="bg-glow relative overflow-hidden">
        <div className="mx-auto grid w-full max-w-7xl items-center gap-12 px-4 pb-20 pt-14 sm:px-6 lg:grid-cols-[1.05fr_1fr] lg:gap-16 lg:pt-20">
          <div className="min-w-0">
            <SectionLabel>Threat modeling for public repositories</SectionLabel>
            <h1 className="mt-6 font-display text-4xl font-semibold leading-[1.08] tracking-tight text-fg sm:text-5xl lg:text-[3.5rem]">
              See how your code could be attacked, <span className="text-mint">and why.</span>
            </h1>
            <p className="mt-5 max-w-xl text-base leading-relaxed text-muted sm:text-lg">
              Paste a public GitHub repository. AttackCanvas maps its architecture, raises STRIDE
              threats tied to OWASP Top 10:2025 and CWE, and shows the evidence and the
              confidence behind every one.
            </p>

            <form
              onSubmit={handleSubmit}
              aria-labelledby="start-heading"
              className="mt-8 rounded-2xl border border-line bg-surface/80 p-5 shadow-[0_20px_50px_-30px_rgba(18,33,63,0.35)] backdrop-blur sm:p-6"
            >
              <h2 id="start-heading" className="sr-only">
                Start an analysis
              </h2>
              <label htmlFor="repo-url" className="block text-sm font-medium text-fg">
                Public GitHub repository URL
              </label>
              <div className="mt-2 flex flex-col gap-3 sm:flex-row lg:flex-col xl:flex-row">
                <input
                  id="repo-url"
                  name="repoUrl"
                  type="url"
                  required
                  autoComplete="url"
                  inputMode="url"
                  spellCheck={false}
                  value={repoUrl}
                  onChange={(event) => setRepoUrl(event.target.value)}
                  placeholder="https://github.com/owner/name"
                  aria-describedby="repo-url-hint"
                  aria-invalid={error?.code === "INVALID_URL" ? true : undefined}
                  className="min-w-0 flex-1 rounded-full border border-line-strong bg-ink px-5 py-3 font-mono text-sm text-fg placeholder:text-subtle focus-visible:border-mint"
                />
                <button
                  type="submit"
                  disabled={starting || repoUrl.trim() === ""}
                  className="rounded-full bg-mint px-6 py-3 text-sm font-semibold text-ink transition-colors hover:bg-mint-strong disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {starting ? "Starting…" : "Analyze repository"}
                </button>
              </div>
              <p id="repo-url-hint" className="mt-2 text-xs text-subtle">
                The repository must be public. Nothing is written to it, and secrets found in it
                are never sent to a model.
              </p>

              <fieldset className="mt-6">
                <legend className="text-sm font-medium text-fg">Analysis level</legend>
                <div className="mt-2 grid grid-cols-[repeat(auto-fit,minmax(7rem,1fr))] gap-2">
                  {LEVELS.map((level) => {
                    const id = `analysis-level-${level}`;
                    return (
                      <div key={level} className="relative">
                        <input
                          id={id}
                          type="radio"
                          name="analysisLevel"
                          value={level}
                          checked={analysisLevel === level}
                          onChange={() => setAnalysisLevel(level)}
                          aria-describedby="analysis-level-hint"
                          className="peer sr-only"
                        />
                        <label
                          htmlFor={id}
                          className="flex h-full cursor-pointer flex-col rounded-xl border border-line bg-ink/60 px-3 py-2.5 text-left transition-colors hover:border-line-strong peer-checked:border-mint peer-checked:bg-mint-deep peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-mint"
                        >
                          <span className="font-mono text-[11px] text-muted">Level {level}</span>
                          <span className="truncate text-sm font-semibold text-fg">
                            {ANALYSIS_LEVEL_LABELS[level]}
                          </span>
                          <span className="mt-1 text-[11px] leading-snug text-subtle">
                            {formatCostRange(level)}
                          </span>
                        </label>
                      </div>
                    );
                  })}
                </div>
                <p id="analysis-level-hint" className="mt-2 text-xs text-subtle" aria-live="polite">
                  {LEVEL_HINTS[analysisLevel] ?? ""}
                </p>
                <p className="mt-1 text-xs text-subtle">
                  Costs are API usage estimates; larger repositories cost more.
                </p>
              </fieldset>

              {error ? (
                <div className="mt-5">
                  <ErrorState error={error} />
                </div>
              ) : null}
            </form>
          </div>

          <div className="min-w-0">
            <HeroIllustration />
          </div>
        </div>
      </section>

      <section aria-labelledby="how-heading" className="border-t border-line/70">
        <div className="mx-auto w-full max-w-7xl px-4 py-16 sm:px-6">
          <div className="text-center">
            <SectionLabel>How it works</SectionLabel>
            <h2
              id="how-heading"
              className="mx-auto mt-4 max-w-2xl font-display text-3xl font-semibold tracking-tight text-fg"
            >
              Evidence first, model second
            </h2>
          </div>
          <ol className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {STEPS.map((step, index) => (
              <li key={step.title} className="rounded-2xl border border-line bg-surface/60 p-5">
                <span className="font-mono text-xs text-mint">0{index + 1}</span>
                <h3 className="mt-3 font-display text-lg font-semibold text-fg">{step.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted">{step.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>
    </main>
  );
}
