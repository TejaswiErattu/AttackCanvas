/**
 * The pure parts of scripts/try-pipeline.ts, kept in their own module so tests can import
 * them: the script itself runs a live, paid analysis the moment it is invoked.
 */

import { formatUsd } from "@/server/ai/usage";
import { isGapEvidence } from "@/server/scoring";
import { STAGE_LABELS } from "@/shared/labels";
import type { AnalysisStage, Basis } from "@/shared/schema";
import type { AnalysisState } from "@/server/analysis/pipeline";

/** Reads `<owner>/<repo>` from a shorthand string or a github.com URL. */
export function parseTarget(input: string): { owner: string; repo: string } {
  const cleaned = input.trim().replace(/\.git$/, "");
  const match =
    /^https?:\/\/github\.com\/([^/]+)\/([^/?#]+)/.exec(cleaned) ??
    /^([^/\s]+)\/([^/\s]+)$/.exec(cleaned);
  if (!match) {
    throw new Error(`could not read "${input}" as owner/repo or a github.com URL`);
  }
  return { owner: match[1], repo: match[2] };
}

/**
 * The public API's AnalysisRequestSchema requires a full URL (contract, unchanged). This
 * script may still accept the shorthand "owner/repo" a person types faster, but it must
 * normalize to a full URL itself before calling into src/server/analysis/pipeline.ts,
 * rather than lean on that module's own (separately still-shorthand-tolerant)
 * parseGitHubUrl to paper over the difference.
 */
export function toGitHubUrl(owner: string, repo: string): string {
  return `https://github.com/${owner}/${repo}`;
}

/**
 * Validates a --timeout value BEFORE any network or model work starts. Returns the
 * parsed milliseconds, or a safe, printable reason it was rejected -- never throws, so
 * the caller can print the reason and exit(1) without doing any work first. `maxMs` is
 * the pipeline's own ceiling (MAX_TIMEOUT_MS), passed in so this module stays pure.
 */
export function parseTimeoutMs(
  raw: string | undefined,
  defaultMs: number,
  maxMs: number,
): { ok: true; value: number } | { ok: false; message: string } {
  if (raw === undefined) return { ok: true, value: defaultMs };
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0 || value > maxMs) {
    return {
      ok: false,
      message: `--timeout must be a positive integer number of milliseconds no greater than ${maxMs}, got "${raw}".`,
    };
  }
  return { ok: true, value };
}

/** One stage-transition line, e.g. "[  12.3s] scanning — Scanning code, ...". */
export function formatStageLine(stage: AnalysisStage, elapsedSeconds: number): string {
  const seconds = elapsedSeconds.toFixed(1).padStart(6, " ");
  return `[${seconds}s] ${stage} — ${STAGE_LABELS[stage]}`;
}

/** The "=== summary ===" block's body lines for a terminal (complete or failed) state. */
export function formatSummary(
  state: Pick<AnalysisState, "stage" | "error" | "threatModel" | "questions" | "cost">,
  basisCounts: Record<Basis, number>,
  elapsedSeconds: number,
): string[] {
  const lines: string[] = [`stage: ${state.stage} | elapsed ${elapsedSeconds.toFixed(1)}s`];
  if (state.error) {
    lines.push(`error: [${state.error.code}] ${state.error.message}`);
    return lines;
  }
  const model = state.threatModel;
  lines.push(`threats: ${model?.threats.length ?? 0}`);
  lines.push(
    `  by basis: evidence_backed ${basisCounts.evidence_backed} | ` +
      `assumption_dependent ${basisCounts.assumption_dependent}`,
  );
  lines.push(`questions: ${state.questions?.length ?? 0}`);
  lines.push(`gaps: ${model ? model.evidence.filter(isGapEvidence).length : 0}`);
  lines.push(`limitations: ${model?.limitations.length ?? 0}`);
  lines.push(`cost: ${formatUsd(state.cost.totalUsd)} (${state.cost.calls} provider response(s))`);
  return lines;
}
