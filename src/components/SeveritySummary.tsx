"use client";

/**
 * Severity headline for the dashboard.
 *
 * Every number shown here is read straight from the server view model: `counts` is
 * DashboardViewModel.counts and `basisCounts` is the route's own derived count. Nothing is
 * re-tallied from the threat list, because the counts are part of the scored result
 * (CLAUDE.md rule 2), not a display convenience.
 *
 * Two lines add context without changing those counts: "Including low-confidence" adds the
 * server's counts of threats below 25% confidence (DashboardViewModel.hiddenCounts), and the
 * carried-forward line says how many of the last run's threats were not re-found and not
 * marked fixed. Neither feeds the tiles or Fix now.
 *
 * The severity palette is exported because ThreatCard and ArchitectureGraph must colour
 * the same severity identically; it lives here rather than in a new shared module.
 */

import { BASIS_LABELS } from "@/shared/labels";
import type { Severity } from "@/shared/schema";
import type { SeverityCounts } from "@/shared/viewModel";
import type { BasisCounts } from "@/client/useAnalysis";
import {
  FINDING_STATUSES,
  FINDING_STATUS_LABELS,
  type StatusCounts,
} from "@/client/findingStatus";

/** Display order, highest severity first. */
export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low"];

export const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

/** Badge styling, shared with ThreatCard so one severity always looks the same. */
export const SEVERITY_BADGE_CLASS: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/50",
  high: "bg-sev-high/15 text-sev-high border-sev-high/50",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/50",
  low: "bg-sev-low/15 text-sev-low border-sev-low/50",
};

/** Node border/accent, used by the architecture graph. Matches the --color-sev-* tokens. */
export const SEVERITY_ACCENT: Record<Severity, string> = {
  critical: "#b42336",
  high: "#9a4408",
  medium: "#765800",
  low: "#2f5bc9",
};

/** Pastel count tiles; the text on them stays the navy fg colour. */
const SEVERITY_TILE_CLASS: Record<Severity, string> = {
  critical: "bg-sev-critical-soft border-sev-critical/20",
  high: "bg-sev-high-soft border-sev-high/20",
  medium: "bg-sev-medium-soft border-sev-medium/20",
  low: "bg-sev-low-soft border-sev-low/20",
};

const SEVERITY_BAR_CLASS: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
};

type SeveritySummaryProps = {
  counts: SeverityCounts;
  basisCounts: BasisCounts | null;
  fixNowCount: number;
  /** The reader's own triage counts over the listed threats; omitted when not tracked. */
  statusCounts?: StatusCounts;
  /** Counts of threats below 25% confidence; the extra line shows only when any exist. */
  hiddenCounts?: SeverityCounts | null;
  /** Threats from the last run not re-found and not marked fixed (src/client/carryForward.ts). */
  carriedCount?: number;
};

/** "Including low-confidence: Critical a, High b, ..." (visible + hidden), or null when none are hidden. */
export function includingLowConfidenceLine(
  counts: SeverityCounts | undefined,
  hiddenCounts: SeverityCounts | null | undefined,
): string | null {
  const hiddenTotal = SEVERITY_ORDER.reduce((sum, s) => sum + readCount(hiddenCounts ?? undefined, s), 0);
  if (hiddenTotal === 0) return null;
  const parts = SEVERITY_ORDER.map(
    (s) => `${SEVERITY_TEXT[s]} ${readCount(counts, s) + readCount(hiddenCounts ?? undefined, s)}`,
  );
  return `Including low-confidence: ${parts.join(", ")}`;
}

function readCount(counts: SeverityCounts | undefined, severity: Severity): number {
  const value = counts?.[severity];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

export default function SeveritySummary({
  counts,
  basisCounts,
  fixNowCount,
  statusCounts,
  hiddenCounts = null,
  carriedCount = 0,
}: SeveritySummaryProps) {
  const including = includingLowConfidenceLine(counts, hiddenCounts);
  const total = SEVERITY_ORDER.reduce(
    (sum, severity) => sum + readCount(counts, severity),
    0,
  );

  return (
    <section
      aria-labelledby="severity-summary-heading"
      className="rounded-2xl border border-line bg-surface/70 p-5"
    >
      <h2
        id="severity-summary-heading"
        className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted"
      >
        Severity summary
      </h2>

      <dl className="mt-4 grid grid-cols-[repeat(auto-fit,minmax(6.5rem,1fr))] gap-3">
        {SEVERITY_ORDER.map((severity) => (
          <div key={severity} className={`rounded-xl border px-4 py-3 ${SEVERITY_TILE_CLASS[severity]}`}>
            <dt className="flex items-center gap-2 text-xs font-medium text-fg">
              <span aria-hidden="true" className={`h-2 w-2 rounded-full ${SEVERITY_BAR_CLASS[severity]}`} />
              {SEVERITY_TEXT[severity]}
            </dt>
            <dd className="mt-1 font-display text-3xl font-semibold tabular-nums text-fg">
              {readCount(counts, severity)}
            </dd>
          </div>
        ))}
        <div className="rounded-xl border border-teal/30 bg-teal/15 px-4 py-3">
          <dt className="text-xs font-medium text-fg">Fix now</dt>
          <dd className="mt-1 font-display text-3xl font-semibold tabular-nums text-fg">{fixNowCount}</dd>
        </div>
      </dl>

      {including ? (
        <p data-testid="including-low-confidence" className="mt-2 text-sm text-muted">
          {including}
        </p>
      ) : null}

      {total > 0 ? (
        <div aria-hidden="true" className="mt-4 flex h-1.5 w-full overflow-hidden rounded-full bg-surface-3">
          {SEVERITY_ORDER.map((severity) => {
            const count = readCount(counts, severity);
            return count > 0 ? (
              <span
                key={severity}
                className={SEVERITY_BAR_CLASS[severity]}
                style={{ width: `${(count / total) * 100}%` }}
              />
            ) : null;
          })}
        </div>
      ) : null}

      <p className="mt-4 text-sm text-muted">
        {total} threat{total === 1 ? "" : "s"} shown. Threats below 25% confidence are
        hidden by default.
      </p>

      {carriedCount > 0 ? (
        <p data-testid="carried-count" className="mt-1 text-sm text-muted">
          {carriedCount} from the last run not re-found and not marked fixed.
        </p>
      ) : null}

      {statusCounts ? (
        <p data-testid="status-counts" className="mt-1 text-sm text-muted">
          Your status:{" "}
          {FINDING_STATUSES.map(
            (value) => `${statusCounts[value]} ${FINDING_STATUS_LABELS[value].toLowerCase()}`,
          ).join(", ")}
          .
        </p>
      ) : null}

      {basisCounts ? (
        // Labelled "all scored threats" on purpose: the route derives basisCounts from the
        // full model, while the list above is the >= 0.25 confidence view. See
        // docs/build-log.md.
        <p className="mt-1 text-sm text-muted">
          Across all scored threats: {basisCounts.evidence_backed}{" "}
          {BASIS_LABELS.evidence_backed.toLowerCase()}, {basisCounts.assumption_dependent}{" "}
          {BASIS_LABELS.assumption_dependent.toLowerCase()}.
        </p>
      ) : null}
    </section>
  );
}
