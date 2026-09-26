"use client";

/**
 * "Still open from the last run": threats the previous run listed, this run did not find,
 * and the reader has not marked Fixed or False positive (src/client/carryForward.ts).
 *
 * Greyed and below the list, with the severity and confidence the previous run gave them.
 * They are not part of this run: no counts, filters or Fix now include them. All text is
 * repository- or model-derived and rendered as text only.
 */

import type { CarriedThreat } from "@/client/carryForward";
import { FINDING_STATUS_LABELS } from "@/client/findingStatus";
import { SEVERITY_BADGE_CLASS, SEVERITY_TEXT } from "@/components/SeveritySummary";

type CarriedForwardProps = {
  threats: readonly CarriedThreat[];
  /** The previous run's date, YYYY-MM-DD, or null when the snapshot has none. */
  lastRunDate: string | null;
};

export default function CarriedForward({ threats, lastRunDate }: CarriedForwardProps) {
  if (threats.length === 0) return null;
  return (
    <section
      aria-labelledby="carried-forward-heading"
      data-testid="carried-forward"
      className="mt-8 opacity-70 grayscale"
    >
      <h3
        id="carried-forward-heading"
        className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted"
      >
        Still open from the last run{lastRunDate ? ` (${lastRunDate})` : ""}
      </h3>
      <p className="mt-1 text-sm text-muted">
        The previous run reported these, this run did not re-find them, and they are not
        marked Fixed or False positive. They are not counted in this run&apos;s summary, filters
        or Fix now.
      </p>
      <ul className="mt-3 space-y-2">
        {threats.map((threat) => (
          <li
            key={threat.key}
            className="rounded-2xl border border-dashed border-line-strong bg-surface/60 px-4 py-3"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider ${
                  SEVERITY_BADGE_CLASS[threat.severity] ?? SEVERITY_BADGE_CLASS.low
                }`}
              >
                {SEVERITY_TEXT[threat.severity] ?? threat.severity}
              </span>
              <span className="text-xs text-muted">{threat.confidence}% confidence last run</span>
              {threat.status !== "open" ? (
                <span className="rounded-full border border-line-strong px-2.5 py-0.5 text-[11px] font-semibold text-muted">
                  {FINDING_STATUS_LABELS[threat.status]}
                </span>
              ) : null}
            </div>
            <p className="mt-1 font-display text-base font-semibold text-fg">{threat.title}</p>
            <p className="mt-0.5 text-xs text-subtle">Not re-found this run.</p>
          </li>
        ))}
      </ul>
    </section>
  );
}
