"use client";

/**
 * The "Since last run" panel: two lines comparing this analysis with the previous one of
 * the same repository in this browser. Counts come from diffThreatModels and carryForward
 * (src/client/drift.ts, src/client/carryForward.ts); nothing is scored here.
 *
 * A threat missing from this run is "not found this run", never resolved or fixed: the
 * tool cannot tell a code change from a run that sampled differently, and only a status the
 * reader sets records that a threat is closed.
 */

import type { DriftResult } from "@/client/drift";

type SinceLastRunProps = {
  /** null when there is no previous run to compare with. */
  drift: DriftResult | null;
  /** Of the threats not found this run, how many the reader has not marked Fixed or False positive. */
  notClosedCount?: number;
  /** The previous run's date, YYYY-MM-DD, or null when unknown. */
  lastRunDate?: string | null;
};

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

export default function SinceLastRun({
  drift,
  notClosedCount = 0,
  lastRunDate = null,
}: SinceLastRunProps) {
  return (
    <section
      aria-labelledby="since-last-run-heading"
      data-testid="since-last-run"
      className="rounded-2xl border border-line bg-surface/70 px-5 py-4"
    >
      <h2
        id="since-last-run-heading"
        className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted"
      >
        Since last run{drift && lastRunDate ? ` (${lastRunDate})` : ""}
      </h2>
      {drift === null ? (
        <p className="mt-2 text-sm text-muted">
          First run of this repository in this browser; nothing to compare with yet.
        </p>
      ) : (
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
          <li>{plural(drift.threats.new.length, "new threat")} this run.</li>
          <li>
            {plural(drift.threats.notFound.length, "threat")} from the last run not found this
            run
            {drift.threats.notFound.length > 0
              ? `, ${notClosedCount} of them not marked Fixed or False positive`
              : ""}
            .
          </li>
        </ul>
      )}
    </section>
  );
}
