"use client";

/**
 * The "Since last run" panel, with a History tab.
 *
 * "Since last run" is two lines comparing this analysis with the previous one of the same
 * repository in this browser. Counts come from the threat diff and carryForward
 * (src/client/drift.ts, src/client/carryForward.ts); nothing is scored here.
 *
 * "History" lists the stored runs (src/client/runHistory.ts), newest first, each with how
 * many threats were new and not found against the run before it, and a timeline for one
 * threat: the runs it appeared in, its confidence each time, and when its status changed.
 *
 * A threat missing from a run is "not found", never resolved or fixed: the tool cannot tell
 * a code change from a run that sampled differently, and only a status the reader sets
 * records that a threat is closed.
 */

import { useState } from "react";
import type { DriftResult } from "@/client/drift";
import { FINDING_STATUS_LABELS } from "@/client/findingStatus";
import {
  formatRunTime,
  historyRows,
  levelLabel,
  threatTimeline,
  threatsAcrossRuns,
  type RunEntry,
} from "@/client/runHistory";

type SinceLastRunProps = {
  /** null when there is no previous run to compare with. */
  drift: Pick<DriftResult, "threats"> | null;
  /** Of the threats not found this run, how many the reader has not marked Fixed or False positive. */
  notClosedCount?: number;
  /** The previous run's date, YYYY-MM-DD, or null when unknown. */
  lastRunDate?: string | null;
  /** The stored runs, oldest first. The History tab appears only when there are some. */
  runs?: readonly RunEntry[];
  /** threatKey of the threat selected in the list, which the timeline starts on. */
  selectedKey?: string | null;
};

type Tab = "since" | "history";

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

const cell = "px-2 py-1 text-left font-normal";

function confidenceText(step: ReturnType<typeof threatTimeline>[number]): string {
  if (!step.found) return "Not found in this run";
  const pct = step.confidence === null ? "" : `${Math.round(step.confidence)}% confidence`;
  if (step.hidden) return pct ? `Found, unverified: ${pct}, below 25%` : "Found, unverified";
  return pct ? `Found, ${pct}` : "Found";
}

function History({ runs, selectedKey }: { runs: readonly RunEntry[]; selectedKey: string | null }) {
  const choices = threatsAcrossRuns(runs);
  const [chosen, setChosen] = useState<string | null>(null);
  const active =
    [chosen, selectedKey].find((key) => key !== null && choices.some((c) => c.key === key)) ??
    choices[0]?.key ??
    null;
  const timeline = active ? threatTimeline(runs, active).reverse() : [];

  return (
    <div className="mt-3 space-y-4 text-sm text-muted">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[34rem] border-collapse">
          <caption className="sr-only">Stored runs of this repository, newest first</caption>
          <thead>
            <tr className="text-[11px] uppercase tracking-[0.1em]">
              <th scope="col" className={cell}>Run</th>
              <th scope="col" className={cell}>Ref</th>
              <th scope="col" className={cell}>Level</th>
              <th scope="col" className={cell}>Threats</th>
              <th scope="col" className={cell}>Visible</th>
              <th scope="col" className={cell}>New</th>
              <th scope="col" className={cell}>Not found</th>
            </tr>
          </thead>
          <tbody>
            {historyRows(runs).map((row, index) => (
              <tr key={`${row.run.at}-${index}`} className="border-t border-line">
                <th scope="row" className={`${cell} text-fg`}>{formatRunTime(row.run.at)}</th>
                <td className={`${cell} font-mono`}>{row.run.ref || "unknown"}</td>
                <td className={cell}>{levelLabel(row.run.level)}</td>
                <td className={cell}>{row.threats}</td>
                <td className={cell}>{row.visible}</td>
                <td className={cell}>{row.newCount ?? "n/a"}</td>
                <td className={cell}>{row.notFoundCount ?? "n/a"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-2 text-xs">
          New and Not found compare each run with the one before it. Not found means the
          analysis did not report the threat that time. It is not the same as Fixed: only a
          status you set closes a threat.
        </p>
      </div>

      {choices.length > 0 ? (
        <div data-testid="threat-timeline">
          <label className="block text-[11px] font-medium uppercase tracking-[0.14em]">
            Timeline for
            <select
              value={active ?? ""}
              onChange={(event) => setChosen(event.target.value)}
              className="mt-1 block w-full max-w-xl rounded-lg border border-line bg-surface px-2 py-1 text-sm normal-case tracking-normal text-fg"
            >
              {choices.map((choice) => (
                <option key={choice.key} value={choice.key}>
                  {choice.title}
                </option>
              ))}
            </select>
          </label>
          <ol className="mt-2 space-y-1" aria-label="Runs, newest first">
            {timeline.map((step, index) => (
              <li
                key={`${step.run.at}-${index}`}
                data-found={step.found ? "true" : "false"}
                className="flex flex-wrap gap-x-3"
              >
                <span className="text-fg">{formatRunTime(step.run.at)}</span>
                <span className={step.found ? "" : "italic"}>{confidenceText(step)}</span>
                {step.statusChanges.map((change, i) => (
                  <span key={i} className="text-mint">
                    Status set to {FINDING_STATUS_LABELS[change.status]} on{" "}
                    {formatRunTime(change.at).slice(0, 10)}
                  </span>
                ))}
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </div>
  );
}

export default function SinceLastRun({
  drift,
  notClosedCount = 0,
  lastRunDate = null,
  runs = [],
  selectedKey = null,
}: SinceLastRunProps) {
  const [tab, setTab] = useState<Tab>("since");
  const hasHistory = runs.length > 0;
  const showing: Tab = hasHistory ? tab : "since";
  const tabClass = (id: Tab) =>
    `rounded-full px-3 py-1 text-xs transition-colors ${
      showing === id ? "bg-mint-deep text-fg" : "text-muted hover:text-fg"
    }`;

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
      {hasHistory ? (
        <div role="tablist" aria-label="Run comparison" className="mt-2 flex gap-1">
          <button
            type="button"
            role="tab"
            id="runs-tab-since"
            aria-selected={showing === "since"}
            aria-controls="runs-panel"
            onClick={() => setTab("since")}
            className={tabClass("since")}
          >
            Since last run
          </button>
          <button
            type="button"
            role="tab"
            id="runs-tab-history"
            aria-selected={showing === "history"}
            aria-controls="runs-panel"
            onClick={() => setTab("history")}
            className={tabClass("history")}
          >
            History
          </button>
        </div>
      ) : null}
      <div
        id="runs-panel"
        role={hasHistory ? "tabpanel" : undefined}
        aria-labelledby={hasHistory ? `runs-tab-${showing}` : undefined}
      >
        {showing === "history" ? (
          <History key={selectedKey ?? ""} runs={runs} selectedKey={selectedKey} />
        ) : drift === null ? (
          <p className="mt-2 text-sm text-muted">
            First run of this repository in this browser; nothing to compare with yet.
          </p>
        ) : (
          <>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
              <li>{plural(drift.threats.new.length, "new threat")} this run.</li>
              <li>
                {plural(drift.threats.notFound.length, "threat")} from the last run not found
                this run
                {drift.threats.notFound.length > 0
                  ? `, ${notClosedCount} of them not marked Fixed or False positive`
                  : ""}
                .
              </li>
            </ul>
            <p className="mt-2 text-xs text-muted">
              Not found is not the same as Fixed: only a status you set closes a threat.
            </p>
          </>
        )}
      </div>
    </section>
  );
}
