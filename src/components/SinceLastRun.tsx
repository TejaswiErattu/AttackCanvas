"use client";

/**
 * The "Since last run" panel: what this analysis found that the previous one of the same
 * repository did not, and what it no longer finds. Counts and lists come from
 * diffThreatModels (src/client/drift.ts); nothing is scored here. All names are repository-
 * or model-derived text and are rendered as text only.
 *
 * A threat missing from this run is "not found this run", and one still scored but under
 * 25% confidence is "dropped below 25%". Neither is called resolved or fixed: the tool
 * cannot tell a code change from a run that sampled differently, and only a status the
 * reader sets records that a threat is closed.
 */

import type { DriftResult } from "@/client/drift";

type SinceLastRunProps = {
  /** null when there is no previous run to compare with. */
  drift: DriftResult | null;
};

function Group({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <h4 className="text-[11px] font-medium uppercase tracking-[0.14em] text-mint">
        {title} ({items.length})
      </h4>
      {items.length ? (
        <ul className="mt-1 list-disc space-y-0.5 pl-5 text-sm text-muted">
          {items.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="mt-1 text-sm text-subtle">None</p>
      )}
    </div>
  );
}

export default function SinceLastRun({ drift }: SinceLastRunProps) {
  return (
    <section
      aria-labelledby="since-last-run-heading"
      data-testid="since-last-run"
      className="rounded-2xl border border-line bg-surface/70 p-5"
    >
      <h2
        id="since-last-run-heading"
        className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted"
      >
        Since last run
      </h2>
      {drift === null ? (
        <p className="mt-3 text-sm text-muted">
          No previous run of this repository in this browser, so there is nothing to compare
          with yet. Run it again later to see what changed.
        </p>
      ) : (
        <div className="mt-3 space-y-4">
          <p className="text-sm text-muted">
            Threats: {drift.threats.new.length} new, {drift.threats.persisting.length} persisting,{" "}
            {drift.threats.notFound.length} not found this run,{" "}
            {drift.threats.droppedBelowCutoff.length} dropped below 25%. Components:{" "}
            {drift.components.added.length}{" "}
            added, {drift.components.removed.length} removed. Flows: {drift.flows.added.length}{" "}
            added, {drift.flows.removed.length} removed.
          </p>
          <p className="text-sm text-subtle">
            A threat this run did not report may still be present: the analysis reads code and
            can miss what an earlier run found. Set a status on a threat to record that it is
            closed.
          </p>
          <div className="grid gap-4 md:grid-cols-2">
            <Group title="New threats" items={drift.threats.new.map((t) => t.title)} />
            <Group
              title="Not found this run"
              items={drift.threats.notFound.map((t) =>
                t.belowCutoff ? `${t.title} (was below 25%)` : t.title,
              )}
            />
            <Group
              title="Dropped below 25%"
              items={drift.threats.droppedBelowCutoff.map((t) => `${t.title} (now ${t.confidence}%)`)}
            />
            <Group
              title="Components added"
              items={drift.components.added.map((c) => `${c.name} (${c.type})`)}
            />
            <Group
              title="Components removed"
              items={drift.components.removed.map((c) => `${c.name} (${c.type})`)}
            />
            <Group
              title="Flows added"
              items={drift.flows.added.map((f) => `${f.source} → ${f.target}: ${f.label}`)}
            />
            <Group
              title="Flows removed"
              items={drift.flows.removed.map((f) => `${f.source} → ${f.target}: ${f.label}`)}
            />
          </div>
        </div>
      )}
    </section>
  );
}
