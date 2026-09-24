"use client";

/**
 * Evidence for one threat, in the order the server supplied it.
 *
 * src/client/adapter.ts already sorts positive findings before missing-control (gap)
 * reasoning, so this component must not re-sort: the ordering is part of the analysis
 * result. It renders the list as given.
 *
 * Snippets are repository content and therefore untrusted (CLAUDE.md rule 3). They are
 * rendered as plain text inside <pre>, never as HTML, and never executed. React escapes
 * the value; there is no dangerouslySetInnerHTML anywhere in this tree.
 */

import type { EvidenceItem } from "@/shared/viewModel";

type EvidencePanelProps = {
  evidence: readonly EvidenceItem[];
  /** Ties the list to the threat heading for screen readers. */
  labelledBy?: string;
};

export default function EvidencePanel({ evidence, labelledBy }: EvidencePanelProps) {
  const items = Array.isArray(evidence) ? evidence : [];

  if (items.length === 0) {
    return (
      <p className="text-sm italic text-subtle">
        No evidence was cited for this threat.
      </p>
    );
  }

  return (
    <ul aria-labelledby={labelledBy} className="space-y-3">
      {items.map((item, index) => (
        <li
          key={`${item?.kind ?? "evidence"}-${index}`}
          className="rounded-xl border border-line bg-ink-2/70 p-3"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full border border-line-strong px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-muted">
              {item?.kindLabel ?? "Evidence"}
            </span>
            {item?.sourceLabel ? (
              <span className="text-[11px] text-subtle">
                via {item.sourceLabel}
              </span>
            ) : null}
          </div>

          <p className="mt-2 text-sm text-fg">
            {item?.summary ?? ""}
          </p>

          {item?.location ? (
            <p className="mt-1 break-all font-mono text-xs text-mint">
              {item.location}
            </p>
          ) : null}

          {item?.snippet ? (
            <pre className="mt-2 max-h-48 overflow-auto rounded-lg border border-line bg-ink p-3 font-mono text-xs leading-relaxed text-fg">
              <code>{item.snippet}</code>
            </pre>
          ) : null}
        </li>
      ))}
    </ul>
  );
}
