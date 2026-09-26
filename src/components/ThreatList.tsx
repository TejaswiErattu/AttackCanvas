"use client";

/**
 * The threat list, in the server's order.
 *
 * DashboardViewModel.threats is already sorted by priority, then risk, then confidence,
 * then id (src/client/adapter.ts). That ordering is part of the scored result, so this
 * component never re-sorts — filtering narrows the list but leaves the sequence intact.
 * (The dashboard alone moves handled findings after open ones within a priority band; see
 * orderByStatus in src/client/findingStatus.ts.)
 *
 * Threats below 25% confidence are off by default. The "Show N low-confidence threats"
 * toggle lists them after the visible ones, greyed and badged as unverified. They are
 * display only and never enter the "Showing x of y" count.
 */

import type { ThreatCardData } from "@/shared/viewModel";
import type { HiddenReason, HiddenSummary } from "@/client/useAnalysis";
import ThreatCard from "@/components/ThreatCard";
import { threatKey } from "@/client/drift";
import type { IssueRepo } from "@/client/issueBody";
import { statusOf, type FindingStatus, type StatusMap } from "@/client/findingStatus";

type ThreatListProps = {
  threats: readonly ThreatCardData[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  /** Total before filtering, used to tell "no threats" apart from "no matches". */
  totalCount: number;
  /** Scored and hidden counts over the whole model, for an honest empty state. */
  hiddenSummary?: HiddenSummary | null;
  statuses?: StatusMap;
  onStatusChange?: (id: string, status: FindingStatus) => void;
  repo?: IssueRepo;
  /** Threat keys (threatKey in src/client/drift.ts) that are new since the last run. */
  newKeys?: ReadonlySet<string>;
  /** Filtered below-25% threats (the view model's hiddenThreats), shown after the list when `showHidden` is on. */
  hiddenThreats?: readonly ThreatCardData[];
  /** All below-25% threats before filtering, for the toggle's "Show N" label. */
  hiddenTotal?: number;
  showHidden?: boolean;
  onShowHiddenChange?: (show: boolean) => void;
};

export const SHOW_HIDDEN_ID = "show-low-confidence";

export function showHiddenLabel(n: number): string {
  return `Show ${n} low-confidence threat${n === 1 ? "" : "s"}`;
}

const REASON_TEXT: Record<HiddenReason, string> = {
  no_evidence: "no cited evidence",
  assumptions: "unconfirmed assumptions",
  weak_evidence: "evidence too weak on its own",
};

/**
 * The empty-list message. When the model scored threats and every one fell below the
 * threshold, it says so with the most common reason, rather than implying nothing was
 * found. Pure, so it is tested without rendering.
 */
export function emptyMessage(
  totalCount: number,
  hidden: HiddenSummary | null | undefined,
): string {
  if (totalCount > 0) return "No threats match the current filters. Clear a filter to see more.";
  if (!hidden || hidden.hidden === 0) {
    return "This analysis produced no threats above the confidence threshold.";
  }
  const n = hidden.hidden;
  const lead =
    n === hidden.scored
      ? `${n} threat${n === 1 ? " was" : "s were"} scored; all fell below 25% confidence.`
      : `${n} of ${hidden.scored} scored threats fell below 25% confidence.`;
  return hidden.topReason
    ? `${lead} Most common reason: ${REASON_TEXT[hidden.topReason]} (${hidden.topReasonCount} of ${n}).`
    : lead;
}

export default function ThreatList({
  threats,
  selectedId,
  onSelect,
  totalCount,
  hiddenSummary = null,
  statuses = {},
  onStatusChange,
  repo,
  newKeys,
  hiddenThreats = [],
  hiddenTotal = 0,
  showHidden = false,
  onShowHiddenChange,
}: ThreatListProps) {
  const items = Array.isArray(threats) ? threats : [];
  const lowItems = showHidden && Array.isArray(hiddenThreats) ? hiddenThreats : [];
  const canToggle = hiddenTotal > 0 && onShowHiddenChange !== undefined;

  const card = (threat: ThreatCardData, belowCutoff: boolean) => (
    <li key={threat.id}>
      <ThreatCard
        threat={threat}
        selected={selectedId === threat.id}
        onSelect={onSelect}
        status={statusOf(statuses, threat.id)}
        onStatusChange={onStatusChange}
        repo={repo}
        isNew={newKeys?.has(threatKey(threat)) ?? false}
        belowCutoff={belowCutoff}
      />
    </li>
  );

  const toggle = canToggle ? (
    <label className="mb-3 flex items-center gap-2 text-sm text-muted">
      <input
        id={SHOW_HIDDEN_ID}
        type="checkbox"
        checked={showHidden}
        onChange={(event) => onShowHiddenChange?.(event.target.checked)}
        className="h-4 w-4 accent-mint"
      />
      {showHiddenLabel(hiddenTotal)}
    </label>
  ) : null;

  if (items.length === 0 && lowItems.length === 0) {
    return (
      <div>
        {toggle}
        <p className="rounded-2xl border border-dashed border-line-strong p-8 text-center text-sm text-muted">
          {emptyMessage(totalCount, hiddenSummary)}
          {canToggle && !showHidden ? (
            <>
              {" "}
              <button
                type="button"
                onClick={() => onShowHiddenChange?.(true)}
                aria-controls={SHOW_HIDDEN_ID}
                className="text-mint underline underline-offset-2"
              >
                {showHiddenLabel(hiddenTotal)}
              </button>
            </>
          ) : null}
        </p>
      </div>
    );
  }

  return (
    <div>
      {toggle}
      <p className="mb-3 text-sm text-muted" aria-live="polite">
        {items.length
          ? `Showing ${items.length} of ${totalCount} threat${totalCount === 1 ? "" : "s"}`
          : emptyMessage(totalCount, hiddenSummary)}
      </p>
      {items.length ? (
        <ul className="space-y-3">{items.map((threat) => card(threat, false))}</ul>
      ) : null}
      {lowItems.length ? (
        <section aria-label="Low-confidence threats" className="mt-6">
          <h3 className="mb-3 text-[11px] font-medium uppercase tracking-[0.14em] text-muted">
            Below 25% confidence ({lowItems.length})
          </h3>
          <ul className="space-y-3">{lowItems.map((threat) => card(threat, true))}</ul>
        </section>
      ) : null}
    </div>
  );
}
