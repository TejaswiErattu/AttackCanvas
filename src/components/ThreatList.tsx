"use client";

/**
 * The threat list, in the server's order.
 *
 * DashboardViewModel.threats is already sorted by priority, then risk, then confidence,
 * then id (src/client/adapter.ts). That ordering is part of the scored result, so this
 * component never re-sorts — filtering narrows the list but leaves the sequence intact.
 * (The dashboard alone moves handled findings after open ones within a priority band; see
 * orderByStatus in src/client/findingStatus.ts.)
 */

import type { ThreatCardData } from "@/shared/viewModel";
import type { HiddenReason, HiddenSummary } from "@/client/useAnalysis";
import ThreatCard from "@/components/ThreatCard";
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
};

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
}: ThreatListProps) {
  const items = Array.isArray(threats) ? threats : [];

  if (items.length === 0) {
    return (
      <p className="rounded-2xl border border-dashed border-line-strong p-8 text-center text-sm text-muted">
        {emptyMessage(totalCount, hiddenSummary)}
      </p>
    );
  }

  return (
    <div>
      <p className="mb-3 text-sm text-muted" aria-live="polite">
        Showing {items.length} of {totalCount} threat{totalCount === 1 ? "" : "s"}
      </p>
      <ul className="space-y-3">
        {items.map((threat) => (
          <li key={threat.id}>
            <ThreatCard
              threat={threat}
              selected={selectedId === threat.id}
              onSelect={onSelect}
              status={statusOf(statuses, threat.id)}
              onStatusChange={onStatusChange}
              repo={repo}
            />
          </li>
        ))}
      </ul>
    </div>
  );
}
