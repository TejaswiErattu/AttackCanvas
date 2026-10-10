"use client";

/**
 * "Download CSV" and "Download JSON" above the threat list.
 *
 * The CSV is the threats the list is showing right now, in the list's order: the caller
 * passes exactly the threats it renders after every filter. The JSON is the server's
 * ThreatModel as it was sent, untouched: not the dashboard view model, and with no display
 * fields, local statuses or filters. Both are built and saved in the browser; nothing is
 * sent to a server. When the model was not sent (a partial or older response) the JSON
 * button is off rather than saving something else.
 */

import { downloadText } from "@/client/download";
import { buildThreatsCsv, exportFileName } from "@/client/exportCsv";
import type { FindingStatus } from "@/client/findingStatus";
import type { ThreatModel } from "@/shared/schema";
import type { ThreatCardData } from "@/shared/viewModel";

type ExportButtonsProps = {
  repoName: string | undefined;
  /** The ThreatModel exactly as the server sent it; null when it was not sent. */
  model: ThreatModel | null;
  /** The threats currently listed, filters applied, in list order. */
  listed: readonly ThreatCardData[];
  statuses: Readonly<Record<string, FindingStatus>>;
};

const BUTTON =
  "rounded-full border border-line bg-ink-2/70 px-3 py-1 text-xs text-muted transition-colors hover:border-line-strong hover:text-fg disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:border-line disabled:hover:text-muted";

export default function ExportButtons({ repoName, model, listed, statuses }: ExportButtonsProps) {
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2" data-testid="export-buttons">
      <button
        type="button"
        className={BUTTON}
        onClick={() =>
          downloadText(exportFileName(repoName, "csv"), buildThreatsCsv(listed, statuses), "text/csv", true)
        }
      >
        Download CSV
      </button>
      <button
        type="button"
        className={BUTTON}
        disabled={model === null}
        title={model === null ? "The full model was not sent with this result." : undefined}
        onClick={() => {
          if (model) {
            downloadText(
              exportFileName(repoName, "json"),
              JSON.stringify(model, null, 2),
              "application/json",
            );
          }
        }}
      >
        Download JSON
      </button>
      <span className="text-xs text-muted">
        CSV has the {listed.length} threat{listed.length === 1 ? "" : "s"} listed below. JSON is
        the full analysis result.
      </span>
    </div>
  );
}
