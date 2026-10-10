"use client";

/**
 * The Limitations list in the caveats panel.
 *
 * Every wire limitation is one sentence, as before. When the server sent detail for it
 * (src/shared/viewModel.ts LimitationDetail), the sentence becomes a disclosure: closed it
 * is the sentence alone, open it lists what the sentence groups. A listed name that is a
 * component of the view is a button that selects that node; any other name is plain text.
 * A "gap_bound_broadly" line also names the kinds of missing control involved.
 *
 * Presentation only: nothing here changes what the analysis found.
 */

import { GAP_KIND_LABELS } from "@/shared/labels";
import type { GraphNode, LimitationDetail } from "@/shared/viewModel";

type NodeRef = Pick<GraphNode, "id" | "label">;

const normalize = (text: string): string =>
  text
    .trim()
    .toLowerCase()
    .replace(/^the\s+/, "")
    .replace(/\s+/g, " ");

/** The component a subject names (ignoring case, spacing and a leading "the"), if any. */
export function findNodeForSubject(subject: string, nodes: readonly NodeRef[]): NodeRef | undefined {
  const wanted = normalize(subject);
  if (wanted === "") return undefined;
  return nodes.find((node) => normalize(node.label) === wanted);
}

/** Plain names for the gap kinds, in the order given; a kind with no label is skipped. */
export function gapKindNames(kinds: readonly string[]): string[] {
  const labels: Record<string, string> = GAP_KIND_LABELS;
  return kinds.flatMap((kind) => (labels[kind] ? [labels[kind]] : []));
}

type Props = {
  /** `view.limitations`: the sentences, as they are on the wire. */
  lines: readonly string[];
  details?: readonly LimitationDetail[];
  nodes: readonly NodeRef[];
  onSelectNode: (id: string) => void;
};

export default function Limitations({ lines, details = [], nodes, onSelectNode }: Props) {
  const bySentence = new Map(details.map((detail) => [detail.sentence, detail]));

  return (
    <ul className="mt-2 space-y-1 text-sm text-muted">
      {lines.map((line, index) => {
        const detail = bySentence.get(line);
        const kinds = gapKindNames(detail?.gapKinds ?? []);
        if (!detail || (detail.subjects.length === 0 && kinds.length === 0)) {
          return (
            <li key={index} className="flex gap-2">
              <span aria-hidden="true" className="w-3 shrink-0 text-center">
                &bull;
              </span>
              <span>{line}</span>
            </li>
          );
        }
        return (
          <li key={index}>
            <details className="group" data-testid={`limitation-${detail.code}`}>
              <summary className="flex cursor-pointer list-none gap-2 marker:hidden [&::-webkit-details-marker]:hidden">
                <span
                  aria-hidden="true"
                  className="w-3 shrink-0 self-start text-center transition-transform group-open:rotate-90"
                >
                  &#9656;
                </span>
                <span>{line}</span>
              </summary>
              <div className="ml-5 mt-1 space-y-1">
                {kinds.length ? (
                  <p>
                    <span className="text-fg">Missing controls involved:</span> {kinds.join(", ")}
                  </p>
                ) : null}
                {detail.subjects.length ? (
                  <ul className="list-disc space-y-0.5 pl-5">
                    {detail.subjects.map((subject) => {
                      const node = findNodeForSubject(subject, nodes);
                      return (
                        <li key={subject}>
                          {node ? (
                            <button
                              type="button"
                              onClick={() => onSelectNode(node.id)}
                              className="text-left text-mint underline decoration-dotted underline-offset-2 hover:decoration-solid"
                            >
                              {subject}
                              <span className="sr-only"> (select this component in the diagram)</span>
                            </button>
                          ) : (
                            <span>{subject}</span>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                ) : null}
              </div>
            </details>
          </li>
        );
      })}
    </ul>
  );
}
