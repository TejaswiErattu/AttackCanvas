/**
 * "How to read these numbers": one plain line for each figure the dashboard shows.
 *
 * Every number comes from a constant, not from typed text, so the explanation moves with the
 * code: confidence points from CONFIDENCE_POINTS (src/shared/confidence.ts), the display
 * cutoff from the adapter's HIDE_BELOW_CONFIDENCE, the Basis names from BASIS_LABELS. The
 * severity bands and the Fix now bar have no shared constant (they are literals in
 * src/server/scoring), so they are written once here as constants and tests/glossary.test.tsx
 * checks them against severityOf, priorityOf and confidenceLabelOf. Nothing is computed.
 */

import { GAP_FLOOR, CONFIDENCE_POINTS } from "@/shared/confidence";
import { BASIS_LABELS } from "@/shared/labels";
import { HIDE_BELOW_CONFIDENCE } from "@/client/adapter";

/** Lowest risk (impact x likelihood, each 1-5) of each severity. */
export const SEVERITY_FLOORS = { critical: 20, high: 12, medium: 6, low: 1 } as const;
/** Confidence a High threat needs for Fix now, and a Medium one for Fix soon. */
export const PRIORITY_CONFIDENCE_BAR = 0.5;
/** Lowest confidence labelled High and Medium. */
export const LABEL_FLOORS = { high: 0.7, medium: 0.4 } as const;

export type GlossaryEntry = { id: string; term: string; text: string };

/** Thousandths as a signed two-decimal string: 350 -> "+0.35", -150 -> "-0.15". */
function points(thousandths: number): string {
  const value = Math.abs(thousandths) / 1000;
  return `${thousandths < 0 ? "-" : "+"}${value.toFixed(2)}`;
}

const two = (value: number): string => value.toFixed(2);
const percent = (value: number): string => `${Math.round(value * 100)}%`;

export function glossaryEntries(): GlossaryEntry[] {
  const p = CONFIDENCE_POINTS;
  const bands = SEVERITY_FLOORS;
  const bar = two(PRIORITY_CONFIDENCE_BAR);
  return [
    {
      id: "severity",
      term: "Severity bands",
      text:
        `Severity is risk, impact times likelihood (each 1 to 5): ${bands.critical}-25 is Critical, ` +
        `${bands.high}-${bands.critical - 1} High, ${bands.medium}-${bands.high - 1} Medium, ` +
        `${bands.low}-${bands.medium - 1} Low.`,
    },
    {
      id: "confidence",
      term: "Confidence points",
      text:
        `Confidence adds up the evidence, kept between 0 and 1: code evidence ${points(p.code)}, a missing ` +
        `control ${points(p.controlGap)} times how certain the check is, a Semgrep finding ${points(p.semgrep)}, ` +
        `a vulnerable dependency (OSV) ${points(p.osv)}, a developer answer ${points(p.developer)}, a second ` +
        `independent source ${points(p.secondSource)}, inference only ${points(p.inferenceOnly)}, and each ` +
        `unconfirmed assumption ${points(p.assumption)}. A threat resting only on near-certain missing ` +
        `controls (combined certainty ${two(p.gapFloorCertainty / 1000)} or more) is raised to ${two(GAP_FLOOR)}. ` +
        `High is ${two(LABEL_FLOORS.high)} and above, Medium ${two(LABEL_FLOORS.medium)} to ` +
        `${two(LABEL_FLOORS.high - 0.01)}, Low below ${two(LABEL_FLOORS.medium)}.`,
    },
    {
      id: "cutoff",
      term: `The ${percent(HIDE_BELOW_CONFIDENCE)} cutoff`,
      text:
        `A threat scored below ${percent(HIDE_BELOW_CONFIDENCE)} confidence is not hidden: it is listed ` +
        "last, greyed and marked unverified, and counted in the severity tiles, but it never counts toward Fix now.",
    },
    {
      id: "priority",
      term: "Fix now, Fix soon, Monitor",
      text:
        `Fix now is every Critical threat, and High ones at ${bar} confidence or more. Fix soon is High ` +
        `below ${bar}, or Medium at ${bar} or more. Monitor is everything else.`,
    },
    {
      id: "basis",
      term: `${BASIS_LABELS.evidence_backed} vs ${BASIS_LABELS.assumption_dependent}`,
      text:
        `"${BASIS_LABELS.evidence_backed}" means at least one piece of evidence is something the analysis ` +
        `saw in the code or its scans. "${BASIS_LABELS.assumption_dependent}" means the threat rests only on a ` +
        "control the checks could not find, or on inference, so it is a prediction to verify.",
    },
    {
      id: "not-found",
      term: "Not found is not fixed",
      text:
        "A threat missing from a later run was not reported that time. The code may have changed, or the " +
        "analysis may have missed it, so only a status you set marks a threat as fixed.",
    },
    {
      id: "unverified",
      term: "Unverified threat",
      text:
        `A threat below ${percent(HIDE_BELOW_CONFIDENCE)} confidence: the evidence behind it is missing, ` +
        "weak or rests on unconfirmed assumptions. Review it before acting on it.",
    },
  ];
}
