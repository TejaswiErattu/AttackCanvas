import type {
  Basis,
  ConfidenceLabel,
  DraftThreat,
  Evidence,
  Priority,
  Severity,
  Threat,
} from "@/shared/schema";
import type { ControlGap } from "@/server/detect/types";
import {
  GAP_FLOOR,
  confidenceOf,
  explainConfidence,
  isGapEvidence,
  type ConfidenceExplanation,
} from "@/shared/confidence";

// The confidence arithmetic lives in src/shared/confidence.ts so the dashboard can explain a
// figure with the same code; it is re-exported here so scoring stays the one public home.
export { GAP_FLOOR, confidenceOf, explainConfidence, isGapEvidence };
export type { ConfidenceExplanation };

/**
 * Deterministic scoring (CLAUDE.md rule 2). Pure functions, no I/O, never a model.
 *
 * Confidence is computed in integer thousandths so a boundary such as 0.40 or 0.70 is
 * exact and never a float accident. The gap floor's 0.80 certainty sum is too.
 */

/** Confidence below this is hidden by the display layer. */
export const HIDE_BELOW = 0.25;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export function severityOf(impact: number, likelihood: number): Severity {
  const risk = impact * likelihood;
  if (risk >= 20) return "critical";
  if (risk >= 12) return "high";
  if (risk >= 6) return "medium";
  return "low";
}

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

export function confidenceLabelOf(value: number): ConfidenceLabel {
  if (value >= 0.7) return "high";
  if (value >= 0.4) return "medium";
  return "low";
}

/** True when the display layer hides a threat of this confidence. */
export function isHidden(confidence: number): boolean {
  return confidence < HIDE_BELOW;
}

// ---------------------------------------------------------------------------
// Basis and priority
// ---------------------------------------------------------------------------

/**
 * A positive observation (rule 2): not a gap, and not an inference or an assumption. An
 * inference is a conclusion, not an observation, so it never makes a threat
 * evidence_backed, whatever its ruleId says.
 */
/**
 * A positive observation (CLAUDE.md rule 2): not a control gap, not an inference, not an
 * assumption. The one definition basisOf and the threat engine's dedupe both use.
 */
export function isPositiveObservation(e: Evidence): boolean {
  return !isGapEvidence(e) && e.kind !== "assumption" && e.kind !== "inference";
}

export function basisOf(evidence: readonly Evidence[]): Basis {
  return evidence.some(isPositiveObservation) ? "evidence_backed" : "assumption_dependent";
}

export function priorityOf(severity: Severity, confidence: number): Priority {
  if (severity === "critical") return "fix_now";
  if (severity === "high") return confidence >= 0.5 ? "fix_now" : "fix_soon";
  if (severity === "medium" && confidence >= 0.5) return "fix_soon";
  return "monitor";
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

export type ScoredThreat = {
  threat: Threat;
  /** Human-readable confidence arithmetic, shown in the UI. */
  breakdown: string[];
  hidden: boolean;
};

/**
 * Scores one draft. `evidence` is every evidence item available; only the ones the draft
 * cites (by id) are used. `gaps` maps a gap's evidence id (ev-gap-3) to its ControlGap.
 */
export function scoreThreat(
  draft: DraftThreat,
  id: string,
  evidence: readonly Evidence[],
  gaps: ReadonlyMap<string, ControlGap>,
): ScoredThreat {
  const cited = evidence.filter((e) => draft.evidenceIds.includes(e.id));
  const { value, breakdown } = confidenceOf(cited, gaps, draft.assumptions, draft.cwe);
  const severity = severityOf(draft.impact, draft.likelihood);
  return {
    threat: {
      ...draft,
      id,
      severity,
      confidence: value,
      confidenceLabel: confidenceLabelOf(value),
      basis: basisOf(cited),
      priority: priorityOf(severity, value),
    },
    breakdown,
    hidden: isHidden(value),
  };
}
