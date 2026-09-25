import type { Evidence } from "./schema";

/**
 * The confidence arithmetic (CLAUDE.md rule 2), shared so the dashboard can explain a
 * threat's confidence with the very code that computed it -- src/server/scoring re-exports
 * everything here and adds severity, priority and assembly. Pure: no I/O, never a model.
 *
 * Confidence is computed in integer thousandths so a boundary such as 0.40 or 0.70 is
 * exact and never a float accident. The gap floor's 0.80 certainty sum is too.
 */

/**
 * The fields of a control gap the arithmetic reads; a server ControlGap satisfies it.
 * `cwe` is the weaknesses the gap asserts, which bound what the gap floor may vouch for.
 */
export type GapCertainty = { control: string; certainty: number; cwe?: readonly string[] };

/** Confidence a gap-only threat is lifted to when the gaps are near-certain. */
export const GAP_FLOOR = 0.4;
/**
 * Combined gap certainty needed for the floor (0.80), in thousandths like the points:
 * each certainty is rounded to thousandths before summing, so 0.7 + 0.1 reaches it
 * exactly instead of falling to the float 0.7999999999999999.
 */
const GAP_FLOOR_CERTAINTY = 800;

// Points in thousandths.
const CODE = 350;
const GAP_WEIGHT = 300; // multiplied by certainty
const SEMGREP = 250;
const OSV = 300;
const DEVELOPER = 300;
const SECOND_SOURCE = 100;
const INFERENCE_ONLY = 200;
const ASSUMPTION = -150;

type Category = "code" | "gap" | "semgrep" | "osv" | "developer" | "inference";

export function isGapEvidence(e: Evidence): boolean {
  return e.ruleId?.startsWith("gap:") === true;
}

/**
 * The confidence category an evidence item feeds, or undefined when it earns nothing
 * (assumption evidence, or a scanner/dependency item from a source we do not weight).
 * The gap prefix is checked first: gap evidence has kind "code" or "config".
 */
function categoryOf(e: Evidence): Category | undefined {
  if (isGapEvidence(e)) return "gap";
  switch (e.kind) {
    case "code":
    case "config":
      return "code";
    case "scanner":
      return e.source === "semgrep" ? "semgrep" : undefined;
    case "dependency":
      return e.source === "osv" ? "osv" : undefined;
    case "developer_answer":
      return "developer";
    case "inference":
      return "inference";
    default:
      return undefined;
  }
}

/** Thousandths as a signed two-decimal string: 285 -> "+0.29", -150 -> "-0.15". */
function signed(thousandths: number): string {
  const sign = thousandths < 0 ? "-" : "+";
  return `${sign}${(Math.round(Math.abs(thousandths) / 10) / 100).toFixed(2)}`;
}

function certaintyText(certainty: number): string {
  return (Math.round(certainty * 100) / 100).toFixed(2);
}

/**
 * A gap's certainty clamped to 0..1, or undefined when the gap is missing or its
 * certainty is not a finite number. Undefined counts as 0 in arithmetic but is reported
 * as "not scored" rather than as a numeric contribution.
 */
function certaintyOf(gap: GapCertainty | undefined): number | undefined {
  const c = gap?.certainty;
  if (typeof c !== "number" || !Number.isFinite(c)) return undefined;
  return Math.min(1, Math.max(0, c));
}

/** Points a non-gap item would earn on its own, used to pick one item per shared location. */
function pointsOf(e: Evidence): number {
  switch (categoryOf(e)) {
    case "code":
      return CODE;
    case "semgrep":
      return SEMGREP;
    case "osv":
      return OSV;
    case "developer":
      return DEVELOPER;
    case "inference":
      return INFERENCE_ONLY;
    default:
      return 0;
  }
}

/**
 * One item per file:line (CLAUDE.md rule 2): items pointing to the same file and line are
 * one source, so a dependency declaration and an advisory on the same package.json line
 * are not two independent confirmations. The highest-scoring item is kept (the first on a
 * tie). Items without both a file and a line are never merged, and neither are control
 * gaps: a gap asserts that a control is missing, a different claim from a positive
 * observation at the same line (an IDOR gap and its route both point at the route line).
 */
function onePerLocation(evidence: readonly Evidence[]): Evidence[] {
  const kept = new Map<string, Evidence>();
  const unlocated: Evidence[] = [];
  for (const e of evidence) {
    if (e.filePath === undefined || e.lineStart === undefined || isGapEvidence(e)) {
      unlocated.push(e);
      continue;
    }
    const key = `${e.filePath}:${e.lineStart}`;
    const current = kept.get(key);
    if (current === undefined || pointsOf(e) > pointsOf(current)) kept.set(key, e);
  }
  const keep = new Set([...unlocated, ...kept.values()]);
  return evidence.filter((e) => keep.has(e));
}

/**
 * A threat's confidence and its UI breakdown (CLAUDE.md rule 2). `claimedCwe` is the
 * threat's own CWE list: the gap floor applies only when every CWE it claims is one the
 * cited gaps assert, so a gap vouches for the missing control and nothing built on it.
 * Evidence sharing a file and line counts once (onePerLocation).
 */
export function confidenceOf(
  evidence: readonly Evidence[],
  gaps: ReadonlyMap<string, GapCertainty>,
  assumptions: readonly string[],
  claimedCwe: readonly string[],
): { value: number; breakdown: string[] } {
  const byCategory = new Map<Category, Evidence[]>();
  for (const e of onePerLocation(evidence)) {
    const category = categoryOf(e);
    if (category === undefined) continue;
    byCategory.set(category, [...(byCategory.get(category) ?? []), e]);
  }

  const breakdown: string[] = [];
  let total = 0;
  const add = (points: number, text: string) => {
    total += points;
    breakdown.push(`${signed(points)} ${text}`);
  };

  // Certainties of the gaps behind gap evidence. Missing or invalid ones are undefined
  // and count as 0 in sums.
  const gapEntries = (byCategory.get("gap") ?? []).map((e) => {
    const gap = gaps.get(e.id);
    return { gap, certainty: certaintyOf(gap) };
  });
  const valid = gapEntries.filter(
    (g): g is { gap: GapCertainty; certainty: number } => g.certainty !== undefined,
  );
  const strongest = valid.reduce<(typeof valid)[number] | undefined>(
    (best, g) => (best === undefined || g.certainty > best.certainty ? g : best),
    undefined,
  );

  if (byCategory.has("code")) add(CODE, "code evidence");
  if (strongest !== undefined) {
    add(
      Math.round(GAP_WEIGHT * strongest.certainty),
      `control gap: no ${strongest.gap.control} (certainty ${certaintyText(strongest.certainty)})`,
    );
  } else if (gapEntries.length > 0) {
    breakdown.push("control gap not scored: missing or invalid certainty");
  }
  if (byCategory.has("semgrep")) add(SEMGREP, "Semgrep finding");
  if (byCategory.has("osv")) add(OSV, "known vulnerable dependency (OSV)");
  if (byCategory.has("developer")) add(DEVELOPER, "developer answer");

  // Supporting evidence, per rule 2: an inference is a conclusion, not direct support,
  // so it is never a second source, never blocks the gap floor and never counts toward it.
  // It earns its own points only when nothing else does ("inference only").
  const contributing = [...byCategory.keys()].filter((c) => c !== "inference");
  if (contributing.length >= 2) {
    add(SECOND_SOURCE, `second independent source (${contributing.length} kinds)`);
  }
  if (contributing.length === 0 && byCategory.has("inference")) {
    add(INFERENCE_ONLY, "inference only");
  }

  for (const assumption of assumptions) {
    add(ASSUMPTION, `unconfirmed assumption: ${assumption}`);
  }

  let value = total;
  const gapOnly = contributing.length === 1 && contributing[0] === "gap";
  const gapCertaintySum = valid.reduce((sum, g) => sum + Math.round(g.certainty * 1000), 0);
  if (gapOnly && gapCertaintySum >= GAP_FLOOR_CERTAINTY && value < GAP_FLOOR * 1000) {
    const asserted = new Set(valid.flatMap((g) => g.gap.cwe ?? []));
    const claimed = [...new Set(claimedCwe)];
    const beyond = claimed.filter((cwe) => !asserted.has(cwe));
    if (claimed.length > 0 && beyond.length === 0) {
      value = GAP_FLOOR * 1000;
      breakdown.push(`floor ${GAP_FLOOR.toFixed(2)} applied: gap-only with high certainty`);
    } else {
      // With no CWE the threat's scope cannot be checked against the gap's, so no floor.
      breakdown.push(
        claimed.length === 0
          ? `floor ${GAP_FLOOR.toFixed(2)} not applied: the threat claims no CWE`
          : `floor ${GAP_FLOOR.toFixed(2)} not applied: the threat also claims ${beyond.join(", ")}, which the cited gaps do not assert`,
      );
    }
  }

  value = Math.min(1000, Math.max(0, value));
  return { value: value / 1000, breakdown };
}


// ---------------------------------------------------------------------------
// Explaining a confidence figure from the model alone
// ---------------------------------------------------------------------------

export type ConfidenceExplanation = {
  /**
   * True when `lines` are the exact point-by-point arithmetic and add up to the
   * threat's confidence. False when they are qualitative and must not be read as a sum.
   */
  exact: boolean;
  lines: string[];
};

const QUALITATIVE: Record<Category, string> = {
  code: "Backed by code or configuration evidence",
  gap: "Supported by a missing-control finding; how much it adds depends on the detector's certainty",
  semgrep: "Confirmed by a Semgrep finding",
  osv: "Confirmed by a known vulnerable dependency (OSV)",
  developer: "Confirmed by a developer answer",
  inference: "Rests on an inference, which counts only when nothing else supports the threat",
};
/**
 * The gap floor, qualitatively: a gap-only threat stored at exactly the floor was raised to
 * it; one below it was not, because its gaps were not near-certain or it claims a weakness
 * beyond them. The model does not carry gap certainty or gap CWEs, so which one is unknown.
 */
const FLOOR_APPLIED =
  "Raised to the 40% minimum for a near-certain missing control: every weakness it claims is one the missing-control finding asserts";
const FLOOR_NOT_APPLIED =
  "Not raised to the 40% minimum for a missing control: that needs near-certain missing-control findings and no claimed weakness beyond theirs";

const QUALITATIVE_ORDER: readonly Category[] = [
  "code",
  "gap",
  "semgrep",
  "osv",
  "developer",
  "inference",
];

/**
 * Why a threat has the confidence it has, from what a ThreatModel carries: the evidence it
 * cites, its assumptions and its stored confidence. A missing control's points are
 * `certainty x 0.30`, and the detector's certainty is not in the model, so:
 *   - no gap evidence, and recomputing from the evidence gives exactly `confidence`: the
 *     real breakdown from confidenceOf, line for line;
 *   - otherwise (gap evidence, or a stored confidence the evidence does not reproduce,
 *     such as a hand-edited model): qualitative lines with no point values, flagged
 *     `exact: false`, so nothing implies they add up.
 */
export function explainConfidence(
  cited: readonly Evidence[],
  assumptions: readonly string[],
  confidence: number,
): ConfidenceExplanation {
  // The model carries neither gap certainty nor gap CWEs, so the map is empty and this
  // recomputation is used only when no gap is cited (the floor then cannot apply).
  const { value, breakdown } = confidenceOf(cited, new Map(), assumptions, []);
  if (!cited.some(isGapEvidence) && Math.round(value * 1000) === Math.round(confidence * 1000)) {
    return { exact: true, lines: breakdown };
  }
  const present = new Set(cited.map(categoryOf));
  const gapOnly = [...present].every((c) => c === "gap" || c === "inference" || c === undefined);
  const floorLine =
    present.has("gap") && gapOnly
      ? Math.round(confidence * 1000) === GAP_FLOOR * 1000
        ? FLOOR_APPLIED
        : Math.round(confidence * 1000) < GAP_FLOOR * 1000
          ? FLOOR_NOT_APPLIED
          : undefined
      : undefined;
  return {
    exact: false,
    lines: [
      ...QUALITATIVE_ORDER.filter((c) => present.has(c)).map((c) => QUALITATIVE[c]),
      ...assumptions.map((a) => `Lowered by an unconfirmed assumption: ${a}`),
      ...(floorLine ? [floorLine] : []),
    ],
  };
}
