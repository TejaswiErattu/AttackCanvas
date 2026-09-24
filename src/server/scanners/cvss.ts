/**
 * Severity from what OSV provides, used only to decide which findings survive the
 * 40-item cap and in what order. It is a scanner's rating, not a AttackCanvas severity:
 * that is computed in src/server/scoring and never by a model (CLAUDE.md rule 2).
 */

export type SeverityLabel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type Severity = { score?: number; label?: SeverityLabel };

const ATTACK_VECTOR: Record<string, number> = {
  N: 0.85,
  A: 0.62,
  L: 0.55,
  P: 0.2,
};
const ATTACK_COMPLEXITY: Record<string, number> = { L: 0.77, H: 0.44 };
const USER_INTERACTION: Record<string, number> = { N: 0.85, R: 0.62 };
const IMPACT: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

/**
 * A metric value's weight, or undefined. Own properties only: the vector is external
 * data, and a plain `table[value]` answers "constructor" or "__proto__" with something
 * inherited from Object.prototype, which turned the score into NaN.
 */
function weight(
  table: Record<string, number>,
  value: string | undefined,
): number | undefined {
  return value !== undefined &&
    Object.prototype.hasOwnProperty.call(table, value)
    ? table[value]
    : undefined;
}

/** CVSS 3.1 Roundup: the smallest one-decimal value not below the input. */
export function roundUp(value: number): number {
  const scaled = Math.round(value * 100000);
  if (scaled % 10000 === 0) return scaled / 100000;
  return (Math.floor(scaled / 10000) + 1) / 10;
}

function metrics(vector: string): Record<string, string> | undefined {
  const parts = vector.trim().split("/");
  if (!/^CVSS:3\.[01]$/.test(parts[0] ?? "")) return undefined;

  const found: Record<string, string> = {};
  for (const part of parts.slice(1)) {
    const [key, value] = part.split(":");
    if (key && value) found[key] = value;
  }
  return found;
}

/**
 * Base score from a CVSS v3.0 or v3.1 vector, or undefined for anything else (v2, v4,
 * a malformed string). Computed rather than read because OSV carries the vector, not
 * the number, and the number is what makes findings comparable.
 */
export function cvssV3Score(vector: string): number | undefined {
  const m = metrics(vector);
  if (!m) return undefined;

  const scopeChanged = m.S === "C";
  if (m.S !== "U" && m.S !== "C") return undefined;

  const attackVector = weight(ATTACK_VECTOR, m.AV);
  const complexity = weight(ATTACK_COMPLEXITY, m.AC);
  const interaction = weight(USER_INTERACTION, m.UI);
  const confidentiality = weight(IMPACT, m.C);
  const integrity = weight(IMPACT, m.I);
  const availability = weight(IMPACT, m.A);

  const privilegeTable: Record<string, number> = scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }
    : { N: 0.85, L: 0.62, H: 0.27 };
  const privileges = weight(privilegeTable, m.PR);

  if (
    attackVector === undefined ||
    complexity === undefined ||
    interaction === undefined ||
    confidentiality === undefined ||
    integrity === undefined ||
    availability === undefined ||
    privileges === undefined
  )
    return undefined;

  const iss = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;

  const exploitability =
    8.22 * attackVector * complexity * privileges * interaction;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);

  return roundUp(raw);
}

/** The qualitative rating for a base score, per the CVSS v3 specification. */
export function labelForScore(score: number): SeverityLabel | undefined {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return undefined;
}

/** GitHub advisories say MODERATE where CVSS says MEDIUM. */
export function labelFromText(text: string): SeverityLabel | undefined {
  switch (text.trim().toUpperCase()) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MODERATE":
    case "MEDIUM":
      return "MEDIUM";
    case "LOW":
      return "LOW";
    default:
      return undefined;
  }
}

/** A representative score for a label alone, so unscored findings still sort sensibly. */
const LABEL_SCORE: Record<SeverityLabel, number> = {
  CRITICAL: 9.5,
  HIGH: 8,
  MEDIUM: 5.5,
  LOW: 2.5,
};

/**
 * OSV's severity: a computed CVSS v3 score when a vector is present, otherwise the
 * advisory's own label. Anything unrecognised is left undefined, and sorts last.
 */
export function severityOf(
  entries: readonly { type?: unknown; score?: unknown }[],
  databaseLabel: unknown,
): Severity {
  for (const entry of entries) {
    if (typeof entry.score !== "string") continue;
    const score = cvssV3Score(entry.score);
    if (score !== undefined) {
      const label = labelForScore(score);
      return { score, ...(label ? { label } : {}) };
    }
  }

  const label =
    typeof databaseLabel === "string"
      ? labelFromText(databaseLabel)
      : undefined;
  return label ? { label } : {};
}

/** A single sortable number: the score, else the label's stand-in, else 0. */
export function rank(severity: Severity): number {
  if (severity.score !== undefined) return severity.score;
  if (severity.label) return LABEL_SCORE[severity.label];
  return 0;
}
