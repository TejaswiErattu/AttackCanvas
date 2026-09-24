/**
 * Model assembly (Prompt Q). The last deterministic step before a ThreatModel leaves the
 * pipeline.
 *
 * Everything upstream is untrusted or unscored: threats.ts (Prompt P2) hands over threats
 * whose classification came from a model and whose severity, confidence, basis and
 * priority do not exist yet. This module normalises classification, resolves every
 * evidence citation to the real Evidence object, scores each threat with
 * src/server/scoring (never reinventing that math, per CLAUDE.md rule 2), and assembles
 * the complete ThreatModel the dashboard renders.
 *
 * Fail-fast, like Prompt P2: an evidence reference that does not resolve, or a model that
 * still fails schema validation, produces typed issues naming the offending path. Nothing
 * is repaired, nothing partial is returned.
 */

import type { ControlGap, GapKind } from "@/server/detect/types";
import { isGapEvidence, scoreThreat } from "@/server/scoring";
import { mapOwasp2021 } from "@/shared/owaspMap";
import {
  Owasp2025Schema,
  validateThreatModel,
  type AnalysisLevel,
  type Component,
  type DataFlow,
  type DraftThreat,
  type Evidence,
  type Owasp2025,
  type RepoSummary,
  type Stride,
  type ThreatModel,
  type TrustBoundary,
  type Unknown,
  type ValidationIssue,
} from "@/shared/schema";
import { GAP_ASSERT_CERTAINTY } from "@/server/analysis/architecture";
import { gapEvidenceId } from "@/server/analysis/context";
import { STRIDE_ORDER } from "@/server/analysis/threatPrompt";
import { normalizeThreat, type EngineThreat } from "@/server/analysis/threats";

// ---------------------------------------------------------------------------
// Public shape
// ---------------------------------------------------------------------------

export type AssembleInput = {
  analysisLevel: AnalysisLevel;
  repo: RepoSummary;
  components: readonly Component[];
  dataFlows: readonly DataFlow[];
  trustBoundaries: readonly TrustBoundary[];
  unknowns: readonly Unknown[];
  /** Every evidence item available, detector, Semgrep and OSV alike. */
  evidence: readonly Evidence[];
  /** Unscored threats from generateThreats, ids already assigned. */
  threats: readonly EngineThreat[];
  /** The detector's gaps, so gap certainty and gap classification can be read back. */
  gaps: readonly ControlGap[];
  assumptions: readonly string[];
  /** Limitations already produced upstream (architecture merge, threat engine). */
  limitations: readonly string[];
  /** Gap kinds a caller disabled or cut before detection ran. */
  disabledGapKinds?: readonly GapKind[];
  /** Upstream analysis stages a caller could not run or had to drop. */
  droppedStages?: readonly string[];
};

export type AssembleResult =
  | { ok: true; model: ThreatModel }
  | { ok: false; issues: ValidationIssue[] };

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sortedUnique<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values)].sort(cmp);
}

/** Fixed, stage-independent number extracted from "threat-7"; ties fall back to string order. */
function threatOrderKey(id: string): [number, string] {
  const match = /^threat-(\d+)$/.exec(id);
  return [match ? Number(match[1]) : Number.POSITIVE_INFINITY, id];
}

function compareThreatIds(a: string, b: string): number {
  const [na, sa] = threatOrderKey(a);
  const [nb, sb] = threatOrderKey(b);
  return na - nb || cmp(sa, sb);
}

// ---------------------------------------------------------------------------
// 1. Classification normalisation
// ---------------------------------------------------------------------------

/**
 * A code is kept as-is when it is already a valid OWASP Top 10:2025 category, translated
 * via src/shared/owaspMap.ts when it is a 2021 code, and dropped otherwise: an invalid
 * code is not a fact to preserve. Defensive rather than load-bearing today, since
 * DraftThreatSchema's owasp field already accepts only Owasp2025 values -- but assemble
 * treats every incoming field as untrusted, the same way CLAUDE.md rule 3 treats
 * repository content.
 */
function normalizeOwaspCodes(raw: readonly string[]): Owasp2025[] {
  const mapped: Owasp2025[] = [];
  for (const code of raw) {
    if (Owasp2025Schema.safeParse(code).success) {
      mapped.push(code as Owasp2025);
      continue;
    }
    const translated = mapOwasp2021(code);
    if (translated !== undefined) mapped.push(translated);
  }
  return sortedUnique(mapped);
}

type Classification = { owasp: Owasp2025[]; cwe: string[]; stride: Stride[] };

/**
 * Normalises one threat's classification and, when it cites nothing but gap evidence and
 * arrives with no OWASP mapping, inherits owasp/cwe/stride from the cited gaps'
 * classification (the same fields detectGaps stamped onto each ControlGap). A
 * model-supplied non-empty value is never overwritten. A gap-driven threat that still has
 * no OWASP mapping after the union falls back to A06:2025 Insecure Design, which is the
 * honest category for a design-level risk with no sharper fit. No CWE fallback is
 * invented: an empty cwe array is valid (ThreatSchema places no minimum on it) and stays
 * empty when nothing defensible is available.
 */
function classifyThreat(
  threat: DraftThreat,
  evidenceById: ReadonlyMap<string, Evidence>,
  gapByEvidenceId: ReadonlyMap<string, ControlGap>,
): Classification {
  const owasp = normalizeOwaspCodes(threat.owasp);
  const cwe = sortedUnique(threat.cwe);
  const stride = STRIDE_ORDER.filter((s) => threat.stride.includes(s));

  const cited = threat.evidenceIds
    .map((id) => evidenceById.get(id))
    .filter((e): e is Evidence => e !== undefined);
  const gapOnly = cited.length > 0 && cited.every(isGapEvidence);

  if (owasp.length > 0 || !gapOnly) {
    return { owasp, cwe, stride };
  }

  const gaps = cited
    .map((e) => gapByEvidenceId.get(e.id))
    .filter((g): g is ControlGap => g !== undefined);
  const gapOwasp = sortedUnique(gaps.flatMap((g) => g.owasp));
  const gapCwe = sortedUnique(gaps.flatMap((g) => g.cwe));
  const gapStride = STRIDE_ORDER.filter((s) => gaps.some((g) => g.stride.includes(s)));

  return {
    owasp: gapOwasp.length > 0 ? gapOwasp : (["A06:2025"] as Owasp2025[]),
    cwe: cwe.length > 0 ? cwe : gapCwe,
    stride: stride.length > 0 ? stride : gapStride,
  };
}

// ---------------------------------------------------------------------------
// 2. Evidence resolution
// ---------------------------------------------------------------------------

/** One unresolved evidenceId, named by the threat that cited it. */
function unresolvedEvidenceIssues(
  threat: EngineThreat,
  evidenceById: ReadonlyMap<string, Evidence>,
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  threat.evidenceIds.forEach((id, index) => {
    if (!evidenceById.has(id)) {
      issues.push({
        path: `threats.${threat.id}.evidenceIds[${index}]`,
        message: `evidence "${id}" cited by threat "${threat.id}" does not resolve to a known evidence item`,
      });
    }
  });
  return issues;
}

// ---------------------------------------------------------------------------
// 3. Automatic limitations
// ---------------------------------------------------------------------------

const REGEX_LIMITATION =
  "Detection is regex-based over source text and may miss dynamically registered routes, framework conventions it does not recognise, or controls supplied by middleware it cannot follow to its definition.";

function automaticLimitations(input: AssembleInput): string[] {
  const out: string[] = [];

  for (const kind of sortedUnique(input.disabledGapKinds ?? [])) {
    out.push(`Control gap detector "${kind}" was disabled or cut and did not run.`);
  }

  out.push(REGEX_LIMITATION);

  const lowCertainty = input.gaps.filter(
    (g) => g.certainty < GAP_ASSERT_CERTAINTY,
  ).length;
  out.push(
    `${lowCertainty} control gap(s) fell below the ${GAP_ASSERT_CERTAINTY.toFixed(2)} certainty threshold and were treated as unknowns rather than confirmed findings.`,
  );

  for (const stage of input.droppedStages ?? []) {
    out.push(`Upstream analysis stage "${stage}" was dropped or unavailable.`);
  }

  return out;
}

// ---------------------------------------------------------------------------
// assembleThreatModel
// ---------------------------------------------------------------------------

export function assembleThreatModel(input: AssembleInput): AssembleResult {
  const evidenceById = new Map(input.evidence.map((e) => [e.id, e]));
  const gapByEvidenceId = new Map(
    input.gaps.map((g) => [gapEvidenceId(g), g] as const),
  );

  const threats = [...input.threats].sort((a, b) => compareThreatIds(a.id, b.id));

  // Resolve evidence before doing anything else: a threat citing something that does not
  // exist is not repaired or dropped (CLAUDE.md rule 2's discipline applied to rule 5).
  const unresolved = threats.flatMap((t) => unresolvedEvidenceIssues(t, evidenceById));
  if (unresolved.length > 0) {
    return { ok: false, issues: unresolved };
  }

  const scored = threats.map((threat) => {
    const classification = classifyThreat(threat, evidenceById, gapByEvidenceId);
    // normalizeThreat also sorts and deduplicates componentIds, dataFlowIds,
    // evidenceIds, assumptions and dependsOnUnknownIds, so the result never depends on
    // the order a caller happened to list them in.
    const draft: DraftThreat = normalizeThreat({
      ...threat,
      owasp: classification.owasp,
      cwe: classification.cwe,
      stride: classification.stride,
    });
    return scoreThreat(draft, threat.id, input.evidence, gapByEvidenceId).threat;
  });

  const citedEvidenceIds = new Set(scored.flatMap((t) => t.evidenceIds));
  const evidence = input.evidence
    .filter((e) => citedEvidenceIds.has(e.id))
    .sort((a, b) => cmp(a.id, b.id));

  const model: ThreatModel = {
    schemaVersion: "1.0",
    analysisLevel: input.analysisLevel,
    repo: input.repo,
    components: [...input.components],
    dataFlows: [...input.dataFlows],
    trustBoundaries: [...input.trustBoundaries],
    unknowns: [...input.unknowns],
    evidence,
    threats: scored,
    questions: [],
    assumptions: sortedUnique(input.assumptions),
    limitations: [...input.limitations, ...automaticLimitations(input)],
  };

  const validated = validateThreatModel(model);
  if (!validated.ok) {
    return { ok: false, issues: validated.issues };
  }
  return { ok: true, model: validated.data };
}
