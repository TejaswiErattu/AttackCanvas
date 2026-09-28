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
import { dedupe } from "@/server/analysis/limitations";
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
  /**
   * Reader-facing limitations already produced upstream: userLimitations() over the merge's
   * and the engine's notes, plus plain caveats such as OSV's. Never diagnostics.
   */
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

/**
 * Reader-facing wording only (src/server/analysis/limitations.ts): what the reader should
 * take into account, never how the pipeline produced it.
 */
export const STATIC_ANALYSIS_LIMITATION =
  "Findings come from reading the source code, not running it. Routes registered at run time, framework conventions the analysis does not recognise, and controls applied in code it could not trace may be missed, or reported as missing when they are present.";

/** What each gap check looks for, as a reader would name it. */
const GAP_KIND_TEXT: Record<GapKind, string> = {
  authz_missing: "ownership and role checks",
  authn_missing: "authentication",
  rate_limit_missing: "rate limiting",
  csrf_missing: "CSRF protection",
  security_headers_missing: "security response headers",
  input_validation_missing: "input validation",
  transport_insecure: "transport encryption",
  password_storage_weak: "password hashing",
  logging_missing: "security logging",
  error_handling_gap: "error handling",
  cors_permissive: "cross-origin (CORS) policy",
  supply_chain_integrity: "dependency integrity",
  client_secret_storage: "secret storage in the browser",
};

/** Plain names for upstream stages a caller may report as dropped. */
const STAGE_TEXT: Record<string, string> = {
  semgrep: "The Semgrep code scanner",
  osv: "The dependency vulnerability lookup (OSV)",
};

function automaticLimitations(input: AssembleInput): string[] {
  const out: string[] = [];

  const disabled = sortedUnique(input.disabledGapKinds ?? []);
  if (disabled.length > 0) {
    const names = disabled.map((kind) => GAP_KIND_TEXT[kind] ?? kind.replace(/_/g, " "));
    out.push(
      `The checks for ${names.join(", ")} did not run, so no finding about ${disabled.length === 1 ? "it" : "them"} does not mean ${disabled.length === 1 ? "it is" : "they are"} in place.`,
    );
  }

  out.push(STATIC_ANALYSIS_LIMITATION);

  const lowCertainty = input.gaps.filter((g) => g.certainty < GAP_ASSERT_CERTAINTY).length;
  if (lowCertainty > 0) {
    out.push(
      `${lowCertainty} possible missing ${lowCertainty === 1 ? "control" : "controls"} could not be confirmed from the code, so ${lowCertainty === 1 ? "it is" : "they are"} treated as uncertain rather than reported as ${lowCertainty === 1 ? "a finding" : "findings"}.`,
    );
  }

  for (const stage of sortedUnique(input.droppedStages ?? [])) {
    const name = STAGE_TEXT[stage] ?? `The ${stage.replace(/_/g, " ")} step`;
    out.push(`${name} could not run, so findings it would have added are missing.`);
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
    // By id, byte order: the model's arrays must not depend on the order a stage happened
    // to list things in. (Trust boundaries and unknowns keep theirs: the diagram puts a
    // component in the first boundary that lists it, and unknowns are ranked.)
    components: [...input.components].sort((a, b) => cmp(a.id, b.id)),
    dataFlows: [...input.dataFlows].sort((a, b) => cmp(a.id, b.id)),
    trustBoundaries: [...input.trustBoundaries],
    unknowns: [...input.unknowns],
    evidence,
    threats: scored,
    questions: [],
    assumptions: sortedUnique(input.assumptions),
    // Reader-facing only, each sentence once (src/server/analysis/limitations.ts).
    limitations: dedupe([...input.limitations, ...automaticLimitations(input)]),
  };

  const validated = validateThreatModel(model);
  if (!validated.ok) {
    return { ok: false, issues: validated.issues };
  }
  return { ok: true, model: validated.data };
}
