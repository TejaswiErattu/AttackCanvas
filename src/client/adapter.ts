import {
  ANALYSIS_LEVEL_LABELS,
  Owasp2025Schema,
  StrideSchema,
  type AnalysisStage,
  type Component,
  type ConfidenceLabel,
  type DataFlow,
  type DeveloperQuestion,
  type ErrorCode,
  type Evidence,
  type Mitigation,
  type Priority,
  type Severity,
  type Threat,
  type ThreatModel,
} from "@/shared/schema";
import {
  BASIS_LABELS,
  ERROR_COPY,
  EVIDENCE_KIND_LABELS,
  EVIDENCE_SOURCE_LABELS,
  OWASP_LABELS,
  PRIORITY_LABELS,
  STAGE_LABELS,
  STRIDE_LABELS,
} from "@/shared/labels";
import { explainConfidence, isGapEvidence } from "@/shared/confidence";
import { exposureMap, type Exposure } from "@/client/exposure";
import type {
  AnalysisError,
  AnalysisStatus,
  DashboardViewModel,
  EvidenceItem,
  FilterOptions,
  GraphEdge,
  GraphNode,
  HiddenThreatCardData,
  MitigationData,
  QuestionData,
  SeverityCounts,
  ThreatCardData,
} from "@/shared/viewModel";

/**
 * Turns the ThreatModel contract into UI-ready data. Every function here is pure:
 * inputs are never mutated and nothing is read from outside the arguments.
 */

const FIX_NOW_LIMIT = 5;

/**
 * CLAUDE.md rule 2: threats below this confidence are hidden by default. Display-layer
 * only: they are kept apart in `hiddenThreats` so the list can show them on request.
 */
const HIDE_BELOW_CONFIDENCE = 0.25;

const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low"];
const CONFIDENCE_ORDER: readonly ConfidenceLabel[] = ["high", "medium", "low"];
const PRIORITY_RANK: Record<Priority, number> = {
  fix_now: 0,
  fix_soon: 1,
  monitor: 2,
};

/** The steps shown in a progress display, in order. `failed` is not a step. */
const STAGE_SEQUENCE: readonly AnalysisStage[] = [
  "queued",
  "loading_repo",
  "scanning",
  "mapping_architecture",
  "generating_threats",
  "awaiting_answers",
  "finalizing",
  "complete",
];

/**
 * Codes where the same request can succeed later: capacity frees up, an upstream service
 * recovers, a model's sampling differs. The rest fail the same way every time (a bad URL,
 * a refusal, a secret in the repository), so no retry button is offered for them.
 */
const RETRYABLE_ERRORS: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  "RATE_LIMITED",
  "AI_FAILURE",
  "TIMEOUT",
  "SERVER_BUSY",
  "UPSTREAM_RATE_LIMITED",
  "GITHUB_UNAVAILABLE",
  "MODEL_OUTPUT_INVALID",
  "NETWORK_ERROR",
]);

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

function isVisible(threat: Threat): boolean {
  return threat.confidence >= HIDE_BELOW_CONFIDENCE;
}

function riskOf(threat: Threat): number {
  return threat.impact * threat.likelihood;
}

/** Priority first, then risk, then confidence; id last so the order is stable. */
function compareThreats(a: Threat, b: Threat): number {
  return (
    PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] ||
    riskOf(b) - riskOf(a) ||
    b.confidence - a.confidence ||
    a.id.localeCompare(b.id)
  );
}

/** Fix Now order: severity, then confidence (both highest first); id keeps it stable. */
function compareFixNow(a: ThreatCardData, b: ThreatCardData): number {
  return (
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
    b.confidence - a.confidence ||
    a.id.localeCompare(b.id)
  );
}

function maxSeverityOf(threats: readonly Threat[]): Severity | null {
  return SEVERITY_ORDER.find((s) => threats.some((t) => t.severity === s)) ?? null;
}

// ---------------------------------------------------------------------------
// Evidence and threat cards
// ---------------------------------------------------------------------------

function formatLocation(evidence: Evidence): string | null {
  const { filePath, lineStart, lineEnd } = evidence;
  if (filePath === undefined) return null;
  if (lineStart === undefined) return filePath;
  if (lineEnd === undefined || lineEnd === lineStart) return `${filePath}:${lineStart}`;
  return `${filePath}:${lineStart}-${lineEnd}`;
}

function resolveEvidence(ids: readonly string[], lookups: Lookups): Evidence[] {
  return ids.flatMap((id) => {
    const evidence = lookups.evidence.get(id);
    return evidence ? [evidence] : [];
  });
}

/**
 * Positive findings first, missing-control (gap) reasoning last, so a user scanning a
 * card sees what was actually found before why a control is believed absent. `sort` is
 * stable, so within each group the original (evidenceIds) order is preserved.
 */
function sortEvidenceGapLast(items: readonly Evidence[]): Evidence[] {
  return [...items].sort((a, b) => Number(isGapEvidence(a)) - Number(isGapEvidence(b)));
}

/**
 * One line per contribution to a threat's confidence, ending with the total. The lines come
 * from src/shared/confidence.ts -- the code scoring itself uses -- so this file holds no
 * copy of the arithmetic. They are exact point values when the model carries enough to
 * reproduce the figure, and qualitative (with a closing note saying so) when it does not,
 * e.g. a missing control, whose points depend on a detector certainty the model lacks.
 */
function confidenceReasonsFor(threat: Threat, cited: readonly Evidence[]): string[] {
  const { exact, lines } = explainConfidence(cited, threat.assumptions, threat.confidence);
  const total = `Confidence ${Math.round(threat.confidence * 100)}% (${threat.confidenceLabel})`;
  return exact
    ? [...lines, total]
    : [...lines, `${total}. These are reasons, not scores that add up to it.`];
}

function toEvidenceItem(evidence: Evidence): EvidenceItem {
  return {
    kind: evidence.kind,
    kindLabel: EVIDENCE_KIND_LABELS[evidence.kind],
    summary: evidence.summary,
    location: formatLocation(evidence),
    snippet: evidence.snippet ?? null,
    sourceLabel: EVIDENCE_SOURCE_LABELS[evidence.source],
  };
}

function toMitigationData(mitigation: Mitigation): MitigationData {
  return {
    summary: mitigation.summary,
    steps: [...mitigation.steps],
    codeLocation: mitigation.codeLocation ?? null,
  };
}

type Lookups = {
  componentNames: ReadonlyMap<string, string>;
  flowNames: ReadonlyMap<string, string>;
  evidence: ReadonlyMap<string, Evidence>;
};

function buildLookups(model: ThreatModel): Lookups {
  return {
    componentNames: new Map(model.components.map((c) => [c.id, c.name])),
    flowNames: new Map(
      model.dataFlows.map((f) => {
        const name = (id: string) => model.components.find((c) => c.id === id)?.name ?? id;
        return [f.id, `${name(f.sourceId)} \u2192 ${name(f.targetId)}`];
      }),
    ),
    evidence: new Map(model.evidence.map((e) => [e.id, e])),
  };
}

function toThreatCard(threat: Threat, lookups: Lookups): ThreatCardData {
  return {
    id: threat.id,
    title: threat.title,
    severity: threat.severity,
    confidence: Math.round(threat.confidence * 100),
    confidenceLabel: threat.confidenceLabel,
    priority: threat.priority,
    priorityLabel: PRIORITY_LABELS[threat.priority],
    stride: threat.stride.map((code) => ({ code, label: STRIDE_LABELS[code] })),
    owasp: threat.owasp.map((code) => ({ code, label: OWASP_LABELS[code] })),
    cwe: [...threat.cwe],
    basis: threat.basis,
    basisLabel: BASIS_LABELS[threat.basis],
    // A validated model always resolves; fall back to the id rather than crash the UI.
    componentNames: threat.componentIds.map(
      (id) => lookups.componentNames.get(id) ?? id,
    ),
    affectedNames: [
      ...new Set([
        ...threat.componentIds.map((id) => lookups.componentNames.get(id) ?? id),
        ...threat.dataFlowIds.flatMap((id) => {
          const name = lookups.flowNames.get(id);
          return name ? [name] : [];
        }),
      ]),
    ],
    componentIds: [...threat.componentIds],
    dataFlowIds: [...threat.dataFlowIds],
    confidenceReasons: confidenceReasonsFor(
      threat,
      resolveEvidence(threat.evidenceIds, lookups),
    ),
    attackScenario: threat.attackScenario,
    evidence: sortEvidenceGapLast(resolveEvidence(threat.evidenceIds, lookups)).map(
      toEvidenceItem,
    ),
    mitigation: toMitigationData(threat.mitigation),
    assumptions: [...threat.assumptions],
  };
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

function toGraphNode(
  component: Component,
  threats: readonly Threat[],
  exposure: ReadonlyMap<string, Exposure>,
): GraphNode {
  const affecting = threats.filter((t) => t.componentIds.includes(component.id));
  return {
    id: component.id,
    type: component.type,
    label: component.name,
    position: component.position ? { ...component.position } : { x: 0, y: 0 },
    threatCount: affecting.length,
    maxSeverity: maxSeverityOf(affecting),
    technologies: [...component.technologies],
    assets: [...component.assets],
    exposure: exposure.get(component.id) ?? "internal",
  };
}

function toGraphEdge(flow: DataFlow): GraphEdge {
  return {
    id: flow.id,
    source: flow.sourceId,
    target: flow.targetId,
    label: flow.label,
    crossesTrustBoundary: flow.crossesTrustBoundary,
    dataClassification: flow.dataClassification,
  };
}

// ---------------------------------------------------------------------------
// Counts and filters
// ---------------------------------------------------------------------------

function countBySeverity(threats: readonly Threat[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const threat of threats) counts[threat.severity] += 1;
  return counts;
}

function buildFilterOptions(
  model: ThreatModel,
  threats: readonly Threat[],
): FilterOptions {
  const usedStride = new Set(threats.flatMap((t) => t.stride));
  const usedOwasp = new Set(threats.flatMap((t) => t.owasp));
  const usedComponents = new Set(threats.flatMap((t) => t.componentIds));
  const usedConfidence = new Set(threats.map((t) => t.confidenceLabel));

  const stride = StrideSchema.options
    .filter((code) => usedStride.has(code))
    .map((code) => ({ code, label: STRIDE_LABELS[code] }));
  const owasp = Owasp2025Schema.options
    .filter((code) => usedOwasp.has(code))
    .map((code) => ({ code, label: OWASP_LABELS[code] }));

  return {
    severities: SEVERITY_ORDER.filter((s) => threats.some((t) => t.severity === s)),
    stride,
    owasp,
    components: model.components
      .filter((c) => usedComponents.has(c.id))
      .map((c) => ({ id: c.id, name: c.name })),
    confidenceLabels: CONFIDENCE_ORDER.filter((l) => usedConfidence.has(l)),
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function toDashboardViewModel(model: ThreatModel): DashboardViewModel {
  // The one visible-threat list. Counts, fixNow, fixNowTotal, threats, node stats and
  // filter options all derive from it, so a hidden threat cannot leak into any of them.
  // filter() returns a new array, so sorting it leaves model.threats untouched.
  const visible = model.threats.filter(isVisible).sort(compareThreats);
  const hidden = model.threats.filter((t) => !isVisible(t)).sort(compareThreats);
  const lookups = buildLookups(model);
  const threats = visible.map((threat) => toThreatCard(threat, lookups));
  const hiddenThreats = hidden.map(
    (threat): HiddenThreatCardData => ({ ...toThreatCard(threat, lookups), belowCutoff: true }),
  );
  // Selected by the server-computed priority only; nothing is re-scored here.
  // Rated on the full flow list, so a sub-view that hides a flow never changes a badge.
  const exposure = exposureMap(
    model.components,
    model.dataFlows.map((flow) => ({ source: flow.sourceId, target: flow.targetId })),
  );
  const fixNowCards = threats
    .filter((t) => t.priority === "fix_now")
    .sort(compareFixNow);

  return {
    analysisLevel: model.analysisLevel,
    analysisLevelLabel: ANALYSIS_LEVEL_LABELS[model.analysisLevel],
    repo: {
      fullName: `${model.repo.owner}/${model.repo.name}`,
      ref: model.repo.ref,
      frameworks: [...model.repo.frameworks],
      fileCount: model.repo.fileCountAnalyzed,
      analyzedAt: model.repo.analyzedAt,
    },
    counts: countBySeverity(visible),
    fixNow: fixNowCards.slice(0, FIX_NOW_LIMIT),
    fixNowTotal: fixNowCards.length,
    nodes: model.components.map((component) => toGraphNode(component, visible, exposure)),
    edges: model.dataFlows.map(toGraphEdge),
    boundaries: model.trustBoundaries.map((boundary) => ({
      id: boundary.id,
      name: boundary.name,
      componentIds: [...boundary.componentIds],
    })),
    threats,
    hiddenThreats,
    hiddenCounts: countBySeverity(hidden),
    assumptions: [...model.assumptions],
    limitations: [...model.limitations],
    // Over every scored threat: the list shows the ones below 25% too, so the filters must
    // reach them.
    filterOptions: buildFilterOptions(model, [...visible, ...hidden]),
  };
}

export function toQuestionData(
  questions: readonly DeveloperQuestion[],
): QuestionData[] {
  return questions.map((question, position) => ({
    id: question.id,
    text: question.text,
    whyAsking: question.whyAsking,
    options: [...question.options],
    allowsUnsure: question.allowsUnsure,
    defaultAssumption: question.defaultAssumption,
    index: position + 1,
    total: questions.length,
  }));
}

export function toAnalysisStatus(stage: AnalysisStage): AnalysisStatus {
  return {
    stage,
    stageLabel: STAGE_LABELS[stage],
    // indexOf is -1 for `failed`, which lands on 0: "not a step".
    stageIndex: STAGE_SEQUENCE.indexOf(stage) + 1,
    stageCount: STAGE_SEQUENCE.length,
  };
}

/**
 * `message` overrides the default copy when it is non-blank. Callers must pass
 * text that is safe to show to a user — never a raw upstream error.
 */
export function toAnalysisError(code: ErrorCode, message?: string): AnalysisError {
  const copy = ERROR_COPY[code];
  const custom = message?.trim();
  return {
    code,
    title: copy.title,
    message: custom ? custom : copy.message,
    canRetry: RETRYABLE_ERRORS.has(code),
  };
}
