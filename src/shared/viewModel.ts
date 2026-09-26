import type {
  AnalysisLevel,
  AnalysisStage,
  Basis,
  ComponentType,
  ConfidenceLabel,
  DataClassification,
  ErrorCode,
  EvidenceKind,
  Owasp2025,
  Priority,
  Severity,
  Stride,
} from "./schema";

/**
 * UI-ready shapes. Everything a component needs is already resolved here — names
 * instead of ids, labels instead of enum codes — and no field is ever `undefined`:
 * absent values are `null`, `[]` or `{ x: 0, y: 0 }`. Built by src/client/adapter.ts.
 */

/** Where a component sits relative to the outside world; rated by src/client/exposure.ts. */
export type Exposure = "external" | "edge" | "internal";

export type CodeLabel<Code extends string> = { code: Code; label: string };

export type GraphNode = {
  id: string;
  type: ComponentType;
  label: string;
  /** {0,0} until the dashboard lays the graph out. */
  position: { x: number; y: number };
  threatCount: number;
  maxSeverity: Severity | null;
  technologies: string[];
  /** What is worth protecting here, from the model. */
  assets: string[];
  /** Where it sits relative to the outside world (src/client/exposure.ts). */
  exposure: Exposure;
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  label: string;
  crossesTrustBoundary: boolean;
  dataClassification: DataClassification;
};

/** A trust boundary as the diagram draws it: its name and the components inside it. */
export type TrustBoundaryView = {
  id: string;
  name: string;
  /** In the model's order. A component may appear in more than one boundary. */
  componentIds: string[];
};

export type EvidenceItem = {
  kind: EvidenceKind;
  kindLabel: string;
  summary: string;
  /** e.g. "src/auth.ts:12-20", or null when the evidence has no file. */
  location: string | null;
  snippet: string | null;
  sourceLabel: string;
};

export type MitigationData = {
  summary: string;
  steps: string[];
  codeLocation: string | null;
};

export type ThreatCardData = {
  id: string;
  title: string;
  severity: Severity;
  /** 0-100, rounded. */
  confidence: number;
  confidenceLabel: ConfidenceLabel;
  priority: Priority;
  priorityLabel: string;
  stride: CodeLabel<Stride>[];
  owasp: CodeLabel<Owasp2025>[];
  cwe: string[];
  basis: Basis;
  basisLabel: string;
  componentNames: string[];
  /**
   * Everything the threat affects, as a reader names it: its components, then each data
   * flow as "Source → Target". A threat about a flow alone would otherwise show no
   * affected location at all.
   */
  affectedNames: string[];
  /**
   * Component ids (graph nodes), in the same order as componentNames. Kept apart from
   * dataFlowIds because the schema only makes ids unique within one collection: a flow
   * may share an id with a component, and one merged list would let that flow match a
   * component filter or light up the component's node.
   */
  componentIds: string[];
  /** Data-flow ids (graph edges) this threat touches. */
  dataFlowIds: string[];
  /**
   * Why the threat has this confidence, one line per contribution, last line the total.
   * Exact point values (they add up to `confidence`) when the model carries enough to
   * reproduce the figure; otherwise, e.g. for a threat backed by a missing control, whose
   * points depend on a detector certainty the model does not hold, qualitative lines with
   * no numbers and a closing note that they do not add up to it. Built by the adapter from
   * src/shared/confidence.ts, never recomputed here.
   */
  confidenceReasons: string[];
  attackScenario: string;
  evidence: EvidenceItem[];
  mitigation: MitigationData;
  assumptions: string[];
};

export type QuestionData = {
  id: string;
  text: string;
  whyAsking: string;
  options: string[];
  allowsUnsure: boolean;
  defaultAssumption: string;
  /** 1-based position, for "Question 1 of 3". */
  index: number;
  total: number;
};

export type SeverityCounts = Record<Severity, number>;

/**
 * Only options that match at least one visible threat are listed. Threats below
 * confidence 0.25 are hidden everywhere in this view model (CLAUDE.md rule 2).
 */
export type FilterOptions = {
  severities: Severity[];
  stride: CodeLabel<Stride>[];
  owasp: CodeLabel<Owasp2025>[];
  components: { id: string; name: string }[];
  confidenceLabels: ConfidenceLabel[];
};

export type DashboardViewModel = {
  /** Copied from ThreatModel.analysisLevel; chosen by the user, never by a model. */
  analysisLevel: AnalysisLevel;
  analysisLevelLabel: string;
  repo: {
    fullName: string;
    ref: string;
    frameworks: string[];
    fileCount: number;
    analyzedAt: string;
  };
  counts: SeverityCounts;
  /** Up to 5 threats with priority fix_now, sorted by severity, then confidence (both highest first). */
  fixNow: ThreatCardData[];
  /** How many visible threats have priority fix_now; `fixNow` lists at most 5 of them. */
  fixNowTotal: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** In the model's order; the diagram puts a component in the first one that lists it. */
  boundaries: TrustBoundaryView[];
  /** Sorted by priority, then risk (impact x likelihood), highest first. */
  threats: ThreatCardData[];
  assumptions: string[];
  limitations: string[];
  filterOptions: FilterOptions;
};

export type AnalysisStatus = {
  stage: AnalysisStage;
  stageLabel: string;
  /** 1-based step within the run; 0 for `failed`, which is not a step. */
  stageIndex: number;
  stageCount: number;
};

export type AnalysisError = {
  /**
   * A schema ErrorCode, or the HTTP-only "NOT_FOUND" that src/server/http/errors.ts sends
   * for an unknown or expired analysis id (a request error, never a failed analysis).
   */
  code: ErrorCode | "NOT_FOUND";
  title: string;
  message: string;
  canRetry: boolean;
};
