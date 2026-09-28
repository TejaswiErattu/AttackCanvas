import type {
  AnalysisStage,
  Basis,
  ErrorCode,
  EvidenceKind,
  EvidenceSource,
  Priority,
  Stride,
} from "./schema";

/**
 * Human-readable labels for every enum the UI shows. Nothing here is computed:
 * it is display copy only. OWASP names are re-exported from the schema, where the
 * verified Top 10:2025 list already lives, so there is a single source of truth.
 */
export { OWASP_LABELS } from "./schema";

export const STRIDE_LABELS = {
  S: "Spoofing",
  T: "Tampering",
  R: "Repudiation",
  I: "Information disclosure",
  D: "Denial of service",
  E: "Elevation of privilege",
} as const satisfies Record<Stride, string>;

export const PRIORITY_LABELS = {
  fix_now: "Fix now",
  fix_soon: "Fix soon",
  monitor: "Monitor",
} as const satisfies Record<Priority, string>;

export const BASIS_LABELS = {
  evidence_backed: "Confirmed by evidence",
  assumption_dependent: "Predicted from a missing control",
} as const satisfies Record<Basis, string>;

export const EVIDENCE_KIND_LABELS = {
  code: "Code",
  config: "Configuration",
  scanner: "Scanner finding",
  dependency: "Dependency",
  developer_answer: "Developer answer",
  inference: "Inference",
  assumption: "Assumption",
} as const satisfies Record<EvidenceKind, string>;

export const EVIDENCE_SOURCE_LABELS = {
  detector: "Code analysis",
  semgrep: "Semgrep",
  osv: "OSV",
  ai: "AI analysis",
  developer: "Developer",
} as const satisfies Record<EvidenceSource, string>;

export const STAGE_LABELS = {
  queued: "Queued",
  loading_repo: "Loading repository",
  scanning: "Scanning code, dependencies and missing controls",
  mapping_architecture: "Mapping architecture",
  generating_threats: "Generating threats",
  awaiting_answers: "Waiting for your answers",
  finalizing: "Finalizing",
  complete: "Complete",
  failed: "Failed",
} as const satisfies Record<AnalysisStage, string>;

/**
 * The default copy for every error code. Fixed text only, never an upstream message
 * (CLAUDE.md rule 8). A route may pass a more specific message for the same code when it
 * knows the detail (the parser's reason for an INVALID_URL, the hourly limit for
 * RATE_LIMITED); the title always comes from here.
 */
export const ERROR_COPY = {
  INVALID_URL: {
    title: "Invalid repository URL",
    message:
      "Enter the URL of a public GitHub repository, like https://github.com/owner/name.",
  },
  REPO_NOT_FOUND: {
    title: "Repository not found",
    message:
      "We couldn't find that repository, or the branch in the URL. Check the URL and make sure the repository is public.",
  },
  REPO_TOO_LARGE: {
    title: "Repository too large",
    message:
      "This repository has more files, or larger files, than AttackCanvas can download in one analysis. Try a smaller repository.",
  },
  INSUFFICIENT_CODE: {
    title: "Not enough code to analyze",
    message:
      "AttackCanvas found too few application source files in this repository to build a threat model.",
  },
  RATE_LIMITED: {
    title: "Too many analyses started",
    message:
      "You've started as many analyses as are allowed in one hour. Try again later.",
  },
  AI_FAILURE: {
    title: "Analysis failed",
    message:
      "Something unexpected went wrong while building the threat model. Please try again.",
  },
  TIMEOUT: {
    title: "Analysis timed out",
    message:
      "The analysis, or one of its steps, ran past its time limit. Large repositories take longer. Please try again.",
  },
  INVALID_REQUEST: {
    title: "Invalid request",
    message:
      "The request was missing a required field or wasn't in the expected format, so nothing was started.",
  },
  NOT_AWAITING_ANSWERS: {
    title: "No longer waiting for answers",
    message:
      "This analysis isn't waiting for answers anymore; it may already have finished. Reload the page to see where it stands.",
  },
  OWNER_NOT_ALLOWED: {
    title: "Owner not allowed on this deployment",
    message:
      "This AttackCanvas deployment only analyzes repositories from a fixed list of owners, and this repository's owner isn't on it. Run your own copy, or ask whoever runs this one.",
  },
  SERVER_BUSY: {
    title: "AttackCanvas is busy",
    message:
      "The most analyses AttackCanvas runs at once are already running. Wait a few minutes and try again.",
  },
  UPSTREAM_RATE_LIMITED: {
    title: "GitHub or Claude asked us to slow down",
    message:
      "GitHub or the Claude API is rate-limiting AttackCanvas right now. Wait a few minutes and try again.",
  },
  GITHUB_UNAVAILABLE: {
    title: "Couldn't read from GitHub",
    message:
      "GitHub returned an error, or a response AttackCanvas couldn't read, while downloading the repository. Wait a few minutes and try again.",
  },
  MODEL_REFUSED: {
    title: "Claude declined the request",
    message:
      "The Claude API declined to analyze this repository's content, so no threat model could be built.",
  },
  MODEL_OUTPUT_INVALID: {
    title: "Unusable response from Claude",
    message:
      "Claude's response was cut off at its length limit, or didn't match the expected format even after a correction attempt. Trying again often works.",
  },
  OUTPUT_REJECTED: {
    title: "Result failed safety checks",
    message:
      "The threat model cited files that aren't in the repository, or left out a confirmed finding, so AttackCanvas discarded it. Repository content that tries to steer the analysis can cause this.",
  },
  SECRET_BLOCKED: {
    title: "Stopped to protect a secret",
    message:
      "A credential in the repository got past redaction, so AttackCanvas stopped before sending anything to the model.",
  },
  NETWORK_ERROR: {
    title: "Connection problem",
    message: "Your browser couldn't reach AttackCanvas. Check your connection and try again.",
  },
} as const satisfies Record<ErrorCode, { title: string; message: string }>;
