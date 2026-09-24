import { z } from "zod";

/**
 * Identifiers are kebab-case throughout the contract, e.g. "web-frontend".
 * Note this deliberately does not cover OWASP codes ("A01:2025"), which are an enum.
 */
export const zId = z.string().regex(/^[a-z0-9]+(-[a-z0-9]+)*$/, {
  message: "must be kebab-case, e.g. web-frontend",
});

export const zCwe = z.string().regex(/^CWE-\d+$/, {
  message: 'must look like "CWE-79"',
});

export const ComponentTypeSchema = z.enum([
  "actor",
  "frontend",
  "backend",
  "api",
  "database",
  "storage",
  "external_service",
  "auth_provider",
  "worker",
  "queue",
]);
export type ComponentType = z.infer<typeof ComponentTypeSchema>;

export const DataClassificationSchema = z.enum([
  "public",
  "internal",
  "sensitive",
  "credential",
]);
export type DataClassification = z.infer<typeof DataClassificationSchema>;

export const EvidenceKindSchema = z.enum([
  "code",
  "config",
  "scanner",
  "dependency",
  "developer_answer",
  "inference",
  "assumption",
]);
export type EvidenceKind = z.infer<typeof EvidenceKindSchema>;

export const EvidenceSourceSchema = z.enum([
  "detector",
  "semgrep",
  "osv",
  "ai",
  "developer",
]);
export type EvidenceSource = z.infer<typeof EvidenceSourceSchema>;

/** Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege. */
export const StrideSchema = z.enum(["S", "T", "R", "I", "D", "E"]);
export type Stride = z.infer<typeof StrideSchema>;

export const Owasp2025Schema = z.enum([
  "A01:2025",
  "A02:2025",
  "A03:2025",
  "A04:2025",
  "A05:2025",
  "A06:2025",
  "A07:2025",
  "A08:2025",
  "A09:2025",
  "A10:2025",
]);
export type Owasp2025 = z.infer<typeof Owasp2025Schema>;

/** Official OWASP Top 10:2025 category names. */
export const OWASP_LABELS = {
  "A01:2025": "Broken Access Control",
  "A02:2025": "Security Misconfiguration",
  "A03:2025": "Software Supply Chain Failures",
  "A04:2025": "Cryptographic Failures",
  "A05:2025": "Injection",
  "A06:2025": "Insecure Design",
  "A07:2025": "Authentication Failures",
  "A08:2025": "Software or Data Integrity Failures",
  "A09:2025": "Security Logging and Alerting Failures",
  "A10:2025": "Mishandling of Exceptional Conditions",
} as const satisfies Record<Owasp2025, string>;

export const SeveritySchema = z.enum(["critical", "high", "medium", "low"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const PrioritySchema = z.enum(["fix_now", "fix_soon", "monitor"]);
export type Priority = z.infer<typeof PrioritySchema>;

export const BasisSchema = z.enum(["evidence_backed", "assumption_dependent"]);
export type Basis = z.infer<typeof BasisSchema>;

/** Confidence bucket. Computed in src/server/scoring, never by a model. */
export const ConfidenceLabelSchema = z.enum(["high", "medium", "low"]);
export type ConfidenceLabel = z.infer<typeof ConfidenceLabelSchema>;

/**
 * How much depth the user asked for. Chosen by the user on the submit form and
 * carried through to the finished ThreatModel — a model never selects or changes
 * it, which is why it appears in no draft schema.
 */
export const AnalysisLevelSchema = z.union([
  z.literal(0),
  z.literal(1),
  z.literal(2),
  z.literal(3),
  z.literal(4),
]);
export type AnalysisLevel = z.infer<typeof AnalysisLevelSchema>;

export const ANALYSIS_LEVEL_LABELS = {
  0: "Snapshot",
  1: "Basic",
  2: "Standard",
  3: "Deep",
  4: "Exhaustive",
} as const satisfies Record<AnalysisLevel, string>;

export const AnalysisStageSchema = z.enum([
  "queued",
  "loading_repo",
  "scanning",
  "mapping_architecture",
  "generating_threats",
  "awaiting_answers",
  "finalizing",
  "complete",
  "failed",
]);
export type AnalysisStage = z.infer<typeof AnalysisStageSchema>;

/**
 * One code per distinct failure, so a code alone says what went wrong. User-facing copy
 * for each lives in ERROR_COPY (src/shared/labels.ts). The first seven are the original
 * set, each narrowed when the rest were added (2026-09-23): RATE_LIMITED is now only our
 * own per-caller limit, TIMEOUT only a time budget running out, and AI_FAILURE the
 * catch-all for a failure no more specific code describes.
 */
export const ErrorCodeSchema = z.enum([
  "INVALID_URL",
  "REPO_NOT_FOUND",
  "REPO_TOO_LARGE",
  "INSUFFICIENT_CODE",
  "RATE_LIMITED",
  "AI_FAILURE",
  "TIMEOUT",
  // Request problems.
  "INVALID_REQUEST",
  "NOT_AWAITING_ANSWERS",
  // Capacity: ours (SERVER_BUSY) and an upstream service's.
  "SERVER_BUSY",
  "UPSTREAM_RATE_LIMITED",
  // Upstream services.
  "GITHUB_UNAVAILABLE",
  "MODEL_REFUSED",
  "MODEL_OUTPUT_INVALID",
  // Safety stops.
  "OUTPUT_REJECTED",
  "SECRET_BLOCKED",
  // Client only: the browser could not reach the server.
  "NETWORK_ERROR",
]);
export type ErrorCode = z.infer<typeof ErrorCodeSchema>;
