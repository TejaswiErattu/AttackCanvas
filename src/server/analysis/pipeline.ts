/**
 * Prompt V, Part 1: the analysis orchestrator.
 *
 * Every stage below already exists as its own module, individually exercised by a
 * scripts/try-*.ts script (see tests/canary.live.test.ts for the reference wiring this
 * mirrors). Nothing wires them together end to end -- this module is that wiring, plus
 * an in-memory job store so a caller can start an analysis, poll its stage, and resume it
 * with developer answers, without holding an HTTP request open for the several minutes a
 * full run can take.
 *
 * Stage sequence (the existing, frozen AnalysisStage enum -- no member is added):
 *
 *   loading_repo -> scanning -> mapping_architecture -> generating_threats
 *     -> awaiting_answers (if questions exist) | finalizing -> complete
 *
 * Gap detection is NOT a separate step: runDetectors (src/server/detect/index.ts) already
 * calls detectGaps as its last step and returns gaps + gap evidence on DetectorResult, so
 * calling detectGaps again here would mint a second "gap-1, gap-2, ..." id series and
 * duplicate "gap:" evidence ids -- which ThreatModelSchema's duplicate-id check would
 * reject. "scanning" is simply the stage during which that already-merged result, plus
 * Semgrep and OSV, run.
 *
 * Budget: PIPELINE_TIMEOUT_MS (10 minutes) bounds the whole run. The stages are
 * sequential, and threat generation alone runs its batches in several concurrency rounds
 * (THREATS_CONCURRENCY at a time), so the whole-run budget must cover loading, scanning,
 * one architecture call, every threat round and the question call back to back -- a live
 * 12-batch run needed about 390 s and was cut off by the old 240 s default. It is still
 * overridable per job (scripts/try-pipeline.ts accepts --timeout), and a single batch's
 * THREATS_TIMEOUT_MS (300 s) is unchanged. Once the deadline passes or the job is
 * cancelled, generateThreats starts no further batch (shouldContinue below), so a
 * timed-out run stops spending on new provider requests. The clock stops at
 * "awaiting_answers": resumeWithAnswers re-arms the deadline with the job's own budget
 * (`timeoutMs`), so however long a developer takes to answer never counts against it.
 *
 * Errors: every thrown value is mapped to a schema ErrorCode and a message taken ONLY from
 * ERROR_COPY (src/shared/labels.ts) -- never from the upstream error's own .message, which
 * for SecretLeakError names the secret type and line number (CLAUDE.md rules 3 and 8).
 * This module contains no console.* calls. Its one log line (logFailure, development
 * only) goes through src/server/log.ts and carries error metadata, never content.
 *
 * In-flight paid work on a timeout is not cancelled (no client here accepts an
 * AbortSignal): it keeps running to its own inner deadline and its usage still lands in
 * usageLedger under the same analysisId. usageLedger.clear(id) is therefore called only on
 * expiry (an hour later, by which time every straggler has finished), never on timeout or
 * completion.
 *
 * Abandoned-stage safety: runSteps' own promise already has `.catch(cause => fail(state,
 * cause))` attached directly to it (not just the outer withDeadline race), so if the
 * orphaned continuation above resumes and later throws (which it always eventually did,
 * because a stale setStage() call would hit its own checkDeadline check), that inner
 * catch corrects `state` back to "failed" synchronously, with no `await` in between --
 * nothing external can observe the intermediate wrong value, by ordinary single-threaded
 * JS semantics. That already made the original design safe in practice; every `state.*`
 * write here is preceded by a fresh checkDeadline() anyway (immediately after every await
 * that could span the deadline, and first thing inside setStage(), before it touches
 * `stage`), and fail() unconditionally clears threatModel/questions/pending. This is
 * deliberate hardening, not a patch for an observed bug: it makes "an abandoned stage can
 * never publish complete or a partial model" hold by construction, provable without
 * relying on microtask-ordering behavior that a future refactor (an added `await`, a
 * changed promise chain) could quietly invalidate.
 *
 * Architecture note: this store is a plain in-memory Map and every stage runs as a
 * fire-and-forget background promise inside the same process that accepted the HTTP
 * request. That is a deliberate local/demo-scale choice, not a production job queue: a
 * process restart, a deploy, or a serverless function being suspended between requests
 * loses every in-flight and completed-but-unpolled analysis. A durable deployment needs a
 * persistent store and a real background worker; nothing here provides either.
 */

import { randomUUID } from "node:crypto";

import type {
  AnalysisLevel,
  AnalysisStage,
  Basis,
  DeveloperQuestion,
  ErrorCode,
  Threat,
  ThreatModel,
} from "@/shared/schema";
import { validateThreatModel, type ValidationIssue } from "@/shared/schema";
import { ERROR_COPY } from "@/shared/labels";

import { parseGitHubUrl } from "@/server/ingest/urlParser";
import { IngestError, loadRepository, modelBoundFiles } from "@/server/ingest/loader";
import {
  FIXTURE_OWNER,
  isFixtureUrl,
  loadFixtureRepo,
  parseFixtureUrl,
} from "@/server/ingest/fixtureLoader";
import { GitHubMcpError } from "@/server/mcp/githubClient";
import { SecretLeakError, redact } from "@/server/security/redactor";
import { injectionEvidence, checkModelOutput } from "@/server/security/injection";
import { runDetectors, frameworkNames } from "@/server/detect";
import type { ControlGap } from "@/server/detect/types";
import { scanFiles, SemgrepMcpError, type RedactedFile } from "@/server/mcp/semgrepClient";
import { normalizeSemgrep } from "@/server/scanners/semgrep";
import { scanDependencies, type ScanFile } from "@/server/scanners/osv";
import { buildRepoFacts, buildContext } from "@/server/analysis/context";
import {
  ARCHITECTURE_CONTEXT_TOKENS,
  inferArchitecture,
  mergeArchitecture,
} from "@/server/analysis/architecture";
import { failedBatchOf, generateThreats } from "@/server/analysis/threats";
import { assembleThreatModel } from "@/server/analysis/assemble";
import { selectQuestions, type QuestionEffects } from "@/server/questions";
import { applyAnswers, type DeveloperAnswer } from "@/server/analysis/answers";
import { AiError, type CallFailure, type ClaudeDeps, type RequestDiagnostic } from "@/server/ai/claude";
import { usageLedger } from "@/server/ai/usage";
import { log } from "@/server/log";
import { isHidden } from "@/server/scoring";

// ---------------------------------------------------------------------------
// Knobs
// ---------------------------------------------------------------------------

/**
 * The whole run's wall-clock budget: 10 minutes. The stages run one after another and
 * threat batches run in several concurrency rounds, so this covers them in sequence (see
 * the module header); per-call timeouts are unchanged. Exported so a caller (the try
 * script, the route) can override it per job via createAnalysis's timeoutMs.
 */
export const PIPELINE_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * The largest timeoutMs createAnalysis accepts: setTimeout's ceiling (2^31 - 1 ms, about
 * 24.8 days). Node clamps any longer delay to 1 ms, which would fire the deadline at once.
 */
export const MAX_TIMEOUT_MS = 2_147_483_647;

/** Entries older than this (by updatedAt) are dropped on the next store access. */
export const ANALYSIS_TTL_MS = 60 * 60 * 1000;

/**
 * Appended to `limitations` when the detectors found zero control gaps -- the one
 * outcome a user could otherwise misread as "nothing to report" rather than "the
 * detector may not cover this framework".
 */
export const NO_GAPS_LIMITATION =
  "No control gaps were detected. This may mean the project is well configured, or " +
  "that its framework is outside the detector's JavaScript and TypeScript coverage.";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

export type AnalysisCost = {
  /** Provider responses recorded so far (a validation retry counts twice). */
  calls: number;
  totalUsd: number;
};

/** Everything resumeWithAnswers needs beyond the ThreatModel itself. */
export type PendingAnswerState = {
  /** questionId -> QuestionEffects, straight from selectQuestions. Not in the contract. */
  effects: Map<string, QuestionEffects>;
  /** The SAME gap objects the detectors produced -- applyAnswers resolves ids from them. */
  gaps: ControlGap[];
  /** Paths the loader actually fetched, for a re-run of checkModelOutput. */
  loadedPaths: string[];
};

export type AnalysisState = {
  id: string;
  repoUrl: string;
  analysisLevel: AnalysisLevel;
  stage: AnalysisStage;
  createdAt: number;
  updatedAt: number;
  /** Set only when stage === "failed". Already safe to show a user. Cleared on any success. */
  error?: { code: ErrorCode; message: string };
  questions?: DeveloperQuestion[];
  /** Set iff questions is set: the resume sidecar. Real jobs only -- see `isDemo`. */
  pending?: PendingAnswerState;
  threatModel?: ThreatModel;
  cost: AnalysisCost;
  /** Non-fatal degradations (Semgrep down), surfaced as assemble's droppedStages. */
  droppedStages: string[];
  /**
   * Explicit marker for a job seeded by src/server/analysis/demo.ts, set at creation.
   * A demo job pauses at "awaiting_answers" without `pending` (there is no real
   * QuestionEffects sidecar for canned data), so callers MUST branch on this flag, never
   * on whether `pending` happens to be missing -- an absent `pending` on a REAL job is a
   * bug, not a demo, and should be treated as one.
   */
  isDemo: boolean;
  /**
   * Internal: the deadline the running stages check. Set at creation; resumeWithAnswers
   * re-arms it to now + timeoutMs, so time spent at "awaiting_answers" never counts.
   */
  deadlineAt: number;
  /** Internal: this job's own budget in ms, given afresh to each running phase. */
  timeoutMs: number;
  cancelled: boolean;
};

const store = new Map<string, AnalysisState>();

export function isExpired(state: AnalysisState, now: number): boolean {
  return now - state.updatedAt >= ANALYSIS_TTL_MS;
}

/** Drops every entry past its TTL and clears its usage-ledger record. Returns the count removed. */
export function sweepExpired(now: number = Date.now()): number {
  let removed = 0;
  for (const [id, state] of store) {
    if (!isExpired(state, now)) continue;
    store.delete(id);
    usageLedger.clear(id);
    removed += 1;
  }
  return removed;
}

export type CreateAnalysisOptions = {
  /** Marks the job explicitly as a demo seed (src/server/analysis/demo.ts). Default false. */
  isDemo?: boolean;
  /**
   * Overrides PIPELINE_TIMEOUT_MS for this job only. Must be a positive integer number
   * of milliseconds, at most MAX_TIMEOUT_MS; validated here, synchronously, before any network or model work
   * this job would otherwise do -- a caller that accepts a timeout from user input (the
   * try script's --timeout) should still validate it itself first so a bad value is
   * rejected before argv parsing even finishes, but this is the backstop.
   */
  timeoutMs?: number;
};

export function createAnalysis(
  repoUrl: string,
  analysisLevel: AnalysisLevel = 2,
  options: CreateAnalysisOptions = {},
): AnalysisState {
  const timeoutMs = options.timeoutMs ?? PIPELINE_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new RangeError(
      `timeoutMs must be a positive integer no greater than ${MAX_TIMEOUT_MS}, got ${String(options.timeoutMs)}`,
    );
  }

  sweepExpired();
  const now = Date.now();
  const state: AnalysisState = {
    id: randomUUID(),
    repoUrl,
    analysisLevel,
    stage: "queued",
    createdAt: now,
    updatedAt: now,
    cost: { calls: 0, totalUsd: 0 },
    droppedStages: [],
    isDemo: options.isDemo ?? false,
    deadlineAt: now + timeoutMs,
    timeoutMs,
    cancelled: false,
  };
  store.set(state.id, state);
  return state;
}

export function getAnalysis(id: string): AnalysisState | undefined {
  sweepExpired();
  return store.get(id);
}

/** Stages a job never leaves: no further paid work happens once it is here. */
const TERMINAL_STAGES = new Set<AnalysisStage>(["complete", "failed"]);

/**
 * How many REAL (non-demo) analyses are "in flight" for the concurrency cap in
 * src/server/http/rateLimit.ts (Prompt U Part 2: cost-abuse controls).
 *
 * The exact policy, one row per stage of the frozen AnalysisStage enum:
 *
 *   queued              counts
 *   loading_repo        counts
 *   scanning            counts
 *   mapping_architecture counts
 *   generating_threats  counts
 *   awaiting_answers    counts   -- see below
 *   finalizing          counts
 *   complete            does NOT count (terminal)
 *   failed              does NOT count (terminal)
 *   any stage, isDemo   does NOT count -- seeded from a fixture by
 *                       src/server/analysis/demo.ts, never calls a paid model, so it
 *                       neither competes for this budget nor is blocked by it.
 *
 * WHY awaiting_answers COUNTS. It is paused waiting on a developer, so it is spending
 * nothing at this instant -- but resumeWithAnswers continues the SAME job and spends
 * again (applyAnswers, re-scoring, and on other paths further paid calls). Counting it
 * means the slot a caller reserved when they started the analysis stays reserved until
 * that analysis actually finishes, which is the property the cap exists to provide.
 *
 * It also closes a bypass: if awaiting_answers did NOT count, a caller could park N
 * analyses at that stage, see the active count drop to zero, start N more, and resume
 * all of them at once -- 2N paid runs in flight under a cap of 2. resumeWithAnswers
 * itself cannot be the choke point for that, because it never creates a job (it only
 * reads an existing one via getAnalysis and continues it), so it has no "reject a new
 * arrival" moment to guard; the reservation has to be held here instead.
 *
 * THE COST OF THAT CHOICE, stated rather than hidden: an ABANDONED awaiting_answers job
 * -- a developer who is asked a question and never answers -- holds its slot until it is
 * explicitly deleted (deleteAnalysis) or ages out of the store (ANALYSIS_TTL_MS, 1 hour
 * from its last update). Two abandoned jobs therefore block new real analyses in this
 * process for up to an hour. That is the deliberate trade: a stuck slot is recoverable
 * and bounded, an uncapped resume storm is neither.
 *
 * Sweeps expired entries first, exactly like getAnalysis, so a stale job that outlived
 * its TTL is not still counted as active -- which is also what bounds the paragraph
 * above to one hour rather than forever.
 */
export function countActiveAnalyses(): number {
  sweepExpired();
  let count = 0;
  for (const state of store.values()) {
    if (!state.isDemo && !TERMINAL_STAGES.has(state.stage)) count += 1;
  }
  return count;
}

export function deleteAnalysis(id: string): void {
  store.delete(id);
  usageLedger.clear(id);
}

/** Test-only: drops every entry without touching the shared usage ledger's other ids. */
export function resetStore(): void {
  for (const id of store.keys()) usageLedger.clear(id);
  store.clear();
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/** Threats grouped by basis, for the analysis summary. Derived, not stored on the model. */
export function countByBasis(threats: readonly Threat[]): Record<Basis, number> {
  const counts: Record<Basis, number> = { evidence_backed: 0, assumption_dependent: 0 };
  for (const threat of threats) counts[threat.basis] += 1;
  return counts;
}

/** Why a hidden threat fell below the display threshold, most basic cause first. */
export type HiddenReason = "no_evidence" | "assumptions" | "weak_evidence";

export type HiddenSummary = {
  /** Every scored threat in the model, shown or not. */
  scored: number;
  /** Threats below the 0.25 display threshold (src/server/scoring HIDE_BELOW). */
  hidden: number;
  /** The most common reason among hidden threats; null when none are hidden. */
  topReason: HiddenReason | null;
  topReasonCount: number;
};

const HIDDEN_REASON_ORDER: readonly HiddenReason[] = [
  "no_evidence",
  "assumptions",
  "weak_evidence",
];

/**
 * One hidden threat's reason: it cites no evidence at all; or it cites some but its
 * unconfirmed assumptions pulled it down; or its evidence alone was too weak.
 */
export function hiddenReasonOf(threat: Threat): HiddenReason {
  if (threat.evidenceIds.length === 0) return "no_evidence";
  if (threat.assumptions.length > 0) return "assumptions";
  return "weak_evidence";
}

/**
 * Counts for the dashboard's empty state, so "no threats" can say that N were scored and
 * all were hidden, and why. Derived like countByBasis, never stored on the model; ties
 * between reasons go to the more basic one, in HIDDEN_REASON_ORDER.
 */
export function summarizeHidden(threats: readonly Threat[]): HiddenSummary {
  const hidden = threats.filter((t) => isHidden(t.confidence));
  const counts = new Map<HiddenReason, number>();
  for (const threat of hidden) {
    const reason = hiddenReasonOf(threat);
    counts.set(reason, (counts.get(reason) ?? 0) + 1);
  }
  let topReason: HiddenReason | null = null;
  for (const reason of HIDDEN_REASON_ORDER) {
    if ((counts.get(reason) ?? 0) > (topReason ? counts.get(topReason)! : 0)) topReason = reason;
  }
  return {
    scored: threats.length,
    hidden: hidden.length,
    topReason,
    topReasonCount: topReason ? counts.get(topReason)! : 0,
  };
}

class DeadlineError extends Error {
  constructor() {
    super("analysis exceeded its time budget");
    this.name = "DeadlineError";
  }
}

export function toErrorCode(cause: unknown): ErrorCode {
  if (cause instanceof DeadlineError) return "TIMEOUT";
  if (cause instanceof IngestError) return cause.code;
  if (cause instanceof GitHubMcpError) return cause.code;
  if (cause instanceof SemgrepMcpError) return cause.code;
  if (cause instanceof AiError) return cause.code;
  // Rule 3's last line of defence fired: the run stopped before any model call.
  if (cause instanceof SecretLeakError) return "SECRET_BLOCKED";
  // SemgrepClientConfigError, GitHubClientConfigError, anything else: fail closed rather
  // than guess at a more specific code.
  return "AI_FAILURE";
}

export function safeMessage(code: ErrorCode): string {
  return ERROR_COPY[code].message;
}

/**
 * Patches questions onto an assembled model and appends any pipeline-level limitations
 * (the zero-gap sentence, output-check findings), then re-validates -- required because
 * assembleThreatModel always emits questions: [] and ThreatModelSchema requires every
 * question's affectedThreatIds to resolve to a threat that survived assembly.
 */
export function finalizeModel(input: {
  model: ThreatModel;
  questions: readonly DeveloperQuestion[];
  extraLimitations: readonly string[];
}): { ok: true; model: ThreatModel } | { ok: false; issues: ValidationIssue[] } {
  const patched: ThreatModel = {
    ...input.model,
    questions: [...input.questions],
    limitations: [...input.model.limitations, ...input.extraLimitations],
  };
  const validated = validateThreatModel(patched);
  return validated.ok ? { ok: true, model: validated.data } : { ok: false, issues: validated.issues };
}

// ---------------------------------------------------------------------------
// The whole-run deadline (PIPELINE_TIMEOUT_MS)
// ---------------------------------------------------------------------------

/**
 * Races `work` against the state's deadline. The loser is orphaned, not cancelled -- its
 * rejection is swallowed so an in-flight paid call does not surface as an unhandled
 * rejection after the pipeline has already failed. See the module header for what happens
 * to that call's usage and cost.
 */
function withDeadline<T>(work: Promise<T>, state: AnalysisState): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const alarm = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => {
        state.cancelled = true;
        reject(new DeadlineError());
      },
      Math.max(0, state.deadlineAt - Date.now()),
    );
    timer.unref?.();
  });
  work.catch(() => {});
  return Promise.race([work, alarm]).finally(() => clearTimeout(timer));
}

function checkDeadline(state: AnalysisState): void {
  if (state.cancelled || Date.now() >= state.deadlineAt) throw new DeadlineError();
}

// ---------------------------------------------------------------------------
// Test seam
// ---------------------------------------------------------------------------

export type PipelineDeps = {
  parseGitHubUrl: typeof parseGitHubUrl;
  loadRepository: typeof loadRepository;
  scanFiles: typeof scanFiles;
  scanDependencies: typeof scanDependencies;
  inferArchitecture: typeof inferArchitecture;
  generateThreats: typeof generateThreats;
  selectQuestions: typeof selectQuestions;
  /** Forwarded verbatim to every paid call's own `deps`. */
  ai?: Partial<ClaudeDeps>;
  now: () => number;
};

/**
 * Dispatches a `fixture:<name>` "repo URL" (src/server/ingest/fixtureLoader.ts) to the
 * local fixture loader and everything else to the real GitHub one, so
 * createAnalysis("fixture:canary-repo") exercises the genuine end-to-end pipeline against
 * tests/fixtures/canary-repo/. Disabled outside development/test by fixtureLoader itself
 * (fixturesEnabled()), not by this dispatch, so the check cannot be routed around.
 */
function dispatchParseUrl(input: string): ReturnType<typeof parseGitHubUrl> {
  return isFixtureUrl(input) ? parseFixtureUrl(input) : parseGitHubUrl(input);
}

function dispatchLoadRepository(
  owner: string,
  repo: string,
  ref?: string,
): ReturnType<typeof loadRepository> {
  return owner === FIXTURE_OWNER ? loadFixtureRepo(owner, repo, ref) : loadRepository(owner, repo, ref);
}

const DEFAULT_DEPS: PipelineDeps = {
  parseGitHubUrl: dispatchParseUrl,
  loadRepository: dispatchLoadRepository,
  scanFiles,
  scanDependencies,
  inferArchitecture,
  generateThreats,
  selectQuestions,
  now: Date.now,
};

function resolveDeps(overrides?: Partial<PipelineDeps>): PipelineDeps {
  return { ...DEFAULT_DEPS, ...overrides };
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Checks the deadline FIRST, before writing anything: an abandoned continuation that
 * resumes after the alarm already fired (state.cancelled) must throw here rather than
 * briefly writing a later stage (even "complete") and being corrected only by the
 * outer .catch a tick later. See the module header's "abandoned-stage safety" note.
 */
function setStage(state: AnalysisState, stage: AnalysisStage): void {
  checkDeadline(state);
  state.stage = stage;
  state.updatedAt = Date.now();
  const usage = usageLedger.forAnalysis(state.id);
  state.cost = { calls: usage.calls.length, totalUsd: usage.totalUsd };
}

/**
 * Marks a job failed. Unconditionally clears threatModel, questions and pending: a
 * "failed" state carries only `error`, never a result -- complete or partial -- even if
 * some of those fields happened to be set moments earlier by the same run.
 */
/** Longest upstream error message logFailure keeps; enough for an API error's reason. */
export const FAILURE_MESSAGE_MAX = 300;

export type FailureDiagnostic = {
  analysisId: string;
  failedStage: AnalysisStage;
  code: ErrorCode;
  causeName: string;
  causeMessage: string;
  causeChain: string[];
  apiStatus?: number;
  issues: { path: string; message: string }[];
  modelCalls: number;
  /** Ledger totals for the whole job: counts and dollars only. */
  usage: {
    inputTokens: number;
    outputTokens: number;
    cacheReadTokens: number;
    cacheWriteTokens: number;
    thinkingTokens: number;
    totalUsd: number;
  };
  /** A 4xx-rejected request's structure (roles, lengths, well-formedness), when there was one. */
  providerRequest?: RequestDiagnostic;
  /** The failed provider request: stage, attempt counts, status and error type. Codes only. */
  providerCall?: CallFailure;
  /** The threat batch that failed, 1-based, and the batch count. */
  batch?: { number: number; of: number };
  /** The last recorded model response's stop reason ("max_tokens", "refusal", ...). */
  stopReason?: string;
  /** Reasoning tokens the last recorded model response spent (a count, never text). */
  thinkingTokens?: number;
};

function nameOf(value: unknown): string {
  if (value instanceof Error) return value.name;
  if (value === null) return "null";
  return typeof value;
}

/**
 * The safe, content-free facts about a failure: which stage, which error class, the
 * upstream message (capped), the class names of nested causes and any HTTP status on
 * them, plus the last recorded model response's stop reason and thinking-token count.
 * Deliberately omits every other field of the cause -- a refusal's stop_details,
 * an APIError's headers or request body -- since those are where prompt or response
 * text would live. Pure: reads `state` before fail() overwrites its stage.
 */
export function failureDiagnostic(
  state: AnalysisState,
  code: ErrorCode,
  cause: unknown,
): FailureDiagnostic {
  const causeChain: string[] = [];
  let apiStatus: number | undefined;
  let current: unknown = cause instanceof Error ? cause.cause : undefined;
  while (current !== undefined && causeChain.length < 5) {
    causeChain.push(nameOf(current));
    const status = (current as { status?: unknown } | null)?.status;
    if (apiStatus === undefined && typeof status === "number") apiStatus = status;
    current = current instanceof Error ? current.cause : undefined;
  }
  // Counts and a stop reason only: CallUsage never holds prompt or response text.
  const ledger = usageLedger.forAnalysis(state.id);
  const calls = ledger.calls;
  const lastCall = calls.at(-1);
  const issues =
    cause instanceof AiError
      ? cause.issues.slice(0, 10).map((issue) => ({
          path: String(issue.path).slice(0, 100),
          message: String(issue.message).slice(0, 200),
        }))
      : [];
  return {
    analysisId: state.id,
    failedStage: state.stage,
    code,
    causeName: nameOf(cause),
    causeMessage: cause instanceof Error ? cause.message.slice(0, FAILURE_MESSAGE_MAX) : "",
    causeChain,
    ...(apiStatus !== undefined ? { apiStatus } : {}),
    issues,
    modelCalls: calls.length,
    usage: {
      inputTokens: ledger.totals.inputTokens,
      outputTokens: ledger.totals.outputTokens,
      cacheReadTokens: ledger.totals.cacheReadTokens,
      cacheWriteTokens: ledger.totals.cacheWriteTokens,
      thinkingTokens: ledger.totals.thinkingTokens,
      totalUsd: ledger.totalUsd,
    },
    ...(cause instanceof AiError && cause.request ? { providerRequest: cause.request } : {}),
    ...(cause instanceof AiError && cause.call ? { providerCall: cause.call } : {}),
    ...(failedBatchOf(cause) ? { batch: failedBatchOf(cause) } : {}),
    ...(lastCall?.stopReason !== undefined ? { stopReason: lastCall.stopReason } : {}),
    ...(lastCall !== undefined ? { thinkingTokens: lastCall.thinkingTokens } : {}),
  };
}

/**
 * Set to "1" to log failure diagnostics outside development (the eval runner does). It
 * enables only this metadata line: prompt dumps under .debug/ still need NODE_ENV=development.
 */
export const FAILURE_DIAGNOSTICS_ENV = "ATTACKCANVAS_FAILURE_DIAGNOSTICS";

/**
 * Development only, or when FAILURE_DIAGNOSTICS_ENV is "1": one structured line explaining
 * why a job failed, since the stored state keeps only the code. log() refuses (throws) on
 * anything secret-shaped; that is swallowed here, because fail() must never throw --
 * losing a diagnostic line is fine, losing the failed state is not.
 */
function logFailure(diagnostic: FailureDiagnostic): void {
  if (process.env.NODE_ENV !== "development" && process.env[FAILURE_DIAGNOSTICS_ENV] !== "1") {
    return;
  }
  try {
    log("error", "analysis failed", diagnostic);
  } catch {
    try {
      log("error", "analysis failed (details withheld: secret-shaped)", {
        analysisId: diagnostic.analysisId,
        failedStage: diagnostic.failedStage,
        code: diagnostic.code,
        causeName: diagnostic.causeName,
      });
    } catch {
      // Nothing safe left to say.
    }
  }
}

/**
 * The debug line for unknowns the question engine skipped. Guarded like logFailure:
 * log() stays fail-closed and throws SecretLeakError on anything secret-shaped, and an
 * unknownId is a model-authored slug that can legitimately name a credential
 * ("xoxb-slack-bot-token" matches the Slack token rule). This line runs after the paid
 * selectQuestions call, so letting that throw fail the run would discard a finished model
 * over a diagnostic. On a refusal the ids are withheld and only counts and the fixed
 * reason codes are logged; if even that is refused, nothing is.
 */
function logSkippedUnknowns(skipped: readonly { unknownId: string; reason: string }[]): void {
  try {
    log("debug", "questions: skipped unknowns", {
      skipped: skipped.map((s) => ({ unknownId: s.unknownId, reason: s.reason })),
    });
  } catch {
    try {
      log("debug", "questions: skipped unknowns (ids withheld: secret-shaped)", {
        count: skipped.length,
        reasons: skipped.map((s) => s.reason),
      });
    } catch {
      // Nothing safe left to say.
    }
  }
}

function fail(state: AnalysisState, cause: unknown): AnalysisState {
  // One failure transition per job. An orphaned stage that later throws (its own
  // DeadlineError, or TIMEOUT from a stopped threat pool) reaches here again: it must not
  // replace the first error or log a second line, only re-clear results and refresh cost.
  if (state.stage !== "failed") {
    const code = toErrorCode(cause);
    logFailure(failureDiagnostic(state, code, cause));
    state.error = { code, message: safeMessage(code) };
    state.stage = "failed";
  }
  state.threatModel = undefined;
  state.questions = undefined;
  state.pending = undefined;
  state.updatedAt = Date.now();
  // Refresh the cost snapshot once more: a timed-out paid call's usage may have landed
  // between the last setStage and now, and the snapshot should not under-report it.
  const usage = usageLedger.forAnalysis(state.id);
  state.cost = { calls: usage.calls.length, totalUsd: usage.totalUsd };
  return state;
}

/**
 * Runs one analysis end to end, in place, updating `state` as it goes. Never rejects: any
 * failure is written into the state as `stage: "failed"` plus a safe `error`, so a caller
 * only ever needs to await and then read the result.
 */
export async function runAnalysis(
  id: string,
  depsOverride?: Partial<PipelineDeps>,
): Promise<AnalysisState> {
  const state = getAnalysis(id);
  if (!state) throw new Error(`unknown analysis id: ${id}`);
  const deps = resolveDeps(depsOverride);

  return withDeadline(runSteps(state, deps).catch((cause) => fail(state, cause)), state).catch(
    (cause) => fail(state, cause),
  );
}

async function runSteps(state: AnalysisState, deps: PipelineDeps): Promise<AnalysisState> {
  // A. loading_repo -------------------------------------------------------
  setStage(state, "loading_repo");

  const parsed = deps.parseGitHubUrl(state.repoUrl);
  if (!parsed.ok) {
    throw new IngestError("INVALID_URL", parsed.message);
  }
  const loaded = await deps.loadRepository(parsed.owner, parsed.repo, parsed.ref);
  checkDeadline(state); // this await can span the deadline; don't redact/scan if it did
  const loadedPaths = loaded.files.map((f) => f.path);

  // Redacted for Semgrep only: everything else on the model path (buildContextWithin,
  // threatPrompt's per-file excerpts, callStructured's final assertNoSecrets) redacts and
  // guards its own text downstream. Detectors get raw content -- password_storage_weak and
  // transport_insecure read source patterns a placeholder would destroy.
  const redacted: RedactedFile[] = modelBoundFiles(loaded.files).map((f) => ({
    path: f.path,
    content: redact(f.content, f.path).content,
  }));

  // B. scanning -------------------------------------------------------------
  setStage(state, "scanning");

  // runDetectors already runs detectGaps as its last step and merges gaps + gap evidence
  // into the result -- see the module header. No second call here.
  const base = runDetectors(loaded.files);
  const detector = {
    ...base,
    evidence: [...base.evidence, ...injectionEvidence(loaded.files)],
  };
  const noGaps = base.gaps.length === 0;

  const [semgrepOutcome, osvResult] = await Promise.all([
    deps
      .scanFiles(redacted)
      .then(
        (raw) => ({ ok: true as const, evidence: normalizeSemgrep(raw) }),
        (cause: unknown) => {
          // Only the documented, expected failure mode degrades. Anything else --
          // SecretLeakError, a network error surfaced as a plain Error, a bug inside
          // scanFiles or its client -- is unexpected and must fail the whole analysis,
          // not be silently folded into "Semgrep was unavailable".
          if (cause instanceof SemgrepMcpError) return { ok: false as const, cause };
          throw cause;
        },
      ),
    deps.scanDependencies(loaded.files as ScanFile[]), // never throws, by contract
  ]);
  checkDeadline(state); // this await can span the deadline too

  let semgrepEvidence: ReturnType<typeof normalizeSemgrep> = [];
  if (semgrepOutcome.ok) {
    semgrepEvidence = semgrepOutcome.evidence;
  } else {
    state.droppedStages.push("semgrep");
  }

  const facts = buildRepoFacts({
    summary: { ...loaded.summary, frameworks: frameworkNames(base) },
    detector,
    semgrep: semgrepEvidence,
    osv: osvResult.evidence,
    files: loaded.files,
  });

  // C. mapping_architecture (PAID) ------------------------------------------
  setStage(state, "mapping_architecture");

  const context = buildContext(facts, ARCHITECTURE_CONTEXT_TOKENS);
  const { draft } = await deps.inferArchitecture({
    repo: { owner: parsed.owner, name: parsed.repo },
    context,
    analysisId: state.id,
    deps: deps.ai,
  });
  checkDeadline(state); // don't start the paid generateThreats call below if already past
  // mergeArchitecture lays out components internally (dagre) -- do not call
  // layoutComponents again here.
  const architecture = mergeArchitecture(draft, facts);

  // D. generating_threats (PAID, fail-fast) ---------------------------------
  setStage(state, "generating_threats");

  const engine = await deps.generateThreats({
    architecture,
    gaps: detector.gaps,
    routePaths: detector.routes.map((route) => route.normalizedPath),
    files: loaded.files,
    sessionCookies: detector.sessionCookies,
    analysisId: state.id,
    deps: deps.ai,
    // Checked before every batch: no new provider request once the job is cancelled or
    // past its deadline, even though this stage's own promise has been orphaned.
    shouldContinue: () => !state.cancelled && Date.now() < state.deadlineAt,
  });
  checkDeadline(state); // don't start the paid selectQuestions call below if already past

  const assembled = assembleThreatModel({
    analysisLevel: state.analysisLevel,
    repo: facts.summary,
    components: architecture.components,
    dataFlows: architecture.dataFlows,
    trustBoundaries: architecture.trustBoundaries,
    unknowns: architecture.unknowns,
    evidence: architecture.evidence,
    threats: engine.threats,
    gaps: detector.gaps,
    assumptions: [],
    limitations: [...architecture.limitations, ...engine.limitations, ...osvResult.limitations],
    droppedStages: state.droppedStages,
  });
  if (!assembled.ok) {
    throw new AiError("AI_FAILURE", "assembled threat model failed validation", {
      issues: assembled.issues,
    });
  }

  const outputIssues = checkModelOutput({
    threats: assembled.model.threats,
    evidence: assembled.model.evidence,
    loadedPaths,
    gaps: detector.gaps,
  });
  // Fatal vs advisory (CLAUDE.md rule 3 / Prompt U): unknown_file means evidence cites a
  // file the loader never fetched -- a fabricated or injected path -- and
  // empty_while_exposed means the analysis was silenced while a proven authn_missing gap
  // exists. Both mean the output itself cannot be trusted, so they fail the run before the
  // paid selectQuestions call below rather than surface as a footnote. injection_echo
  // stays advisory: a title-regex match is a heuristic, and one false positive should not
  // discard an otherwise-good paid analysis.
  const fatalIssues = outputIssues.filter(
    (issue) => issue.code === "unknown_file" || issue.code === "empty_while_exposed",
  );
  if (fatalIssues.length > 0) {
    throw new AiError("OUTPUT_REJECTED", "output checks rejected the model response", {
      issues: fatalIssues.map(({ path, message }) => ({ path, message })),
    });
  }
  const extraLimitations: string[] = outputIssues.map(
    (issue) => `Output check "${issue.code}" flagged an item: ${issue.path}.`,
  );
  if (noGaps) extraLimitations.push(NO_GAPS_LIMITATION);

  // E. questions engine (PAID only if a candidate qualifies) ----------------
  const q = await deps.selectQuestions({
    unknowns: assembled.model.unknowns,
    threats: assembled.model.threats, // scored -- this is why this runs after assemble
    gaps: detector.gaps,
    components: assembled.model.components,
    deployment: detector.deployment,
    analysisId: state.id,
    deps: deps.ai,
  });
  if (q.skippedReasons.length > 0) logSkippedUnknowns(q.skippedReasons);
  // REQUIRED, not hygiene: everything from here on (section F/G) writes to `state`
  // (questions, pending, threatModel) with no further await in between, so this is the
  // one checkpoint that guards all of it. See the module header.
  checkDeadline(state);
  extraLimitations.push(...q.limitations);

  // F. patch questions + limitations back in, re-validate -------------------
  let finalized = finalizeModel({
    model: assembled.model,
    questions: q.questions,
    extraLimitations,
  });
  let questions = q.questions;
  let effects = q.effects;
  if (!finalized.ok) {
    // Degrade rather than fail: the questions referenced something assembly dropped.
    finalized = finalizeModel({
      model: assembled.model,
      questions: [],
      extraLimitations: [
        ...extraLimitations,
        "Developer questions were dropped: they referenced threats that are not in the model.",
      ],
    });
    questions = [];
    effects = new Map();
    if (!finalized.ok) {
      // assembled.model already validated once; this should be unreachable.
      throw new AiError("AI_FAILURE", "finalized threat model failed validation", {
        issues: finalized.issues,
      });
    }
  }

  // G. terminal stage ---------------------------------------------------------
  if (questions.length > 0) {
    state.questions = questions;
    state.pending = { effects, gaps: [...detector.gaps], loadedPaths };
    state.threatModel = finalized.model;
    setStage(state, "awaiting_answers");
    return state;
  }

  setStage(state, "finalizing");
  state.threatModel = finalized.model;
  setStage(state, "complete");
  return state;
}

/**
 * Applies developer answers to a job paused at "awaiting_answers" and finalizes it. Like
 * runAnalysis, this never rejects -- failure is written into the state.
 *
 * Gets a fresh deadline (now + the job's own timeoutMs) rather than the one set at
 * creation: runAnalysis's alarm was cleared when the job paused, so the time a developer
 * spent answering must not count. Only the concurrency slot stays held meanwhile (see
 * countActiveAnalyses), not the clock.
 */
export async function resumeWithAnswers(
  id: string,
  answers: readonly DeveloperAnswer[],
  depsOverride?: Partial<PipelineDeps>,
): Promise<AnalysisState> {
  const state = getAnalysis(id);
  if (!state) throw new Error(`unknown analysis id: ${id}`);
  void resolveDeps(depsOverride); // no external deps needed; kept for signature symmetry

  if (state.stage !== "awaiting_answers" || !state.pending || !state.threatModel) {
    // Reject the OPERATION without mutating the job's own stored state. This matters
    // most when the job already reached "complete" with a valid result (a duplicate or
    // out-of-order resume call, direct API misuse bypassing the route's own guard):
    // routing that through fail() would clear a perfectly good result just because this
    // particular call was invalid. The frozen ErrorCode enum has no "wrong state" code;
    // Part 2's route already guards this itself (409) before ever calling this function,
    // so in practice this only protects a caller that bypasses the route.
    return state;
  }
  // Captured into locals: narrowing on `state.pending`/`state.threatModel` does not
  // survive into the closure below (TS treats a mutable object's properties as possibly
  // reassigned by the time the closure runs), but these `const` bindings do.
  const pending = state.pending;
  const threatModel = state.threatModel;

  // Re-arm the clock for this phase. Inheriting the creation-time deadline failed a
  // finished analysis with TIMEOUT whenever the answer arrived after it had passed.
  state.deadlineAt = Date.now() + state.timeoutMs;

  return withDeadline(
    (async () => {
      const { model, limitations } = applyAnswers({
        model: threatModel,
        effects: pending.effects,
        gaps: pending.gaps,
        answers,
      });

      setStage(state, "finalizing");

      const patched: ThreatModel = {
        ...model,
        limitations: [...model.limitations, ...limitations],
      };
      const validated = validateThreatModel(patched);
      if (!validated.ok) {
        throw new AiError("AI_FAILURE", "answered threat model failed validation", {
          issues: validated.issues,
        });
      }

      state.threatModel = validated.data;
      state.questions = undefined;
      state.pending = undefined;
      setStage(state, "complete");
      return state;
    })(),
    state,
  ).catch((cause) => fail(state, cause));
}
