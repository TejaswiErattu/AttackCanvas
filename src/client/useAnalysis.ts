"use client";

/**
 * Polling client for one analysis.
 *
 * The backend already owns the state machine; this hook only mirrors it. It polls the
 * existing GET /api/analyze/[id] and posts to the existing POST /api/analyze/[id]/answers.
 * It computes nothing about the analysis itself — severity, confidence, priority, basis,
 * ordering and stage labels all arrive from the server (CLAUDE.md rule 2).
 *
 * The state machine is exported as a plain reducer plus two predicates so it can be
 * unit-tested in the plain Node environment, with no DOM and no React renderer. The hook
 * below is a thin wrapper: fetch, dispatch, reschedule.
 *
 * Polling stops whenever there is nothing left to learn:
 *   - "complete" / "failed" are terminal;
 *   - "awaiting_answers" is a user-input pause, so we idle until answers are submitted and
 *     resume from `answers_accepted`;
 *   - a non-retryable request error (a 404 for an expired id) stops too, since retrying it
 *     would only produce the same 404 forever.
 *
 * A failed answer submission is the one place the client cannot tell where the job is: a
 * lost response may hide answers the server did accept, a 409 means the job already moved
 * on (another tab), and a 404 means it expired. So after `answers_failed` the hook fetches
 * the status exactly once. That single fetch settles it -- a finished job shows its
 * result, an expired one shows the non-retryable error, and a job still waiting keeps the
 * submission error on the question panel -- without starting a polling loop.
 *
 * Repository-derived strings reaching this file (threat titles, file paths, snippets) are
 * untrusted data and are only ever rendered as text by the components, never as HTML.
 */

import { useCallback, useEffect, useReducer } from "react";
import { STAGE_LABELS } from "@/shared/labels";
import type { AnalysisStage, Basis } from "@/shared/schema";
import type {
  AnalysisError,
  DashboardViewModel,
  QuestionData,
} from "@/shared/viewModel";

export type BasisCounts = Record<Basis, number>;

export type HiddenReason = "no_evidence" | "assumptions" | "weak_evidence";

/** Mirrors the server's summarizeHidden: scored threats, how many are hidden, and why. */
export type HiddenSummary = {
  scored: number;
  hidden: number;
  topReason: HiddenReason | null;
  topReasonCount: number;
};

/** One poll of GET /api/analyze/[id], normalised and safe to render. */
export type AnalysisSnapshot = {
  stage: AnalysisStage;
  stageLabel: string;
  stageIndex: number;
  stageCount: number;
  /** Empty until the backend reaches "awaiting_answers". */
  questions: QuestionData[];
  /** Present from "awaiting_answers" onward, so partial results can be shown early. */
  view: DashboardViewModel | null;
  basisCounts: BasisCounts | null;
  hiddenSummary: HiddenSummary | null;
  /** The analysis's own failure, present when stage is "failed". */
  error: AnalysisError | null;
};

export type AnalysisPhase =
  | "loading"
  | "active"
  | "awaiting_answers"
  | "submitting"
  | "complete"
  | "failed"
  | "error";

export type AnalysisState = {
  phase: AnalysisPhase;
  /** The last good snapshot; kept across a transient request error. */
  snapshot: AnalysisSnapshot | null;
  /** A transport/API error, distinct from a snapshot's own analysis failure. */
  error: AnalysisError | null;
};

export type AnalysisAction =
  | { type: "status"; snapshot: AnalysisSnapshot }
  | { type: "request_failed"; error: AnalysisError }
  | { type: "submit_answers" }
  | { type: "answers_accepted" }
  | { type: "answers_failed"; error: AnalysisError }
  | { type: "retry" };

export type AnswerSubmission = {
  questionId: string;
  status: "answered" | "skipped" | "unsure";
  optionIndex?: number;
};

export const INITIAL_ANALYSIS_STATE: AnalysisState = {
  phase: "loading",
  snapshot: null,
  error: null,
};

export const DEFAULT_POLL_MS = 1200;

/** For a failed poll. True to its word: a retryable error keeps the polling loop going. */
const NETWORK_ERROR: AnalysisError = {
  code: "NETWORK_ERROR",
  title: "Connection problem",
  message: "We couldn't reach the analysis service. Retrying...",
  canRetry: true,
};

/**
 * For an answer submission that got no response. Nothing resubmits automatically, and the
 * answers may or may not have arrived, so this copy promises no retry; the one status
 * fetch that follows moves the page on if they did arrive.
 */
const ANSWERS_NETWORK_ERROR: AnalysisError = {
  code: "NETWORK_ERROR",
  title: "Connection problem",
  message:
    "We couldn't confirm your answers were received. If the questions are still shown, submit them again.",
  canRetry: true,
};

const MALFORMED_ERROR: AnalysisError = {
  code: "AI_FAILURE",
  title: "Unexpected response",
  message: "The analysis service returned something we couldn't read.",
  canRetry: true,
};

// ---------------------------------------------------------------------------
// Reading the API response
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isStage(value: unknown): value is AnalysisStage {
  return typeof value === "string" && Object.hasOwn(STAGE_LABELS, value);
}

function readNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function readString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function readBasisCounts(value: unknown): BasisCounts | null {
  if (!isRecord(value)) return null;
  return {
    evidence_backed: readNumber(value.evidence_backed, 0),
    assumption_dependent: readNumber(value.assumption_dependent, 0),
  };
}

const HIDDEN_REASONS: readonly HiddenReason[] = ["no_evidence", "assumptions", "weak_evidence"];

export function readHiddenSummary(value: unknown): HiddenSummary | null {
  if (!isRecord(value)) return null;
  const reason = value.topReason;
  return {
    scored: readNumber(value.scored, 0),
    hidden: readNumber(value.hidden, 0),
    topReason: HIDDEN_REASONS.find((r) => r === reason) ?? null,
    topReasonCount: readNumber(value.topReasonCount, 0),
  };
}

/**
 * Normalises a GET response into a snapshot, or null when it is not usable. Only `stage`
 * is genuinely required; everything else falls back so a partial response degrades the UI
 * instead of crashing it. The view model is passed through untouched — re-deriving any of
 * it on the client is exactly what must not happen.
 */
export function readSnapshot(json: unknown): AnalysisSnapshot | null {
  if (!isRecord(json)) return null;
  if (!isStage(json.stage)) return null;
  const stage = json.stage;
  return {
    stage,
    stageLabel: readString(json.stageLabel, STAGE_LABELS[stage]),
    stageIndex: readNumber(json.stageIndex, 0),
    stageCount: readNumber(json.stageCount, 0),
    questions: Array.isArray(json.questions) ? (json.questions as QuestionData[]) : [],
    view: isRecord(json.threatModel) ? (json.threatModel as DashboardViewModel) : null,
    basisCounts: readBasisCounts(json.basisCounts),
    hiddenSummary: readHiddenSummary(json.hiddenSummary),
    error: readApiError(json, 0),
  };
}

/**
 * Reads the shared `{ error: { code, title, message, canRetry } }` body. Returns null when
 * the body carries no error. `status` only picks the fallback copy when the body is
 * unreadable, so a 404 still reads as non-retryable.
 */
export function readApiError(json: unknown, status: number): AnalysisError | null {
  if (!isRecord(json) || !isRecord(json.error)) {
    if (status === 0) return null;
    return status === 404
      ? {
          code: "NOT_FOUND",
          title: "Analysis not found",
          message: "No analysis exists with that id, or it has expired.",
          canRetry: false,
        }
      : MALFORMED_ERROR;
  }
  const error = json.error;
  return {
    // Cast, not validated: a code this client does not know yet is still worth showing,
    // and `code` is only ever displayed, never matched on.
    code: readString(error.code, "AI_FAILURE") as AnalysisError["code"],
    title: readString(error.title, "Analysis failed"),
    message: readString(error.message, "The analysis couldn't be completed."),
    canRetry: error.canRetry === true,
  };
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

function phaseForStage(stage: AnalysisStage): AnalysisPhase {
  if (stage === "complete") return "complete";
  if (stage === "failed") return "failed";
  if (stage === "awaiting_answers") return "awaiting_answers";
  return "active";
}

/** Terminal in the backend's sense: the analysis will not change again. */
export function isTerminalStage(stage: AnalysisStage): boolean {
  return stage === "complete" || stage === "failed";
}

/** True once nothing further can change without a new request from the user. */
export function isTerminal(state: AnalysisState): boolean {
  if (state.phase === "complete" || state.phase === "failed") return true;
  return state.phase === "error" && state.error?.canRetry !== true;
}

/** Drives the polling loop: false means stop scheduling fetches. */
export function shouldPoll(state: AnalysisState): boolean {
  switch (state.phase) {
    case "loading":
    case "active":
      return true;
    case "error":
      // A retryable error keeps polling — that *is* the retry.
      return state.error?.canRetry === true;
    case "awaiting_answers":
    case "submitting":
    case "complete":
    case "failed":
      return false;
  }
}

export function analysisReducer(
  state: AnalysisState,
  action: AnalysisAction,
): AnalysisState {
  switch (action.type) {
    case "status": {
      const { snapshot } = action;
      // Terminal stays terminal: a slow poll issued before completion must not reopen a
      // finished analysis.
      if (
        (state.phase === "complete" || state.phase === "failed") &&
        !isTerminalStage(snapshot.stage)
      ) {
        return state;
      }
      // A poll already in flight when the user submitted answers must not drag the job
      // back to the question panel.
      if (state.phase === "submitting" && snapshot.stage === "awaiting_answers") {
        return state;
      }
      // The status fetch after a failed submission found the job still waiting: keep the
      // submission error on screen so the user knows to submit again.
      if (state.phase === "awaiting_answers" && snapshot.stage === "awaiting_answers") {
        return { ...state, snapshot };
      }
      return { phase: phaseForStage(snapshot.stage), snapshot, error: null };
    }
    case "request_failed":
      // The last good snapshot is kept so the dashboard does not blank out on one bad poll.
      return { phase: "error", snapshot: state.snapshot, error: action.error };
    case "submit_answers":
      return { ...state, phase: "submitting", error: null };
    case "answers_accepted":
      // Resume polling; the next status response supplies the real stage.
      return { ...state, phase: "active", error: null };
    case "answers_failed":
      // Back to the questions so the user can correct and resubmit. submitAnswers then
      // fetches the status once, which moves the page on if the job is no longer waiting.
      return { ...state, phase: "awaiting_answers", error: action.error };
    case "retry":
      return {
        ...state,
        phase: state.snapshot ? "active" : "loading",
        error: null,
      };
  }
}

/** Any phase the polling loop runs in; the reducer treats them all alike for a poll. */
const POLLING_STATE: AnalysisState = { phase: "active", snapshot: null, error: null };

/**
 * Whether the polling loop schedules another round after a poll produced `action`.
 *
 * The loop only runs while polling is active (loading, active, or a retryable error), and
 * from each of those phases the reducer handles `status` and `request_failed` the same
 * way, so this is exactly the phase React is about to commit. Deciding here, rather than
 * waiting for that commit to cancel the loop, closes a race: when the commit landed later
 * than one poll interval, one more request went out after a terminal response.
 */
export function pollsAfter(action: AnalysisAction): boolean {
  return shouldPoll(analysisReducer(POLLING_STATE, action));
}

/** One GET of the analysis, as the action it produces. Never throws. */
async function fetchStatus(id: string): Promise<AnalysisAction> {
  try {
    const response = await fetch(`/api/analyze/${encodeURIComponent(id)}`, {
      cache: "no-store",
    });
    const json: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      return {
        type: "request_failed",
        error: readApiError(json, response.status) ?? MALFORMED_ERROR,
      };
    }
    const snapshot = readSnapshot(json);
    return snapshot
      ? { type: "status", snapshot }
      : { type: "request_failed", error: MALFORMED_ERROR };
  } catch {
    return { type: "request_failed", error: NETWORK_ERROR };
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export type UseAnalysisResult = AnalysisState & {
  /**
   * Posts answers and resumes polling. Resolves true when the backend accepted them; on
   * failure, resolves false only after one status fetch has settled the job's real stage.
   */
  submitAnswers: (answers: readonly AnswerSubmission[]) => Promise<boolean>;
  /** Clears a request error and resumes polling. */
  retry: () => void;
};

export function useAnalysis(
  id: string,
  pollMs: number = DEFAULT_POLL_MS,
): UseAnalysisResult {
  const [state, dispatch] = useReducer(analysisReducer, INITIAL_ANALYSIS_STATE);

  const poll = useCallback(async (): Promise<AnalysisAction> => {
    const action = await fetchStatus(id);
    dispatch(action);
    return action;
  }, [id]);

  const active = shouldPoll(state);

  useEffect(() => {
    if (!active || id === "") return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const run = async (): Promise<void> => {
      const action = await poll();
      // `cancelled` is checked after the await so an unmounted/paused loop stops here
      // rather than scheduling one more round, and pollsAfter stops it on a terminal
      // response without waiting for React to commit that response.
      if (!cancelled && pollsAfter(action)) timer = setTimeout(() => void run(), pollMs);
    };
    void run();

    return () => {
      cancelled = true;
      if (timer !== undefined) clearTimeout(timer);
    };
    // `active` restarts the loop when polling resumes after answers are submitted.
  }, [active, id, pollMs, poll]);

  const submitAnswers = useCallback(
    async (answers: readonly AnswerSubmission[]): Promise<boolean> => {
      dispatch({ type: "submit_answers" });
      try {
        const response = await fetch(
          `/api/analyze/${encodeURIComponent(id)}/answers`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ answers }),
          },
        );
        const json: unknown = await response.json().catch(() => null);
        if (response.ok) {
          dispatch({ type: "answers_accepted" });
          return true;
        }
        dispatch({
          type: "answers_failed",
          error: readApiError(json, response.status) ?? MALFORMED_ERROR,
        });
      } catch {
        dispatch({ type: "answers_failed", error: ANSWERS_NETWORK_ERROR });
      }
      // Either way the client no longer knows the job's stage (see the module header), so
      // ask once. awaiting_answers does not poll, so without this a job that already
      // finished or expired would sit behind the question panel indefinitely.
      await poll();
      return false;
    },
    [id, poll],
  );

  const retry = useCallback(() => dispatch({ type: "retry" }), []);

  return { ...state, submitAnswers, retry };
}
