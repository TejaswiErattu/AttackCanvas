/**
 * useAnalysis: the polling state machine.
 *
 * The hook itself is a thin fetch/dispatch wrapper; the behaviour worth pinning is the
 * reducer and the two predicates that drive it, which is why they are exported. The
 * properties tested here are the ones that cost real money or break the page if they are
 * wrong: polling stops in every terminal state, a finished analysis cannot be reopened by
 * a slow poll, an in-flight poll cannot drag a submitting job back to the question panel,
 * and a malformed response degrades instead of crashing.
 *
 * Plain Node environment: no DOM, no React renderer, no fetch.
 */

import { describe, expect, it } from "vitest";
import {
  analysisReducer,
  INITIAL_ANALYSIS_STATE,
  isTerminal,
  isTerminalStage,
  readApiError,
  pollsAfter,
  readSnapshot,
  shouldPoll,
  type AnalysisSnapshot,
  type AnalysisState,
} from "@/client/useAnalysis";
import type { AnalysisStage } from "@/shared/schema";
import { deepFreeze } from "./helpers";

function snapshot(
  stage: AnalysisStage,
  overrides: Partial<AnalysisSnapshot> = {},
): AnalysisSnapshot {
  return {
    stage,
    stageLabel: stage,
    stageIndex: 1,
    stageCount: 8,
    questions: [],
    view: null,
    basisCounts: null,
    hiddenSummary: null,
    error: null,
    ...overrides,
  };
}

function advance(stages: readonly AnalysisStage[]): AnalysisState {
  return stages.reduce<AnalysisState>(
    (state, stage) => analysisReducer(state, { type: "status", snapshot: snapshot(stage) }),
    INITIAL_ANALYSIS_STATE,
  );
}

describe("analysisReducer: stage progression", () => {
  it("starts in loading and polls immediately", () => {
    expect(INITIAL_ANALYSIS_STATE.phase).toBe("loading");
    expect(shouldPoll(INITIAL_ANALYSIS_STATE)).toBe(true);
  });

  it("maps every working stage to the active phase and keeps polling", () => {
    const working: AnalysisStage[] = [
      "queued",
      "loading_repo",
      "scanning",
      "mapping_architecture",
      "generating_threats",
      "finalizing",
    ];
    working.forEach((stage) => {
      const state = advance([stage]);
      expect(state.phase).toBe("active");
      expect(shouldPoll(state)).toBe(true);
      expect(isTerminal(state)).toBe(false);
    });
  });

  it("walks the real backend sequence through to complete", () => {
    const state = advance([
      "queued",
      "loading_repo",
      "scanning",
      "mapping_architecture",
      "generating_threats",
      "awaiting_answers",
      "finalizing",
      "complete",
    ]);
    expect(state.phase).toBe("complete");
  });

  it("does not mutate the state it is given", () => {
    const state = deepFreeze({ ...INITIAL_ANALYSIS_STATE });
    expect(() =>
      analysisReducer(state, { type: "status", snapshot: snapshot("scanning") }),
    ).not.toThrow();
    expect(state.phase).toBe("loading");
  });
});

describe("analysisReducer: terminal states", () => {
  it("stops polling at complete", () => {
    const state = advance(["scanning", "complete"]);
    expect(state.phase).toBe("complete");
    expect(shouldPoll(state)).toBe(false);
    expect(isTerminal(state)).toBe(true);
  });

  it("stops polling at failed", () => {
    const state = advance(["scanning", "failed"]);
    expect(state.phase).toBe("failed");
    expect(shouldPoll(state)).toBe(false);
    expect(isTerminal(state)).toBe(true);
  });

  it("does not reopen a finished analysis from a slow in-flight poll", () => {
    const complete = advance(["scanning", "complete"]);
    const stale = analysisReducer(complete, {
      type: "status",
      snapshot: snapshot("generating_threats"),
    });

    expect(stale).toBe(complete);
    expect(shouldPoll(stale)).toBe(false);
  });

  it("reports which stages the backend treats as terminal", () => {
    expect(isTerminalStage("complete")).toBe(true);
    expect(isTerminalStage("failed")).toBe(true);
    expect(isTerminalStage("awaiting_answers")).toBe(false);
    expect(isTerminalStage("scanning")).toBe(false);
  });

  it("carries the analysis's own error through on failure", () => {
    const failure = snapshot("failed", {
      error: {
        code: "AI_FAILURE",
        title: "Analysis failed",
        message: "The analysis couldn't be completed.",
        canRetry: true,
      },
    });
    const state = analysisReducer(INITIAL_ANALYSIS_STATE, {
      type: "status",
      snapshot: failure,
    });

    expect(state.snapshot?.error?.code).toBe("AI_FAILURE");
    // The stage is terminal even though the error is marked retryable: retrying means a
    // new analysis, not more polling of this one.
    expect(shouldPoll(state)).toBe(false);
  });
});

describe("analysisReducer: awaiting answers", () => {
  it("pauses polling while waiting on the user", () => {
    const state = advance(["generating_threats", "awaiting_answers"]);
    expect(state.phase).toBe("awaiting_answers");
    expect(shouldPoll(state)).toBe(false);
    expect(isTerminal(state)).toBe(false);
  });

  it("stays paused while the answers are being submitted", () => {
    const waiting = advance(["awaiting_answers"]);
    const submitting = analysisReducer(waiting, { type: "submit_answers" });

    expect(submitting.phase).toBe("submitting");
    expect(shouldPoll(submitting)).toBe(false);
  });

  it("resumes polling once the backend accepts the answers", () => {
    const submitting = analysisReducer(advance(["awaiting_answers"]), {
      type: "submit_answers",
    });
    const accepted = analysisReducer(submitting, { type: "answers_accepted" });

    expect(accepted.phase).toBe("active");
    expect(shouldPoll(accepted)).toBe(true);
  });

  it("ignores an in-flight awaiting_answers poll that lands mid-submission", () => {
    const submitting = analysisReducer(advance(["awaiting_answers"]), {
      type: "submit_answers",
    });
    const late = analysisReducer(submitting, {
      type: "status",
      snapshot: snapshot("awaiting_answers"),
    });

    expect(late).toBe(submitting);
    expect(late.phase).toBe("submitting");
  });

  it("returns to the questions when the submission is rejected", () => {
    const submitting = analysisReducer(advance(["awaiting_answers"]), {
      type: "submit_answers",
    });
    const rejected = analysisReducer(submitting, {
      type: "answers_failed",
      error: {
        code: "AI_FAILURE",
        title: "Analysis failed",
        message: "This analysis is not waiting for answers.",
        canRetry: true,
      },
    });

    expect(rejected.phase).toBe("awaiting_answers");
    expect(rejected.error?.message).toContain("not waiting for answers");
  });

  // After a failed submission the hook fetches the status once; these pin what that
  // single "status" does to the rejected state.
  const rejectedState = (): AnalysisState =>
    analysisReducer(
      analysisReducer(advance(["awaiting_answers"]), { type: "submit_answers" }),
      {
        type: "answers_failed",
        error: {
          code: "TIMEOUT",
          title: "Connection problem",
          message: "We couldn't confirm your answers were received.",
          canRetry: true,
        },
      },
    );

  it("keeps the submission error when the follow-up status finds the job still waiting", () => {
    const refreshed = analysisReducer(rejectedState(), {
      type: "status",
      snapshot: snapshot("awaiting_answers", { stageIndex: 6 }),
    });

    expect(refreshed.phase).toBe("awaiting_answers");
    expect(refreshed.error?.message).toContain("couldn't confirm");
    expect(refreshed.snapshot?.stageIndex).toBe(6);
    expect(shouldPoll(refreshed)).toBe(false);
  });

  it("moves on when the follow-up status finds the answers were accepted after all", () => {
    const refreshed = analysisReducer(rejectedState(), {
      type: "status",
      snapshot: snapshot("complete"),
    });

    expect(refreshed.phase).toBe("complete");
    expect(refreshed.error).toBeNull();
  });
});

describe("analysisReducer: request errors", () => {
  const retryable = {
    code: "TIMEOUT" as const,
    title: "Connection problem",
    message: "We couldn't reach the analysis service.",
    canRetry: true,
  };
  const fatal = {
    code: "AI_FAILURE" as const,
    title: "Analysis not found",
    message: "No analysis exists with that id, or it has expired.",
    canRetry: false,
  };

  it("keeps polling through a retryable error", () => {
    const state = analysisReducer(advance(["scanning"]), {
      type: "request_failed",
      error: retryable,
    });

    expect(state.phase).toBe("error");
    expect(shouldPoll(state)).toBe(true);
    expect(isTerminal(state)).toBe(false);
  });

  it("keeps the last good snapshot so the page does not blank out", () => {
    const state = analysisReducer(advance(["scanning"]), {
      type: "request_failed",
      error: retryable,
    });

    expect(state.snapshot?.stage).toBe("scanning");
  });

  it("stops polling on a non-retryable error", () => {
    const state = analysisReducer(INITIAL_ANALYSIS_STATE, {
      type: "request_failed",
      error: fatal,
    });

    expect(shouldPoll(state)).toBe(false);
    expect(isTerminal(state)).toBe(true);
  });

  it("resumes polling after an explicit retry", () => {
    const failed = analysisReducer(INITIAL_ANALYSIS_STATE, {
      type: "request_failed",
      error: retryable,
    });
    const retried = analysisReducer(failed, { type: "retry" });

    expect(retried.error).toBeNull();
    expect(shouldPoll(retried)).toBe(true);
  });
});

describe("readSnapshot", () => {
  it("reads a full status response without altering the view model", () => {
    const view = { threats: [], counts: { critical: 1, high: 0, medium: 0, low: 0 } };
    const result = readSnapshot({
      stage: "complete",
      stageLabel: "Complete",
      stageIndex: 8,
      stageCount: 8,
      questions: [{ id: "q1" }],
      threatModel: view,
      basisCounts: { evidence_backed: 2, assumption_dependent: 1 },
    });

    expect(result?.stage).toBe("complete");
    expect(result?.stageIndex).toBe(8);
    expect(result?.questions).toHaveLength(1);
    // Passed through by reference: the client must not rebuild or re-score it.
    expect(result?.view).toEqual(view);
    expect(result?.basisCounts).toEqual({ evidence_backed: 2, assumption_dependent: 1 });
  });

  it("rejects a response without a recognised stage", () => {
    expect(readSnapshot({ stage: "not-a-stage" })).toBeNull();
    expect(readSnapshot(null)).toBeNull();
    expect(readSnapshot("nope")).toBeNull();
    expect(readSnapshot({})).toBeNull();
  });

  it("falls back safely when optional fields are missing", () => {
    const result = readSnapshot({ stage: "scanning" });

    expect(result?.stageLabel).toBe("Scanning code, dependencies and missing controls");
    expect(result?.questions).toEqual([]);
    expect(result?.view).toBeNull();
    expect(result?.basisCounts).toBeNull();
    expect(result?.error).toBeNull();
  });

  it("ignores fields of the wrong type instead of crashing", () => {
    const result = readSnapshot({
      stage: "scanning",
      stageIndex: "three",
      questions: "not-an-array",
      threatModel: 42,
    });

    expect(result?.stageIndex).toBe(0);
    expect(result?.questions).toEqual([]);
    expect(result?.view).toBeNull();
  });
});

describe("readApiError", () => {
  it("reads the shared error body, including canRetry", () => {
    const error = readApiError(
      {
        error: {
          code: "RATE_LIMITED",
          title: "Too many requests",
          message: "Wait a moment and try again.",
          canRetry: true,
        },
      },
      429,
    );

    expect(error).toEqual({
      code: "RATE_LIMITED",
      title: "Too many requests",
      message: "Wait a moment and try again.",
      canRetry: true,
    });
  });

  it("treats a missing canRetry as not retryable", () => {
    const error = readApiError({ error: { code: "INVALID_URL" } }, 400);
    expect(error?.canRetry).toBe(false);
  });

  it("returns null when a 200 body carries no error", () => {
    expect(readApiError({ stage: "complete" }, 0)).toBeNull();
  });

  it("supplies non-retryable copy for an unreadable 404", () => {
    const error = readApiError(null, 404);
    expect(error?.canRetry).toBe(false);
    expect(error?.title).toBe("Analysis not found");
    // The same code the route's own 404 body carries, not the catch-all.
    expect(error?.code).toBe("NOT_FOUND");
  });
});

describe("pollsAfter", () => {
  const status = (stage: AnalysisStage) => ({ type: "status" as const, snapshot: snapshot(stage) });
  const failed = (canRetry: boolean) => ({
    type: "request_failed" as const,
    error: { code: "NETWORK_ERROR" as const, title: "t", message: "m", canRetry },
  });

  it("keeps polling through the working stages", () => {
    for (const stage of ["queued", "loading_repo", "scanning", "generating_threats", "finalizing"] as const) {
      expect(pollsAfter(status(stage)), stage).toBe(true);
    }
  });

  it("stops on a terminal stage or when the job waits for answers", () => {
    expect(pollsAfter(status("complete"))).toBe(false);
    expect(pollsAfter(status("failed"))).toBe(false);
    expect(pollsAfter(status("awaiting_answers"))).toBe(false);
  });

  it("keeps polling through a retryable request failure and stops on a permanent one", () => {
    expect(pollsAfter(failed(true))).toBe(true);
    expect(pollsAfter(failed(false))).toBe(false);
  });

  it("agrees with shouldPoll on the committed state from every phase the loop runs in", () => {
    const running: AnalysisState[] = [
      INITIAL_ANALYSIS_STATE,
      advance(["scanning"]),
      analysisReducer(advance(["scanning"]), failed(true)),
    ];
    const actions = [status("scanning"), status("complete"), status("awaiting_answers"), failed(true), failed(false)];
    for (const state of running) {
      for (const action of actions) {
        expect(pollsAfter(action)).toBe(shouldPoll(analysisReducer(state, action)));
      }
    }
  });
});
