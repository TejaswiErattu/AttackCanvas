// @vitest-environment jsdom

/**
 * useAnalysis, the hook itself: the fetch / dispatch / reschedule loop around the reducer
 * that tests/useAnalysis.test.ts pins.
 *
 * The reducer tests prove which phases *should* poll; these prove the effect actually does
 * what they say -- that the loop stops at complete and on a 404, stays idle while the user
 * answers questions, resumes after the answers are accepted, recovers from a failed
 * submission with exactly one status fetch, and schedules nothing once unmounted.
 *
 * `fetch` is stubbed with a tiny in-memory stand-in for the three analyze routes, so the
 * network is never touched. Real timers with a 5 ms poll interval keep this fast without
 * fake-timer interplay with Testing Library's waitFor.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { useAnalysis, type AnswerSubmission } from "@/client/useAnalysis";
import type { AnalysisStage } from "@/shared/schema";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const POLL_MS = 5;
const ID = "job-1";
const ANSWERS: AnswerSubmission[] = [{ questionId: "q1", status: "skipped" }];

const QUESTIONS = [
  {
    id: "q1",
    text: "Is the API behind authentication?",
    whyAsking: "It changes two threat ratings.",
    options: ["Yes", "No"],
    allowsUnsure: true,
    defaultAssumption: "We assume it is not.",
    index: 1,
    total: 1,
  },
];

/** The shape GET /api/analyze/[id] sends; only what the hook reads is filled in. */
function statusBody(stage: AnalysisStage): unknown {
  return {
    stage,
    stageLabel: stage,
    stageIndex: 1,
    stageCount: 8,
    questions: stage === "awaiting_answers" ? QUESTIONS : undefined,
    threatModel: stage === "complete" ? { threats: [] } : undefined,
  };
}

/** notFoundResponse() in src/server/http/errors.ts. */
const NOT_FOUND = {
  error: {
    code: "NOT_FOUND",
    title: "Analysis not found",
    message: "No analysis exists with that id, or it has expired.",
    canRetry: false,
  },
};

/** The answers route's 409 for a job that is no longer at awaiting_answers. */
const CONFLICT = {
  error: {
    code: "NOT_AWAITING_ANSWERS",
    title: "No longer waiting for answers",
    message:
      "This analysis isn't waiting for answers anymore; it may already have finished. Reload the page to see where it stands.",
    canRetry: false,
  },
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

type Call = { method: string; url: string };

/** Installs a fetch stub. The handler may throw to simulate a network failure. */
function stubFetch(handler: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const call = { method: init?.method ?? "GET", url: String(input) };
      calls.push(call);
      return handler(call);
    }),
  );
  return {
    gets: () => calls.filter((c) => c.method === "GET").length,
    posts: () => calls.filter((c) => c.method === "POST").length,
    calls,
  };
}

/** Lets several poll intervals pass inside act, so any stray loop would show up. */
async function idle(ms = POLL_MS * 12): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, ms));
  });
}

function renderAnalysis() {
  return renderHook(() => useAnalysis(ID, POLL_MS));
}

/** A job paused at awaiting_answers whose answers route is `onPost`. */
function awaitingServer(onPost: (server: { stage: AnalysisStage }) => Response) {
  const server: { stage: AnalysisStage; gone: boolean } = {
    stage: "awaiting_answers",
    gone: false,
  };
  const fetchStub = stubFetch((call) => {
    if (call.method === "POST") return onPost(server);
    if (server.gone) return json(NOT_FOUND, 404);
    return json(statusBody(server.stage));
  });
  return { server, ...fetchStub };
}

async function submit(result: { current: ReturnType<typeof useAnalysis> }): Promise<boolean> {
  let accepted = true;
  await act(async () => {
    accepted = await result.current.submitAnswers(ANSWERS);
  });
  return accepted;
}

describe("useAnalysis polling loop", () => {
  it("schedules no further round after a terminal response, without waiting for React to commit it", async () => {
    // A delay no other timer here uses, so the loop's own reschedules can be counted.
    // Before pollsAfter, the loop scheduled a round after EVERY response and relied on
    // React's commit to cancel it; when that commit came later than the interval, one
    // more request went out after "complete".
    const LOOP_MS = 13;
    const stages: AnalysisStage[] = ["queued", "complete"];
    stubFetch(() => json(statusBody(stages.shift() ?? "complete")));
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");

    const { result } = renderHook(() => useAnalysis(ID, LOOP_MS));
    await waitFor(() => expect(result.current.phase).toBe("complete"));
    await idle();

    const loopRounds = setTimeoutSpy.mock.calls.filter(([, delay]) => delay === LOOP_MS);
    // One round after "queued"; none after "complete".
    expect(loopRounds).toHaveLength(1);
    setTimeoutSpy.mockRestore();
  });

  it("polls through the working stages and stops at complete", async () => {
    const stages: AnalysisStage[] = ["queued", "scanning", "complete"];
    const { gets } = stubFetch(() => json(statusBody(stages.shift() ?? "complete")));

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("complete"));
    expect(gets()).toBe(3);

    await idle();
    expect(gets()).toBe(3);
  });

  it("stops for good on a 404", async () => {
    const { gets } = stubFetch(() => json(NOT_FOUND, 404));

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("error"));
    expect(result.current.error?.canRetry).toBe(false);

    await idle();
    expect(gets()).toBe(1);
  });

  it("retry() restarts a loop that a non-retryable error stopped", async () => {
    // The reducer test pins that `retry` makes shouldPoll true; this proves the hook's
    // effect then actually issues requests again, and that they reach the server.
    let gone = true;
    const { gets } = stubFetch(() =>
      gone ? json(NOT_FOUND, 404) : json(statusBody("complete")),
    );

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("error"));
    await idle();
    expect(gets()).toBe(1); // stopped for good, exactly as in the 404 test above

    gone = false;
    act(() => result.current.retry());
    expect(result.current.error).toBeNull();

    await waitFor(() => expect(result.current.phase).toBe("complete"));
    expect(gets()).toBe(2);
  });

  it("reports an unreachable server as a retryable NETWORK_ERROR and keeps polling", async () => {
    const { gets } = stubFetch(() => {
      throw new TypeError("Failed to fetch");
    });

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("error"));
    expect(result.current.error).toMatchObject({ code: "NETWORK_ERROR", canRetry: true });
    await waitFor(() => expect(gets()).toBeGreaterThanOrEqual(3));
  });

  it("keeps polling through a transient network failure", async () => {
    let first = true;
    stubFetch(() => {
      if (first) {
        first = false;
        throw new TypeError("Failed to fetch");
      }
      return json(statusBody("complete"));
    });

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("complete"));
    expect(result.current.error).toBeNull();
  });

  it("stays idle while awaiting answers and resumes once they are accepted", async () => {
    const { server, gets } = awaitingServer((s) => {
      s.stage = "complete";
      return json({ status: "complete" }, 202);
    });

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("awaiting_answers"));
    const whileWaiting = gets();
    await idle();
    expect(gets()).toBe(whileWaiting);

    expect(await submit(result)).toBe(true);
    await waitFor(() => expect(result.current.phase).toBe("complete"));
    expect(gets()).toBeGreaterThan(whileWaiting);
    expect(server.stage).toBe("complete");
  });
});

describe("useAnalysis recovery after a failed submission", () => {
  it("shows the result when the answers arrived but the response was lost", async () => {
    const { gets } = awaitingServer((s) => {
      s.stage = "complete"; // the server accepted and finished ...
      throw new TypeError("Failed to fetch"); // ... but the client never heard back
    });

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("awaiting_answers"));
    const before = gets();

    expect(await submit(result)).toBe(false);
    expect(result.current.phase).toBe("complete");
    expect(result.current.snapshot?.view).not.toBeNull();
    expect(gets()).toBe(before + 1);

    await idle();
    expect(gets()).toBe(before + 1);
  });

  it("shows the result when another tab already answered (409)", async () => {
    const { server } = awaitingServer(() => json(CONFLICT, 409));

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("awaiting_answers"));
    server.stage = "complete"; // answered and finished elsewhere

    expect(await submit(result)).toBe(false);
    expect(result.current.phase).toBe("complete");
    expect(result.current.error).toBeNull();
  });

  it("shows the non-retryable error when the analysis expired (404)", async () => {
    const { server } = awaitingServer(() => json(NOT_FOUND, 404));

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("awaiting_answers"));
    server.gone = true; // swept after the TTL while the questions sat open

    expect(await submit(result)).toBe(false);
    // phase "error" with canRetry false is what AnalysisView renders with "Start over".
    expect(result.current.phase).toBe("error");
    expect(result.current.error?.canRetry).toBe(false);
    expect(result.current.error?.title).toBe("Analysis not found");
  });

  it("keeps the questions and an honest error when the job is still waiting", async () => {
    const { gets } = awaitingServer(() => {
      throw new TypeError("Failed to fetch"); // never reached the server
    });

    const { result } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("awaiting_answers"));
    const before = gets();

    expect(await submit(result)).toBe(false);
    expect(result.current.phase).toBe("awaiting_answers");
    expect(result.current.snapshot?.questions).toHaveLength(1);
    // A connection failure, reported as one rather than as a timeout.
    expect(result.current.error?.code).toBe("NETWORK_ERROR");
    // Nothing retries a submission, so the copy must not claim it does.
    expect(result.current.error?.message).not.toMatch(/retrying/i);
    expect(result.current.error?.message).toMatch(/submit them again/);

    // Exactly one status fetch, and no loop left running behind the question panel.
    expect(gets()).toBe(before + 1);
    await idle();
    expect(gets()).toBe(before + 1);
  });
});

describe("useAnalysis cleanup", () => {
  it("schedules nothing after unmount", async () => {
    const { gets } = stubFetch(() => json(statusBody("scanning")));

    const { result, unmount } = renderAnalysis();
    await waitFor(() => expect(result.current.phase).toBe("active"));
    unmount();
    const atUnmount = gets();

    await idle();
    expect(gets()).toBe(atUnmount);
  });

  it("does not reschedule when a poll in flight resolves after unmount", async () => {
    let release: (response: Response) => void = () => {};
    const { gets } = stubFetch(
      () => new Promise<Response>((resolve) => (release = resolve)),
    );

    const { unmount } = renderAnalysis();
    await waitFor(() => expect(gets()).toBe(1));
    unmount();
    release(json(statusBody("scanning")));

    await idle();
    expect(gets()).toBe(1);
  });
});
