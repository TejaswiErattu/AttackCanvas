/**
 * POST /api/analyze/[id]/answers. src/server/analysis/pipeline.ts is mocked: applying an
 * answer is tests/pipeline.test.ts's job, this only checks the route's own guards.
 */

import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/server/analysis/pipeline", () => ({
  getAnalysis: vi.fn(),
  resumeWithAnswers: vi.fn(),
}));
vi.mock("@/server/analysis/demo", () => ({
  resumeDemoAnalysis: vi.fn(),
}));

import { POST } from "@/app/api/analyze/[id]/answers/route";
import { getAnalysis, resumeWithAnswers } from "@/server/analysis/pipeline";
import { resumeDemoAnalysis } from "@/server/analysis/demo";

function post(id: string, body: unknown) {
  return POST(
    new NextRequest(`http://localhost/api/analyze/${id}/answers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    { params: Promise.resolve({ id }) },
  );
}

beforeEach(() => {
  vi.mocked(getAnalysis).mockReset();
  vi.mocked(resumeWithAnswers).mockReset();
  vi.mocked(resumeDemoAnalysis).mockReset();
});

describe("POST /api/analyze/[id]/answers", () => {
  it("404s for an unknown id, without calling resumeWithAnswers", async () => {
    vi.mocked(getAnalysis).mockReturnValue(undefined);
    const response = await post("nope", { answers: [{ questionId: "q-1", status: "skipped" }] });
    expect(response.status).toBe(404);
    expect((await response.json()).error).toMatchObject({ code: "NOT_FOUND", canRetry: false });
    expect(resumeWithAnswers).not.toHaveBeenCalled();
  });

  it("409s when the job is not awaiting_answers", async () => {
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-1", stage: "scanning" } as never);
    const response = await post("job-1", { answers: [{ questionId: "q-1", status: "skipped" }] });
    expect(response.status).toBe(409);
    expect((await response.json()).error).toMatchObject({
      code: "NOT_AWAITING_ANSWERS",
      title: "No longer waiting for answers",
      canRetry: false,
    });
    expect(resumeWithAnswers).not.toHaveBeenCalled();
  });

  it("400s on a malformed body", async () => {
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-2", stage: "awaiting_answers" } as never);
    const response = await post("job-2", { answers: [] }); // .min(1) rejects empty
    expect(response.status).toBe(400);
    const { error } = await response.json();
    expect(error).toMatchObject({ code: "INVALID_REQUEST", canRetry: false });
    expect(error.message).toContain("non-empty array of at most 10 entries");
    expect(resumeWithAnswers).not.toHaveBeenCalled();
  });

  it("400s with INVALID_REQUEST on a body that is not JSON", async () => {
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-2", stage: "awaiting_answers" } as never);
    const response = await POST(
      new NextRequest("http://localhost/api/analyze/job-2/answers", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "not json",
      }),
      { params: Promise.resolve({ id: "job-2" }) },
    );
    expect(response.status).toBe(400);
    expect((await response.json()).error).toMatchObject({
      code: "INVALID_REQUEST",
      message: "Request body must be JSON.",
    });
    expect(resumeWithAnswers).not.toHaveBeenCalled();
  });

  it("400s on an invalid status value", async () => {
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-3", stage: "awaiting_answers" } as never);
    const response = await post("job-3", { answers: [{ questionId: "q-1", status: "maybe" }] });
    expect(response.status).toBe(400);
  });

  it("starts resumeWithAnswers for a real job (isDemo: false) and reports the resulting status", async () => {
    const job = { id: "job-4", stage: "awaiting_answers", isDemo: false, pending: {} };
    vi.mocked(getAnalysis)
      .mockReturnValueOnce(job as never) // guard before the body is read
      .mockReturnValueOnce(job as never) // re-check after the body is read
      .mockReturnValueOnce({ id: "job-4", stage: "finalizing" } as never);
    vi.mocked(resumeWithAnswers).mockResolvedValue(undefined as never);

    const answers = [{ questionId: "q-1", status: "answered" as const, optionIndex: 0 }];
    const response = await post("job-4", { answers });

    expect(response.status).toBe(202);
    const json = await response.json();
    expect(json).toEqual({ status: "finalizing" });
    expect(resumeWithAnswers).toHaveBeenCalledWith("job-4", answers);
    expect(resumeDemoAnalysis).not.toHaveBeenCalled();
  });

  it("starts resumeDemoAnalysis for a demo job, keyed on the explicit isDemo flag (not on missing pending)", async () => {
    const demo = { id: "demo-1", stage: "awaiting_answers", isDemo: true };
    vi.mocked(getAnalysis)
      .mockReturnValueOnce(demo as never)
      .mockReturnValueOnce(demo as never)
      .mockReturnValueOnce({ id: "demo-1", stage: "complete" } as never);
    vi.mocked(resumeDemoAnalysis).mockResolvedValue(undefined as never);

    const response = await post("demo-1", {
      answers: [{ questionId: "q-1", status: "skipped" as const }],
    });

    expect(response.status).toBe(202);
    expect(resumeDemoAnalysis).toHaveBeenCalledWith("demo-1");
    expect(resumeWithAnswers).not.toHaveBeenCalled();
  });

  it("still calls resumeWithAnswers (not the demo path) for a real job missing pending -- a bug, not a demo", async () => {
    // isDemo: false with no `pending` should never be silently treated as a demo job:
    // it should go down the real path and let resumeWithAnswers's own guard reject it.
    const job = { id: "job-5", stage: "awaiting_answers", isDemo: false };
    vi.mocked(getAnalysis)
      .mockReturnValueOnce(job as never)
      .mockReturnValueOnce(job as never)
      .mockReturnValueOnce({ id: "job-5", stage: "awaiting_answers" } as never);
    vi.mocked(resumeWithAnswers).mockResolvedValue(undefined as never);

    await post("job-5", { answers: [{ questionId: "q-1", status: "skipped" as const }] });

    expect(resumeWithAnswers).toHaveBeenCalled();
    expect(resumeDemoAnalysis).not.toHaveBeenCalled();
  });

  it("409s a duplicate submission for the same id once the job has left awaiting_answers", async () => {
    const job = { id: "job-6", stage: "awaiting_answers", isDemo: false, pending: {} };
    vi.mocked(getAnalysis)
      .mockReturnValueOnce(job as never) // first POST's guard
      .mockReturnValueOnce(job as never) // first POST's post-body re-check
      .mockReturnValueOnce({ id: "job-6", stage: "finalizing" } as never) // first POST's status read
      .mockReturnValueOnce({ id: "job-6", stage: "finalizing" } as never); // second POST's guard
    vi.mocked(resumeWithAnswers).mockResolvedValue(undefined as never);

    const answers = [{ questionId: "q-1", status: "skipped" as const }];
    const first = await post("job-6", { answers });
    expect(first.status).toBe(202);

    const second = await post("job-6", { answers });
    expect(second.status).toBe(409);
    expect(resumeWithAnswers).toHaveBeenCalledTimes(1);
  });

  it("409s a job that left awaiting_answers while this request's body was being read", async () => {
    vi.mocked(getAnalysis)
      .mockReturnValueOnce({ id: "job-7", stage: "awaiting_answers", isDemo: false } as never) // guard
      .mockReturnValueOnce({ id: "job-7", stage: "complete", isDemo: false } as never); // re-check
    const response = await post("job-7", { answers: [{ questionId: "q-1", status: "skipped" }] });
    expect(response.status).toBe(409);
    expect((await response.json()).error.code).toBe("NOT_AWAITING_ANSWERS");
    expect(resumeWithAnswers).not.toHaveBeenCalled();
  });

  it("two overlapping POSTs: exactly one resumes (202), the other 409s instead of a silent 202", async () => {
    // One shared job object, like the real store. The fake resume moves it off
    // awaiting_answers synchronously, exactly as the real resumeWithAnswers does.
    const job = { id: "job-8", stage: "awaiting_answers", isDemo: false, pending: {} };
    vi.mocked(getAnalysis).mockImplementation(() => job as never);
    vi.mocked(resumeWithAnswers).mockImplementation(async () => {
      job.stage = "complete";
      return job as never;
    });

    // Both start before either body is read, so both pass the up-front guard.
    const [a, b] = await Promise.all([
      post("job-8", { answers: [{ questionId: "q-1", status: "answered", optionIndex: 0 }] }),
      post("job-8", { answers: [{ questionId: "q-1", status: "answered", optionIndex: 1 }] }),
    ]);

    expect([a.status, b.status].sort()).toEqual([202, 409]);
    expect(resumeWithAnswers).toHaveBeenCalledTimes(1);
  });

  it("400s more than 10 answers, and accepts exactly 10", async () => {
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-9", stage: "awaiting_answers", isDemo: false } as never);
    const answer = { questionId: "q-1", status: "skipped" as const };

    const tooMany = await post("job-9", { answers: Array.from({ length: 11 }, () => answer) });
    expect(tooMany.status).toBe(400);
    expect(resumeWithAnswers).not.toHaveBeenCalled();

    const atCap = await post("job-9", { answers: Array.from({ length: 10 }, () => answer) });
    expect(atCap.status).toBe(202);
    expect(resumeWithAnswers).toHaveBeenCalledTimes(1);
  });

  it("400s a questionId longer than 64 characters, and accepts exactly 64", async () => {
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-10", stage: "awaiting_answers", isDemo: false } as never);

    const long = await post("job-10", { answers: [{ questionId: "q".repeat(65), status: "skipped" }] });
    expect(long.status).toBe(400);
    expect(resumeWithAnswers).not.toHaveBeenCalled();

    const atCap = await post("job-10", { answers: [{ questionId: "q".repeat(64), status: "skipped" }] });
    expect(atCap.status).toBe(202);
  });
});
