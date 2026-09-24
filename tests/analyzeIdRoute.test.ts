/**
 * GET /api/analyze/[id]. src/server/analysis/pipeline.ts's store is mocked so the route
 * is exercised against controlled AnalysisState shapes; toDashboardViewModel and friends
 * run for real (they are already covered by tests/adapter.test.ts) against the known-good
 * fixtures/empty-analysis.json model.
 */

import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { validateThreatModel, type ThreatModel } from "@/shared/schema";
import emptyAnalysisJson from "../fixtures/empty-analysis.json";

vi.mock("@/server/analysis/pipeline", async () => {
  const actual = await vi.importActual<typeof import("@/server/analysis/pipeline")>(
    "@/server/analysis/pipeline",
  );
  return { ...actual, getAnalysis: vi.fn() };
});

import { GET } from "@/app/api/analyze/[id]/route";
import { getAnalysis } from "@/server/analysis/pipeline";

const EMPTY_MODEL: ThreatModel = (() => {
  const result = validateThreatModel(emptyAnalysisJson);
  if (!result.ok) throw new Error("fixture invalid");
  return result.data;
})();

function get(id: string) {
  return GET(new NextRequest(`http://localhost/api/analyze/${id}`), {
    params: Promise.resolve({ id }),
  });
}

beforeEach(() => {
  vi.mocked(getAnalysis).mockReset();
});

describe("GET /api/analyze/[id]", () => {
  it("404s for an unknown id", async () => {
    vi.mocked(getAnalysis).mockReturnValue(undefined);
    const response = await get("does-not-exist");
    expect(response.status).toBe(404);
    const json = await response.json();
    expect(json.error.code).toBe("NOT_FOUND");
  });

  it("reports stage and status fields for a job still in progress, with no questions or threatModel", async () => {
    vi.mocked(getAnalysis).mockReturnValue({
      id: "job-1",
      stage: "scanning",
      cost: { calls: 0, totalUsd: 0 },
    } as never);

    const response = await get("job-1");
    expect(response.status).toBe(200);
    const json = await response.json();
    expect(json.stage).toBe("scanning");
    expect(json.stageLabel).toBe("Scanning code, dependencies and missing controls");
    expect(json.questions).toBeUndefined();
    expect(json.threatModel).toBeUndefined();
    expect(json.error).toBeUndefined();
  });

  it("includes questions while awaiting_answers", async () => {
    vi.mocked(getAnalysis).mockReturnValue({
      id: "job-2",
      stage: "awaiting_answers",
      questions: [
        {
          id: "q-1",
          text: "Is this reachable?",
          whyAsking: "It changes severity.",
          options: ["Yes", "No"],
          allowsUnsure: true,
          affectedThreatIds: [],
          unknownId: "unk-1",
          defaultAssumption: "Assume yes.",
          valueScore: 0.5,
        },
      ],
    } as never);

    const response = await get("job-2");
    const json = await response.json();
    expect(json.stage).toBe("awaiting_answers");
    expect(json.questions).toHaveLength(1);
    expect(json.questions[0]).toMatchObject({ id: "q-1", index: 1, total: 1 });
  });

  it("includes the adapted dashboard and basis counts once a threatModel is present", async () => {
    vi.mocked(getAnalysis).mockReturnValue({
      id: "job-3",
      stage: "complete",
      threatModel: EMPTY_MODEL,
    } as never);

    const response = await get("job-3");
    const json = await response.json();
    expect(json.stage).toBe("complete");
    expect(json.threatModel.repo.fullName).toBe("acme/hello-static");
    expect(json.threatModel.threats).toEqual([]);
    expect(json.basisCounts).toEqual({ evidence_backed: 0, assumption_dependent: 0 });
    expect(json.hiddenSummary).toEqual({ scored: 0, hidden: 0, topReason: null, topReasonCount: 0 });
  });

  it("reports a safe error, never the raw upstream message, for a failed job", async () => {
    vi.mocked(getAnalysis).mockReturnValue({
      id: "job-4",
      stage: "failed",
      error: { code: "REPO_NOT_FOUND", message: "We couldn't find that repository. Check the URL and make sure the repository is public." },
    } as never);

    const response = await get("job-4");
    const json = await response.json();
    expect(json.stage).toBe("failed");
    expect(json.error.code).toBe("REPO_NOT_FOUND");
    expect(json.error.canRetry).toBe(false); // REPO_NOT_FOUND is not in RETRYABLE_ERRORS
  });
});
