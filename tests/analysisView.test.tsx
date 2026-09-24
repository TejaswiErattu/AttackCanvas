// @vitest-environment jsdom

/**
 * AnalysisView: what each hook state renders, and which recovery each error offers.
 *
 * useAnalysis is mocked so every phase can be set directly; the hook's own polling is
 * covered by tests/useAnalysisHook.test.tsx. Dashboard is stubbed (React Flow needs layout
 * APIs jsdom lacks); tests/dashboardComponents.test.tsx renders the real one.
 *
 * The error cases pin docs/frontend-integration.md: a request error and a failed analysis
 * are different things, a 404 offers Start over, and retry() is never offered for a
 * terminal failed analysis, because it only resumes polling the same id.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type {
  AnalysisPhase,
  AnalysisSnapshot,
  UseAnalysisResult,
} from "@/client/useAnalysis";
import type { AnalysisStage } from "@/shared/schema";
import type { AnalysisError, DashboardViewModel, QuestionData } from "@/shared/viewModel";

const useAnalysis = vi.fn<(id: string) => UseAnalysisResult>();
vi.mock("@/client/useAnalysis", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/client/useAnalysis")>()),
  useAnalysis: (id: string) => useAnalysis(id),
}));
vi.mock("@/components/Dashboard", () => ({
  default: ({ view }: { view: DashboardViewModel }) => (
    <div data-testid="dashboard">{view.repo.fullName}</div>
  ),
}));

const { default: AnalysisView } = await import("@/components/AnalysisView");

afterEach(() => {
  cleanup();
  useAnalysis.mockReset();
});

const QUESTIONS: QuestionData[] = [
  {
    id: "admin-panel-network-access",
    text: "Who can reach the admin panel over the network?",
    whyAsking: "Public exposure decides how likely the admin attacks are.",
    options: ["Only through a VPN or IP allowlist", "The public internet"],
    allowsUnsure: true,
    defaultAssumption: "The admin panel is reachable from the public internet.",
    index: 1,
    total: 1,
  },
];

function snapshot(stage: AnalysisStage, extra: Partial<AnalysisSnapshot> = {}): AnalysisSnapshot {
  return {
    stage,
    stageLabel: `label:${stage}`,
    stageIndex: 3,
    stageCount: 8,
    questions: [],
    view: null,
    basisCounts: null,
    hiddenSummary: null,
    error: null,
    ...extra,
  };
}

function hook(
  phase: AnalysisPhase,
  snap: AnalysisSnapshot | null,
  error: AnalysisError | null = null,
) {
  const result: UseAnalysisResult = {
    phase,
    snapshot: snap,
    error,
    submitAnswers: vi.fn(async () => true),
    retry: vi.fn(),
  };
  useAnalysis.mockReturnValue(result);
  return result;
}

const NOT_FOUND: AnalysisError = {
  code: "NOT_FOUND",
  title: "Analysis not found",
  message: "No analysis exists with that id, or it has expired.",
  canRetry: false,
};

const NETWORK: AnalysisError = {
  code: "NETWORK_ERROR",
  title: "Connection problem",
  message: "We couldn't reach the analysis service. Retrying...",
  canRetry: true,
};

describe("AnalysisView progress", () => {
  it("shows the server's stage label and step, and explains the stage", () => {
    hook("active", snapshot("scanning", { stageIndex: 3 }));
    render(<AnalysisView analysisId="job-1" />);

    expect(screen.getByText("label:scanning")).toBeTruthy();
    expect(screen.getByText("Step 3 of 8")).toBeTruthy();
    expect(screen.getAllByText(/Semgrep and OSV/).length).toBeGreaterThan(0);
    expect(screen.getByRole("progressbar").getAttribute("aria-valuenow")).toBe("38");
    expect(useAnalysis).toHaveBeenCalledWith("job-1");
  });

  it("offers no navigation that jumps between phases", () => {
    hook("active", snapshot("mapping_architecture"));
    render(<AnalysisView analysisId="job-1" />);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });
});

describe("AnalysisView questions", () => {
  it("renders the server's questions and submits through submitAnswers", () => {
    const result = hook("awaiting_answers", snapshot("awaiting_answers", { questions: QUESTIONS }));
    render(<AnalysisView analysisId="job-1" />);

    expect(screen.getByText(QUESTIONS[0].text)).toBeTruthy();
    expect(screen.getByText(/The admin panel is reachable from the public internet/)).toBeTruthy();

    fireEvent.click(screen.getByLabelText("The public internet"));
    fireEvent.click(screen.getByRole("button", { name: /submit answers/i }));

    expect(result.submitAnswers).toHaveBeenCalledWith([
      { questionId: "admin-panel-network-access", status: "answered", optionIndex: 1 },
    ]);
  });

  it("shows no question panel when the server asked none", () => {
    hook("active", snapshot("finalizing"));
    render(<AnalysisView analysisId="job-1" />);
    expect(screen.queryByText(/questions to sharpen/)).toBeNull();
  });
});

describe("AnalysisView errors", () => {
  it("offers Start over, not Try again, for an expired or unknown id", () => {
    hook("error", null, NOT_FOUND);
    render(<AnalysisView analysisId="gone" />);

    expect(screen.getByRole("alert").textContent).toContain("Analysis not found");
    expect(screen.getByRole("link", { name: "Start over" }).getAttribute("href")).toBe("/");
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
  });

  it("never offers retry for a failed analysis, even when its code is retryable", () => {
    const result = hook(
      "failed",
      snapshot("failed", {
        error: {
          code: "TIMEOUT",
          title: "The analysis took too long",
          message: "It ran past its time limit.",
          canRetry: true,
        },
      }),
    );
    render(<AnalysisView analysisId="job-1" />);

    expect(screen.getByRole("alert").textContent).toContain("The analysis took too long");
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
    expect(screen.getByRole("link", { name: "Start a new analysis" }).getAttribute("href")).toBe("/");
    expect(result.retry).not.toHaveBeenCalled();
  });

  it("shows a retryable request error as a banner over the last progress, with Try again", () => {
    const result = hook("error", snapshot("scanning"), NETWORK);
    render(<AnalysisView analysisId="job-1" />);

    expect(screen.getByText("label:scanning")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(result.retry).toHaveBeenCalledTimes(1);
  });

  it("offers Try again when the very first poll failed with a retryable error", () => {
    const result = hook("error", null, NETWORK);
    render(<AnalysisView analysisId="job-1" />);

    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(result.retry).toHaveBeenCalledTimes(1);
  });
});

describe("AnalysisView results", () => {
  it("renders the dashboard from the completed snapshot's view model", () => {
    hook(
      "complete",
      snapshot("complete", {
        view: { repo: { fullName: "acme/acme-notes" } } as unknown as DashboardViewModel,
      }),
    );
    render(<AnalysisView analysisId="job-1" />);

    expect(screen.getByTestId("dashboard").textContent).toBe("acme/acme-notes");
    expect(screen.getByRole("link", { name: "Analyze another repository" })).toBeTruthy();
  });
});
