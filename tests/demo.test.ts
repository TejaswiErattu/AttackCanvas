/**
 * src/server/analysis/demo.ts. Uses the real pipeline store (createAnalysis/getAnalysis)
 * since both functions' whole contract is mutating that exact stored reference.
 */

import { describe, expect, it, beforeEach } from "vitest";
import { createAnalysis, getAnalysis, resetStore } from "@/server/analysis/pipeline";
import {
  DEMO_RESUME_STAGES,
  DEMO_STAGES_BEFORE_QUESTIONS,
  DEMO_STAGES_NO_QUESTIONS,
  resumeDemoAnalysis,
  seedDemoAnalysis,
} from "@/server/analysis/demo";

// Same stages, no delay: proves the sequencing and outcome without the several seconds of
// real delay the exported schedules use to look alive during an actual demo.
const fast = (stages: typeof DEMO_STAGES_BEFORE_QUESTIONS) =>
  stages.map((s) => ({ ...s, delayMs: 0 }));

beforeEach(() => {
  resetStore();
});

describe("seedDemoAnalysis", () => {
  it("pauses at awaiting_answers, since demo-analysis.json carries developer questions", async () => {
    const state = createAnalysis("acme/golden");
    await seedDemoAnalysis(
      state.id,
      fast(DEMO_STAGES_BEFORE_QUESTIONS),
      fast(DEMO_STAGES_NO_QUESTIONS),
    );

    const result = getAnalysis(state.id);
    expect(result?.stage).toBe("awaiting_answers");
    expect(result?.questions?.length).toBe(2);
    expect(result?.threatModel).toBeDefined();
    expect(result?.pending).toBeUndefined(); // the demo has no real resume sidecar
  });

  it("is a no-op for an id that does not exist", async () => {
    await expect(
      seedDemoAnalysis("does-not-exist", fast(DEMO_STAGES_BEFORE_QUESTIONS)),
    ).resolves.toBeUndefined();
  });
});

describe("resumeDemoAnalysis", () => {
  it("finishes a paused demo job with the same fixture, ignoring the submitted answers' content", async () => {
    const state = createAnalysis("acme/golden");
    await seedDemoAnalysis(
      state.id,
      fast(DEMO_STAGES_BEFORE_QUESTIONS),
      fast(DEMO_STAGES_NO_QUESTIONS),
    );
    const beforeThreats = getAnalysis(state.id)?.threatModel?.threats;

    await resumeDemoAnalysis(state.id, fast(DEMO_RESUME_STAGES));

    const result = getAnalysis(state.id);
    expect(result?.stage).toBe("complete");
    expect(result?.questions).toBeUndefined();
    expect(result?.threatModel?.threats).toEqual(beforeThreats);
  });

  it("is a no-op when the job is not awaiting_answers", async () => {
    const state = createAnalysis("acme/golden"); // still "queued"
    await resumeDemoAnalysis(state.id, fast(DEMO_RESUME_STAGES));
    expect(getAnalysis(state.id)?.stage).toBe("queued");
  });

  it("is a no-op on a REAL (isDemo: false) job even if it happens to be awaiting_answers", async () => {
    const state = createAnalysis("acme/canary"); // isDemo defaults to false
    state.stage = "awaiting_answers"; // simulate a real job paused for real answers
    state.questions = [{ id: "q-1" } as never];

    await resumeDemoAnalysis(state.id, fast(DEMO_RESUME_STAGES));

    const result = getAnalysis(state.id);
    expect(result?.stage).toBe("awaiting_answers"); // untouched
    expect(result?.questions).toEqual([{ id: "q-1" }]); // untouched
  });
});
