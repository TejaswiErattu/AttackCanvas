/**
 * Regression gate for the seeded bench (scripts/eval/bench.ts, eval/bench/report.md).
 *
 * Runs the detectors-only pass, three times from a fresh load, so the gate needs no local
 * Semgrep binary. Also fails, inside runBench, if any expected.yaml is malformed or any
 * SEEDED marker disagrees with its label. No model, network or MCP call.
 *
 * When a detector change moves these numbers on purpose, rerun `pnpm bench`, add the new
 * bench row to eval/bench/report.md, and update BASELINE in the same commit.
 */

import { describe, expect, it } from "vitest";
import { runBench } from "../scripts/eval/benchLib";

/** Measured 2026-09-25 at commit 67f52f4, detectors only: 15 TP, 1 FP, 0 FN, 3 skipped; 1 of 17 controls produced a gap. */
const BASELINE = {
  date: "2026-09-25",
  recall: 1,
  falseGapRate: 1 / 17,
} as const;

const RECALL_TOLERANCE = 0.05;

describe("seeded bench (detectors only)", () => {
  it("holds recall, the false-gap rate and determinism at the recorded baseline", async () => {
    const { run, deterministic, hashes } = await runBench();

    expect(hashes).toHaveLength(3);
    expect(deterministic, "the three runs produced different output").toBe(true);
    expect(run.total.recall, `recall fell more than ${RECALL_TOLERANCE} below the ${BASELINE.date} baseline`).toBeGreaterThanOrEqual(
      BASELINE.recall - RECALL_TOLERANCE,
    );
    expect(run.total.falseGapRate, `false-gap rate rose above the ${BASELINE.date} baseline`).toBeLessThanOrEqual(
      BASELINE.falseGapRate,
    );
  });
});
