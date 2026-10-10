/**
 * src/server/analysis/checkpoints.ts and scripts/replay-stage-lib.ts. The end-to-end
 * write-then-replay check lives in tests/pipeline.test.ts ("stage checkpoints").
 */

import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CHECKPOINT_DIR_ENV,
  checkpointDir,
  checkpointPath,
  readCheckpoint,
  writeCheckpoint,
} from "@/server/analysis/checkpoints";
import type { DetectorResult } from "@/server/detect/types";
import { parseReplayArgs } from "../scripts/replay-stage-lib";

const DETECTOR = { frameworks: [], routes: [], gaps: [] } as unknown as DetectorResult;

describe("checkpoints", () => {
  it("is off when unset or in production", () => {
    expect(checkpointDir({ NODE_ENV: "development" })).toBeUndefined();
    expect(checkpointDir({ NODE_ENV: "production", [CHECKPOINT_DIR_ENV]: "d" })).toBeUndefined();
    expect(checkpointDir({ NODE_ENV: "development", [CHECKPOINT_DIR_ENV]: "d" })).toBe("d");
    // scripts/eval/run.ts and pnpm try leave NODE_ENV unset: checkpoints stay on.
    expect(checkpointDir({ [CHECKPOINT_DIR_ENV]: ".cache/checkpoints" })).toBe(".cache/checkpoints");
  });

  it("round-trips a checkpoint under <owner>__<repo>/<stage>.json", () => {
    const dir = mkdtempSync(join(tmpdir(), "cp-"));
    writeCheckpoint(dir, "detect", { owner: "acme", repo: "app", detector: DETECTOR });
    expect(readCheckpoint(dir, "acme", "app", "detect")).toEqual({
      owner: "acme",
      repo: "app",
      detector: DETECTOR,
    });
  });

  it("does nothing without a directory and never throws on a bad name", () => {
    expect(() => writeCheckpoint(undefined, "detect", { owner: "a", repo: "b", detector: DETECTOR })).not.toThrow();
    expect(() => writeCheckpoint("x", "detect", { owner: "../a", repo: "b", detector: DETECTOR })).not.toThrow();
    expect(() => checkpointPath("x", "../a", "b", "load")).toThrow();
  });

  it("refuses a missing or mismatched checkpoint with a plain message", () => {
    const dir = mkdtempSync(join(tmpdir(), "cp-"));
    expect(() => readCheckpoint(dir, "acme", "app", "scanners")).toThrow(/no readable scanners checkpoint/);
    mkdirSync(join(dir, "acme__app"));
    writeFileSync(join(dir, "acme__app", "scanners.json"), JSON.stringify({ version: 1, stage: "load", data: {} }));
    expect(() => readCheckpoint(dir, "acme", "app", "scanners")).toThrow(/not a version 1 scanners/);
  });
});

describe("parseReplayArgs", () => {
  it("reads owner/repo, --from and --level", () => {
    expect(parseReplayArgs(["OWASP/NodeGoat", "--from", "scanners"])).toEqual({
      owner: "OWASP",
      repo: "NodeGoat",
      from: "scanners",
      level: 2,
    });
    expect(parseReplayArgs(["--from", "scanners", "https://github.com/a/b", "--level", "0"]).level).toBe(0);
  });

  it("rejects a missing target, an unknown or unsupported stage, and a bad level", () => {
    expect(() => parseReplayArgs(["--from", "scanners"])).toThrow(/usage/);
    expect(() => parseReplayArgs(["a/b", "--from", "nope"])).toThrow(/must be one of/);
    expect(() => parseReplayArgs(["a/b", "--from", "load"])).toThrow(/not supported/);
    expect(() => parseReplayArgs(["a/b", "--from", "scanners", "--level", "9"])).toThrow(/--level/);
  });
});
