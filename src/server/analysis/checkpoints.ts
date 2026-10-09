/**
 * Stage checkpoints: the pipeline's free stages saved to disk so the paid ones can be
 * re-run from them (scripts/replay-stage.ts).
 *
 * When ATTACKCANVAS_CHECKPOINT_DIR is set and NODE_ENV is not "production", runAnalysis
 * writes <dir>/<owner>__<repo>/<stage>.json after load, after detect, after the scanners
 * and after the architecture merge. The scanners checkpoint holds everything the
 * architecture and threat stages read, so they can be replayed without GitHub, Docker or
 * Semgrep; the architecture checkpoint holds what the threat stage alone reads, so
 * scripts/eval/mini.ts can re-render STRIDE batches without the architecture call.
 *
 * These files hold RAW repository content (the detectors need it unredacted), so keep the
 * directory local and gitignored (.cache/ is). Nothing read back from one skips the
 * redaction and secret checks on the model path: those run downstream as usual. A failed
 * write never fails an analysis.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Evidence, RepoSummary } from "@/shared/schema";
import type { LoadedFile, LoadedRepo } from "@/server/ingest/loader";
import type { DetectorResult } from "@/server/detect/types";
import type { MergedArchitecture } from "@/server/analysis/architecture";

export const CHECKPOINT_DIR_ENV = "ATTACKCANVAS_CHECKPOINT_DIR";

export const CHECKPOINT_STAGES = ["load", "detect", "scanners", "architecture"] as const;
export type CheckpointStage = (typeof CHECKPOINT_STAGES)[number];

export type LoadCheckpoint = { owner: string; repo: string; ref?: string; loaded: LoadedRepo };
export type DetectCheckpoint = { owner: string; repo: string; detector: DetectorResult };

/** Everything the architecture and threat stages read, after detect and the scanners. */
export type ScannersCheckpoint = {
  owner: string;
  repo: string;
  /** The loader's summary with detected framework names filled in. */
  summary: RepoSummary;
  /** Detector result including injection evidence. */
  detector: DetectorResult;
  semgrep: Evidence[];
  osv: Evidence[];
  osvLimitations: string[];
  /** Every loaded file, raw: the threat stage and the output checks read them all. */
  files: LoadedFile[];
  droppedStages: string[];
};

/** MergedArchitecture with its Maps as entry lists, so it survives JSON. */
export type SerializedArchitecture = Omit<
  MergedArchitecture,
  "gapBindings" | "componentEvidence" | "flowEvidence"
> & {
  gapBindings: [string, string[]][];
  componentEvidence: [string, string[]][];
  flowEvidence: [string, string[]][];
};

/** What the threat stage reads from the architecture stage (scripts/eval/mini.ts replays it). */
export type ArchitectureCheckpoint = {
  owner: string;
  repo: string;
  architecture: SerializedArchitecture;
};

export function serializeArchitecture(architecture: MergedArchitecture): SerializedArchitecture {
  return {
    ...architecture,
    gapBindings: [...architecture.gapBindings],
    componentEvidence: [...architecture.componentEvidence],
    flowEvidence: [...architecture.flowEvidence],
  };
}

export function deserializeArchitecture(saved: SerializedArchitecture): MergedArchitecture {
  return {
    ...saved,
    gapBindings: new Map(saved.gapBindings),
    componentEvidence: new Map(saved.componentEvidence),
    flowEvidence: new Map(saved.flowEvidence),
  };
}

type Payload = {
  load: LoadCheckpoint;
  detect: DetectCheckpoint;
  scanners: ScannersCheckpoint;
  architecture: ArchitectureCheckpoint;
};

/** The checkpoint directory, or undefined when checkpoints are off (unset or production). */
export function checkpointDir(
  env: Record<string, string | undefined> = process.env,
): string | undefined {
  const dir = env[CHECKPOINT_DIR_ENV]?.trim();
  if (!dir || env.NODE_ENV === "production") return undefined;
  return dir;
}

const SAFE_NAME = /^[A-Za-z0-9._-]{1,100}$/;

/** <dir>/<owner>__<repo>/<stage>.json; throws on a name that could leave `dir`. */
export function checkpointPath(dir: string, owner: string, repo: string, stage: CheckpointStage): string {
  if (!SAFE_NAME.test(owner) || !SAFE_NAME.test(repo) || owner.startsWith(".")) {
    throw new Error("checkpoint: owner or repo is not a safe file name");
  }
  return join(dir, `${owner}__${repo}`, `${stage}.json`);
}

/** Writes one checkpoint when `dir` is set. Never throws. */
export function writeCheckpoint<S extends CheckpointStage>(
  dir: string | undefined,
  stage: S,
  data: Payload[S],
): void {
  if (!dir) return;
  try {
    const path = checkpointPath(dir, data.owner, data.repo, stage);
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, JSON.stringify({ version: 1, stage, data }), "utf8");
  } catch {
    // A checkpoint is a convenience; losing one must not fail the analysis.
  }
}

/** Reads one checkpoint. Throws with a plain message when it is missing or malformed. */
export function readCheckpoint<S extends CheckpointStage>(
  dir: string,
  owner: string,
  repo: string,
  stage: S,
): Payload[S] {
  const path = checkpointPath(dir, owner, repo, stage);
  let parsed: { version?: unknown; stage?: unknown; data?: unknown };
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`no readable ${stage} checkpoint at ${path}`);
  }
  if (parsed?.version !== 1 || parsed.stage !== stage || typeof parsed.data !== "object" || !parsed.data) {
    throw new Error(`${path} is not a version 1 ${stage} checkpoint`);
  }
  return parsed.data as Payload[S];
}
