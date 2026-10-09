/**
 * The pure part of scripts/replay-stage.ts: argument parsing, kept apart so tests can
 * import it without starting a run.
 */

import { CHECKPOINT_STAGES, type CheckpointStage } from "@/server/analysis/checkpoints";
import { parseTarget } from "./try-pipeline-lib";

/** The stages replay-stage.ts can resume from. Only the last free stage, for now. */
export const REPLAYABLE_FROM: readonly CheckpointStage[] = ["scanners"];

export type ReplayArgs = { owner: string; repo: string; from: CheckpointStage; level: 0 | 1 | 2 | 3 | 4 };

/** `<owner>/<repo> --from scanners [--level 0-4]`. Throws a printable message. */
export function parseReplayArgs(argv: readonly string[]): ReplayArgs {
  const positional: string[] = [];
  let from: string | undefined;
  let level = 2;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--from") from = argv[++i];
    else if (arg === "--level") level = Number(argv[++i]);
    else positional.push(arg);
  }
  if (positional.length !== 1) throw new Error("usage: replay-stage.ts <owner>/<repo> --from scanners [--level 0-4]");
  if (!from || !(CHECKPOINT_STAGES as readonly string[]).includes(from)) {
    throw new Error(`--from must be one of: ${CHECKPOINT_STAGES.join(", ")}`);
  }
  if (!REPLAYABLE_FROM.includes(from as CheckpointStage)) {
    throw new Error(`--from ${from} is not supported yet; use --from scanners`);
  }
  if (![0, 1, 2, 3, 4].includes(level)) throw new Error("--level must be 0, 1, 2, 3 or 4");
  const { owner, repo } = parseTarget(positional[0]);
  return { owner, repo, from: from as CheckpointStage, level: level as ReplayArgs["level"] };
}
