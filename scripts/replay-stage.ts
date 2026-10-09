/**
 * Re-runs only the architecture and threat stages from a saved checkpoint
 * (src/server/analysis/checkpoints.ts), so a prompt change can be tried without loading
 * the repository or running the scanners again.
 *
 *   ATTACKCANVAS_CHECKPOINT_DIR=.cache/checkpoints \
 *     pnpm try scripts/replay-stage.ts <owner>/<repo> --from scanners [--level 0-4]
 *
 * PAID unless every call hits the model cache: set ATTACKCANVAS_MODEL_CACHE=1 to serve
 * repeated calls from .cache/model/ (src/server/ai/modelCache.ts). Needs
 * ANTHROPIC_API_KEY on a cache miss; never GitHub, Docker or Semgrep.
 */

import { randomUUID } from "node:crypto";
import { architectureAndThreats, countByBasis } from "@/server/analysis/pipeline";
import { CHECKPOINT_DIR_ENV, checkpointDir, readCheckpoint } from "@/server/analysis/checkpoints";
import { inferArchitecture } from "@/server/analysis/architecture";
import { generateThreats } from "@/server/analysis/threats";
import { AiError } from "@/server/ai/claude";
import { usageLedger } from "@/server/ai/usage";
import { parseReplayArgs } from "./replay-stage-lib";
import { formatUsageLines } from "./try-threats-lib";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

async function main(): Promise<number> {
  let args;
  try {
    args = parseReplayArgs(process.argv.slice(2));
  } catch (error) {
    console.error((error as Error).message);
    return 1;
  }
  const dir = checkpointDir();
  if (!dir) {
    console.error(`${CHECKPOINT_DIR_ENV} must be set (and NODE_ENV not production).`);
    return 1;
  }

  let scanned;
  try {
    scanned = readCheckpoint(dir, args.owner, args.repo, "scanners");
  } catch (error) {
    console.error((error as Error).message);
    return 1;
  }

  const analysisId = `replay-${randomUUID()}`;
  console.log(`replaying ${args.owner}/${args.repo} from ${args.from} at level ${args.level}`);
  try {
    const { architecture, model } = await architectureAndThreats({
      scanned,
      analysisLevel: args.level,
      analysisId,
      deps: { inferArchitecture, generateThreats },
      onStage: (stage) => console.log(`stage: ${stage}`),
    });
    const basis = countByBasis(model.threats);
    console.log(
      `components ${architecture.components.length}, flows ${architecture.dataFlows.length}, ` +
        `threats ${model.threats.length} (evidence_backed ${basis.evidence_backed}, ` +
        `assumption_dependent ${basis.assumption_dependent})`,
    );
    return 0;
  } catch (error) {
    console.error(error instanceof AiError ? `failed: ${error.code} ${error.message}` : `failed: ${(error as Error).name}`);
    return 1;
  } finally {
    for (const line of formatUsageLines(usageLedger.forAnalysis(analysisId))) console.log(line);
  }
}

main().then((code) => process.exit(code));
