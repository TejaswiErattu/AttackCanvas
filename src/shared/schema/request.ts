import { z } from "zod";
import { AnalysisLevelSchema } from "./enums";

/**
 * What the user submits to start an analysis. Both fields are user-supplied:
 * `analysisLevel` is chosen in the UI and is never selected or modified by a model.
 *
 * `repoUrl` is only shape-checked here. Ownership, visibility and size are settled in
 * src/server/ingest, which returns INVALID_URL / REPO_NOT_FOUND / REPO_TOO_LARGE.
 */
export const AnalysisRequestSchema = z.object({
  repoUrl: z.url(),
  analysisLevel: AnalysisLevelSchema,
});
export type AnalysisRequest = z.infer<typeof AnalysisRequestSchema>;
