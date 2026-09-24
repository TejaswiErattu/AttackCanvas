import { z } from "zod";

export const RepoSummarySchema = z.object({
  owner: z.string().min(1),
  name: z.string().min(1),
  /** Branch, tag or commit SHA the analysis ran against. */
  ref: z.string().min(1),
  languages: z.array(z.string().min(1)),
  frameworks: z.array(z.string().min(1)),
  fileCountAnalyzed: z.number().int().min(0),
  analyzedAt: z.iso.datetime(),
});
export type RepoSummary = z.infer<typeof RepoSummarySchema>;
