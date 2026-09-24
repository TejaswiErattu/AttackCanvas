import { z } from "zod";
import { zId } from "./enums";

/**
 * A question put to the developer to resolve an Unknown. At most 3 are asked.
 * `valueScore` and `affectedThreatIds` are computed in src/server/questions.
 */
export const DeveloperQuestionSchema = z.object({
  id: zId,
  text: z.string().min(1),
  whyAsking: z.string().min(1),
  options: z.array(z.string().min(1)).min(2).max(4),
  allowsUnsure: z.boolean(),
  affectedThreatIds: z.array(zId),
  unknownId: zId,
  /** Applied when the developer skips or answers "unsure". */
  defaultAssumption: z.string().min(1),
  /** How much answering would sharpen the model, 0..1. */
  valueScore: z.number().min(0).max(1),
});
export type DeveloperQuestion = z.infer<typeof DeveloperQuestionSchema>;
