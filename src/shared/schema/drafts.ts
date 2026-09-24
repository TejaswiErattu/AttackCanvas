import { z } from "zod";
import {
  ComponentSchema,
  DataFlowSchema,
  TrustBoundarySchema,
  UnknownSchema,
} from "./architecture";
import { DeveloperQuestionSchema } from "./question";
import { ThreatSchema } from "./threat";

/**
 * What a model is allowed to return. Every field computed in src/server/scoring or
 * src/server/questions is omitted rather than optional, so a model cannot supply a
 * severity, confidence or priority even if it tries (CLAUDE.md rule 2).
 *
 * Drafts are derived from the canonical schemas with .omit()/.extend() so they cannot
 * drift from them. Unknown keys are stripped, Zod's default: a stray invented field
 * should not consume the single retry allowed by CLAUDE.md rule 5.
 */

/** An evidence id, or a repository path when the model cites a file directly. */
const evidenceRefs = z.array(z.string().min(1));

export const DraftComponentSchema = ComponentSchema.omit({
  position: true,
}).extend({ evidenceRefs });
export type DraftComponent = z.infer<typeof DraftComponentSchema>;

export const DraftDataFlowSchema = DataFlowSchema.extend({ evidenceRefs });
export type DraftDataFlow = z.infer<typeof DraftDataFlowSchema>;

export const ArchitectureDraftSchema = z.object({
  components: z.array(DraftComponentSchema),
  dataFlows: z.array(DraftDataFlowSchema),
  trustBoundaries: z.array(TrustBoundarySchema),
  unknowns: z.array(UnknownSchema),
});
export type ArchitectureDraft = z.infer<typeof ArchitectureDraftSchema>;

export const DraftThreatSchema = ThreatSchema.omit({
  id: true,
  severity: true,
  confidence: true,
  confidenceLabel: true,
  basis: true,
  priority: true,
});
export type DraftThreat = z.infer<typeof DraftThreatSchema>;

export const CandidateQuestionSchema = DeveloperQuestionSchema.omit({
  id: true,
  valueScore: true,
  affectedThreatIds: true,
});
export type CandidateQuestion = z.infer<typeof CandidateQuestionSchema>;

/**
 * JSON Schema versions, for handing to the model as a tool/output contract.
 * Generated once at module load; these schemas hold no transforms or refinements.
 */
export const architectureDraftJsonSchema = z.toJSONSchema(ArchitectureDraftSchema);
export const draftThreatJsonSchema = z.toJSONSchema(DraftThreatSchema);
export const candidateQuestionJsonSchema = z.toJSONSchema(CandidateQuestionSchema);
