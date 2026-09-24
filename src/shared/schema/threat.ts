import { z } from "zod";
import {
  BasisSchema,
  ConfidenceLabelSchema,
  Owasp2025Schema,
  PrioritySchema,
  SeveritySchema,
  StrideSchema,
  zCwe,
  zId,
} from "./enums";

export const MitigationSchema = z.object({
  summary: z.string().min(1),
  steps: z.array(z.string().min(1)),
  /** Where the fix belongs, e.g. "src/app/api/login/route.ts". */
  codeLocation: z.string().min(1).optional(),
});
export type Mitigation = z.infer<typeof MitigationSchema>;

/**
 * A scored threat. `severity`, `confidence`, `confidenceLabel`, `basis` and
 * `priority` are computed in src/server/scoring and are never set by a model
 * (CLAUDE.md rule 2) — see DraftThreatSchema for what a model may return.
 */
export const ThreatSchema = z.object({
  id: zId,
  title: z.string().min(1),
  stride: z.array(StrideSchema).min(1),
  owasp: z.array(Owasp2025Schema).min(1),
  cwe: z.array(zCwe),
  componentIds: z.array(zId),
  dataFlowIds: z.array(zId),
  asset: z.string().min(1),
  attackScenario: z.string().min(1),
  evidenceIds: z.array(zId),
  assumptions: z.array(z.string().min(1)),
  dependsOnUnknownIds: z.array(zId),
  impact: z.number().int().min(1).max(5),
  likelihood: z.number().int().min(1).max(5),
  impactReason: z.string().min(1),
  likelihoodReason: z.string().min(1),
  severity: SeveritySchema,
  confidence: z.number().min(0).max(1),
  confidenceLabel: ConfidenceLabelSchema,
  basis: BasisSchema,
  mitigation: MitigationSchema,
  priority: PrioritySchema,
});
export type Threat = z.infer<typeof ThreatSchema>;
