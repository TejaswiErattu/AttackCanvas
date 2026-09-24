import { z } from "zod";
import { ComponentTypeSchema, DataClassificationSchema, zId } from "./enums";

export const PositionSchema = z.object({
  x: z.number(),
  y: z.number(),
});
export type Position = z.infer<typeof PositionSchema>;

export const ComponentSchema = z.object({
  id: zId,
  name: z.string().min(1),
  type: ComponentTypeSchema,
  description: z.string().min(1),
  technologies: z.array(z.string().min(1)),
  /** Repository paths this component was inferred from. */
  files: z.array(z.string().min(1)),
  /** What is worth protecting here, e.g. "user credentials". */
  assets: z.array(z.string().min(1)),
  /** Set by the dashboard layout (dagre); absent until laid out. */
  position: PositionSchema.optional(),
});
export type Component = z.infer<typeof ComponentSchema>;

export const DataFlowSchema = z.object({
  id: zId,
  sourceId: zId,
  targetId: zId,
  label: z.string().min(1),
  protocol: z.string().min(1).optional(),
  dataClassification: DataClassificationSchema,
  crossesTrustBoundary: z.boolean(),
  boundaryId: zId.optional(),
});
export type DataFlow = z.infer<typeof DataFlowSchema>;

export const TrustBoundarySchema = z.object({
  id: zId,
  name: z.string().min(1),
  componentIds: z.array(zId),
  description: z.string().min(1),
});
export type TrustBoundary = z.infer<typeof TrustBoundarySchema>;

/**
 * Something the analysis could not determine from code alone. Drives the
 * developer questions and lowers confidence until answered.
 */
export const UnknownSchema = z.object({
  id: zId,
  description: z.string().min(1),
  affectsComponentIds: z.array(zId),
});
export type Unknown = z.infer<typeof UnknownSchema>;
