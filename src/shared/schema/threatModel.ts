import { z } from "zod";
import {
  ComponentSchema,
  DataFlowSchema,
  TrustBoundarySchema,
  UnknownSchema,
} from "./architecture";
import { AnalysisLevelSchema } from "./enums";
import { EvidenceSchema } from "./evidence";
import { DeveloperQuestionSchema } from "./question";
import { RepoSummarySchema } from "./repo";
import { ThreatSchema } from "./threat";

const ThreatModelShape = z.object({
  schemaVersion: z.literal("1.0"),
  /** Echoed from the user's AnalysisRequest; never chosen by a model. */
  analysisLevel: AnalysisLevelSchema,
  repo: RepoSummarySchema,
  components: z.array(ComponentSchema),
  dataFlows: z.array(DataFlowSchema),
  trustBoundaries: z.array(TrustBoundarySchema),
  unknowns: z.array(UnknownSchema),
  evidence: z.array(EvidenceSchema),
  threats: z.array(ThreatSchema),
  questions: z.array(DeveloperQuestionSchema),
  assumptions: z.array(z.string().min(1)),
  limitations: z.array(z.string().min(1)),
});

/** Reports every id that appears more than once in a collection. */
function addDuplicateIdIssues(
  ctx: z.RefinementCtx,
  items: readonly { id: string }[],
  collection: string,
): void {
  const seen = new Set<string>();
  items.forEach((item, index) => {
    if (seen.has(item.id)) {
      ctx.addIssue({
        code: "custom",
        path: [collection, index, "id"],
        message: `duplicate id "${item.id}" in ${collection}`,
      });
    }
    seen.add(item.id);
  });
}

/**
 * The full analysis result. Beyond per-field validation this enforces that every
 * cross-reference resolves, so the dashboard can index by id without guarding.
 */
export const ThreatModelSchema = ThreatModelShape.superRefine((model, ctx) => {
  const componentIds = new Set(model.components.map((c) => c.id));
  const dataFlowIds = new Set(model.dataFlows.map((f) => f.id));
  const evidenceIds = new Set(model.evidence.map((e) => e.id));
  const threatIds = new Set(model.threats.map((t) => t.id));

  // 1. Every flow connects two components that exist.
  model.dataFlows.forEach((flow, index) => {
    (["sourceId", "targetId"] as const).forEach((key) => {
      if (!componentIds.has(flow[key])) {
        ctx.addIssue({
          code: "custom",
          path: ["dataFlows", index, key],
          message: `${key} "${flow[key]}" does not match any component id`,
        });
      }
    });
  });

  model.threats.forEach((threat, index) => {
    // 2. Every threat reference resolves.
    const references = [
      { key: "componentIds", ids: threat.componentIds, known: componentIds, label: "component" },
      { key: "dataFlowIds", ids: threat.dataFlowIds, known: dataFlowIds, label: "data flow" },
      { key: "evidenceIds", ids: threat.evidenceIds, known: evidenceIds, label: "evidence" },
    ] as const;

    references.forEach(({ key, ids, known, label }) => {
      ids.forEach((id, idIndex) => {
        if (!known.has(id)) {
          ctx.addIssue({
            code: "custom",
            path: ["threats", index, key, idIndex],
            message: `"${id}" does not match any ${label} id`,
          });
        }
      });
    });

    // 3. A threat must rest on evidence or on a stated assumption.
    if (threat.evidenceIds.length === 0 && threat.assumptions.length === 0) {
      ctx.addIssue({
        code: "custom",
        path: ["threats", index, "evidenceIds"],
        message: "threat needs at least one evidenceId or one assumption",
      });
    }
  });

  // 4. Every question points at threats that exist.
  model.questions.forEach((question, index) => {
    question.affectedThreatIds.forEach((id, idIndex) => {
      if (!threatIds.has(id)) {
        ctx.addIssue({
          code: "custom",
          path: ["questions", index, "affectedThreatIds", idIndex],
          message: `"${id}" does not match any threat id`,
        });
      }
    });
  });

  // 5. Ids are unique, so lookups by id are unambiguous.
  addDuplicateIdIssues(ctx, model.components, "components");
  addDuplicateIdIssues(ctx, model.dataFlows, "dataFlows");
  addDuplicateIdIssues(ctx, model.trustBoundaries, "trustBoundaries");
  addDuplicateIdIssues(ctx, model.unknowns, "unknowns");
  addDuplicateIdIssues(ctx, model.evidence, "evidence");
  addDuplicateIdIssues(ctx, model.threats, "threats");
  addDuplicateIdIssues(ctx, model.questions, "questions");
});

export type ThreatModel = z.infer<typeof ThreatModelSchema>;

export type ValidationIssue = {
  /** Dotted path to the offending field, e.g. "threats.0.evidenceIds.1". */
  path: string;
  message: string;
};

export type ValidationResult =
  | { ok: true; data: ThreatModel }
  | { ok: false; issues: ValidationIssue[] };

/** Validates an untrusted ThreatModel. Never throws. */
export function validateThreatModel(input: unknown): ValidationResult {
  const result = ThreatModelSchema.safeParse(input);
  if (result.success) {
    return { ok: true, data: result.data };
  }
  return {
    ok: false,
    issues: result.error.issues.map((issue) => ({
      path: issue.path.join("."),
      message: issue.message,
    })),
  };
}
