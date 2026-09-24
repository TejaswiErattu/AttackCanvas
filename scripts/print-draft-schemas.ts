/**
 * Prints the JSON Schemas handed to the model, so you can eyeball that no computed
 * field (id, severity, confidence, confidenceLabel, basis, priority) leaked in.
 *
 *   pnpm try scripts/print-draft-schemas.ts
 */
import {
  architectureDraftJsonSchema,
  candidateQuestionJsonSchema,
  draftThreatJsonSchema,
} from "../src/shared/schema";

const schemas = {
  ArchitectureDraft: architectureDraftJsonSchema,
  DraftThreat: draftThreatJsonSchema,
  CandidateQuestion: candidateQuestionJsonSchema,
};

for (const [name, schema] of Object.entries(schemas)) {
  console.log(`\n===== ${name} =====`);
  console.log(JSON.stringify(schema, null, 2));
}
