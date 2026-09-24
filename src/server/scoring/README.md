# server/scoring

Computes risk, severity, confidence and fix priority. Never done by a model.

`index.ts` exports pure functions: `severityOf`, `confidenceOf` (value plus UI breakdown),
`confidenceLabelOf`, `basisOf`, `priorityOf`, `isHidden` and `scoreThreat`. The gap map is
keyed by gap **evidence id** (`ev-gap-3`), see `gapEvidenceId` in `analysis/context.ts`.
Confidence is computed in integer thousandths, so 0.40 and 0.70 are exact.

Inference evidence is a conclusion, not direct supporting evidence (CLAUDE.md rule 2). It never
makes a threat `evidence_backed`, is never a second independent source, and neither blocks nor
counts toward the gap floor; it scores only as "inference only" when nothing else contributes.

`confidenceOf`, `isGapEvidence`, `GAP_FLOOR` and `explainConfidence` live in
`src/shared/confidence.ts` (pure, no server imports) and are re-exported from here, so the
dashboard adapter explains a confidence figure with the code that computed it.
`explainConfidence` returns the exact breakdown when the model alone reproduces the stored
confidence, and qualitative lines (`exact: false`) for gap-backed threats, whose points depend
on a detector certainty the ThreatModel does not carry.
