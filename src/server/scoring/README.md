# server/scoring

Computes risk, severity, confidence and fix priority. Never done by a model.

`index.ts` exports pure functions: `severityOf`, `confidenceOf` (value plus UI breakdown),
`confidenceLabelOf`, `basisOf`, `priorityOf`, `isHidden` and `scoreThreat`. The gap map is
keyed by gap **evidence id** (`ev-gap-3`), see `gapEvidenceId` in `analysis/context.ts`.
Confidence is computed in integer thousandths, so 0.40 and 0.70 are exact.

Inference evidence is a conclusion, not direct supporting evidence (CLAUDE.md rule 2). It never
makes a threat `evidence_backed`, is never a second independent source, and neither blocks nor
counts toward the gap floor; it scores only as "inference only" when nothing else contributes.

The gap floor is scoped by CWE: it lifts a gap-only threat to 0.40 only when every CWE the
threat claims is one its cited gaps assert (`ControlGap.cwe`), so a real missing control does
not vouch for clickjacking or XSS built on top of it. A threat with no CWE gets no floor.
`confidenceOf` takes the threat's CWE list as its fourth argument for this check.

`confidenceOf`, `isGapEvidence`, `GAP_FLOOR` and `explainConfidence` live in
`src/shared/confidence.ts` (pure, no server imports) and are re-exported from here, so the
dashboard adapter explains a confidence figure with the code that computed it.
`explainConfidence` returns the exact breakdown when the model alone reproduces the stored
confidence, and qualitative lines (`exact: false`) for gap-backed threats, whose points depend
on a detector certainty the ThreatModel does not carry.
