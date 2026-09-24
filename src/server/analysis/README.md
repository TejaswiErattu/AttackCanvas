# server/analysis

Builds the architecture model and STRIDE threats mapped to OWASP Top 10:2025 and CWE.

| File         | What it holds                                                                                             |
| ------------ | --------------------------------------------------------------------------------------------------------- |
| `context.ts` | `RepoFacts`, `buildRepoFacts`, `buildContext` (gap-aware, budgeted model context) and `writeDebugContext` |
| `architecture.ts` | `inferArchitecture` (N1) sends the built context to the model and validates an `ArchitectureDraft`; `mergeArchitecture` (N2) checks that draft against the facts |
| `pipeline.ts` | Prompt V: the orchestrator. `createAnalysis`/`getAnalysis` hold an in-memory, 1-hour-TTL job store; `runAnalysis` drives one job through every stage above plus the scanners and questions engine; `resumeWithAnswers` finishes a job paused at `awaiting_answers` |

`inferArchitecture` (Prompt N1) infers and nothing else. It drops no invented reference,
adds back no detected fact and computes no layout: that is `mergeArchitecture` (Prompt
N2), where the model proposes and code disposes.

`mergeArchitecture(draft, facts)` is pure. In order it: drops components and flows that
cite files or evidence that do not exist (recording each in `limitations`); adds back
every detected datastore and deployment target the draft missed, citing the detector's
own evidence found by file, line and summary (never by counting); binds every control gap
to a component; turns gaps below `GAP_ASSERT_CERTAINTY` (0.7) into unknowns as well as
evidence; caps unknowns at 12; lays components out with dagre; and validates the result,
returning typed `issues` rather than throwing.

Two rules worth knowing:

- **Identity.** A draft component is the same as a detected datastore or deployment only
  with a compatible type AND a strong anchor (the same evidence, or the same source
  file). A matching name or technology can break a tie but never establishes identity.
  Ambiguous matches are not merged: the detector's component is added and the ambiguity
  is recorded. The schema has no deployment type, so deployment targets are modelled as
  `external_service`, which keeps them out of the api/backend set gaps fall back to.
- **Binding.** A gap binds by, in order: a component listing its file; the components
  whose file directories are the longest prefix of its directory; the api/backend
  components; every component. Steps 2-4 record a limitation naming the gap and the
  components chosen. A gap in a repository-wide file (manifest, lockfile, deployment
  config) skips the first two steps, since no single component owns such a file. The map is returned as `gapBindings` for Prompt P.

Its prompt asks the model to enumerate the controls a component of each type normally
has, then to split them. A control the gap detector already proved absent stays
evidence and produces no unknown. A control the evidence settles produces no unknown. A
control the context cannot settle either way becomes an `Unknown`, which lowers
confidence downstream and becomes a candidate developer question. Gaps and unknowns are
the two halves of one idea: what we are confident is absent, and what we cannot see
either way.

Smoke test against a real repository (one paid model call, needs `ANTHROPIC_API_KEY`,
`GITHUB_PERSONAL_ACCESS_TOKEN` and Docker):

```
pnpm try scripts/try-architecture.ts <owner>/<repo>
```

## pipeline.ts (Prompt V)

Stage sequence, using the existing `AnalysisStage` enum unchanged -- gap detection is not
a separate stage, since `runDetectors` (`src/server/detect`) already runs `detectGaps` as
its last step:

```
loading_repo -> scanning -> mapping_architecture -> generating_threats
  -> awaiting_answers (if questions exist) | finalizing -> complete
```

`runAnalysis` never rejects: any failure is written into the stored `AnalysisState` as
`stage: "failed"` plus a safe `{code, message}` drawn only from `ERROR_COPY`
(`src/shared/labels.ts`) -- never from an upstream error's own message, which for a
`SecretLeakError` names the secret type and line. A Semgrep failure degrades the run
(`droppedStages: ["semgrep"]`) instead of failing it; OSV never throws by its own
contract. The whole run is bounded by `PIPELINE_TIMEOUT_MS` (10 minutes: the stages are
sequential and threat batches run in several concurrency rounds); after it, no new threat
batch starts, and in-flight paid work is not cancelled, only orphaned, and its usage still lands in
`usageLedger` under the analysis id -- see the module's header comment for why
`usageLedger.clear` is called only on the store's 1-hour TTL expiry, never on timeout or
completion.

Smoke test (**paid**, several model calls; needs `ANTHROPIC_API_KEY`,
`GITHUB_PERSONAL_ACCESS_TOKEN`, Docker and the semgrep CLI):

```
pnpm try scripts/try-pipeline.ts <owner>/<repo>
```
