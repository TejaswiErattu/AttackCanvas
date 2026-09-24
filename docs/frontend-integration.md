# Frontend integration: `useAnalysis(id)`

For Jasnoor. This describes the hook as it exists today in `src/client/useAnalysis.ts`.
It is not the `submit()` / `loadDemo()` design from the playbook's Prompt W example, and
nothing here needs to change to match it.

## The three pieces

| Piece | File | Job |
| --- | --- | --- |
| Start an analysis | `src/app/page.tsx` | Posts `{ repoUrl, analysisLevel }` to `POST /api/analyze`, then `router.push("/analyze/<id>")` |
| Follow an analysis | `src/client/useAnalysis.ts` | Given an id, polls the status, holds the state, submits answers |
| Show an analysis | `src/components/AnalysisView.tsx` | Reads the hook and picks what to render for each phase |

**Submission does not happen in the hook.** The hook never creates an analysis and has no
`submit`, `loadDemo` or `analysisId` field. The landing page starts the analysis, gets an
`analysisId`, and navigates to `/analyze/<id>`. `src/app/analyze/[id]/page.tsx` passes that
id to `AnalysisView`, which calls `useAnalysis(id)`. Because the id lives in the URL, a page
refresh just restarts polling against the same job.

The request body is validated by the server. Both fields are required: `repoUrl` (a full
`https://github.com/<owner>/<repo>` URL) and `analysisLevel` (0, 1, 2, 3 or 4). The page
sends the URL exactly as typed and renders whatever `{ error }` comes back, including the
429 a user gets after five starts in an hour.

## The hook

```ts
function useAnalysis(id: string, pollMs?: number): UseAnalysisResult;
```

`pollMs` defaults to `DEFAULT_POLL_MS` (1200 ms). An empty `id` starts no requests.

```ts
type UseAnalysisResult = {
  phase: AnalysisPhase;
  snapshot: AnalysisSnapshot | null;
  error: AnalysisError | null;
  submitAnswers: (answers: readonly AnswerSubmission[]) => Promise<boolean>;
  retry: () => void;
};
```

### Returned fields

| Field | Type | Meaning |
| --- | --- | --- |
| `phase` | `AnalysisPhase` | What the UI should be doing. See the phase table below |
| `snapshot` | `AnalysisSnapshot \| null` | The last good poll. `null` until the first successful response. Kept when a later poll fails, so the dashboard does not blank out on one bad request |
| `error` | `AnalysisError \| null` | A **request** error (network, 404, unreadable response, or a failed answer submission). It is not the analysis's own failure. See "Two kinds of error" |
| `submitAnswers` | function | See below |
| `retry` | function | See "What `retry()` does" |

`AnalysisSnapshot` (one normalised `GET /api/analyze/[id]` response):

| Field | Type | Meaning |
| --- | --- | --- |
| `stage` | `AnalysisStage` | `queued`, `loading_repo`, `scanning`, `mapping_architecture`, `generating_threats`, `awaiting_answers`, `finalizing`, `complete` or `failed` |
| `stageLabel` | `string` | Display text from the server (`STAGE_LABELS`) |
| `stageIndex` | `number` | 1-based step of 8; `0` for `failed`, which is not a step |
| `stageCount` | `number` | 8 |
| `questions` | `QuestionData[]` | Empty until `awaiting_answers` |
| `view` | `DashboardViewModel \| null` | The dashboard data. Present from `awaiting_answers` onward, not only at `complete` |
| `basisCounts` | `Record<Basis, number> \| null` | Evidence-backed vs assumption-dependent counts over **all scored** threats, including hidden ones |
| `hiddenSummary` | `HiddenSummary \| null` | How many threats were scored, how many hidden (confidence below 0.25), and the most common reason |
| `error` | `AnalysisError \| null` | The analysis's own failure, set when `stage` is `failed` |

### Phases

| `phase` | Polling? | When | `AnalysisView` shows |
| --- | --- | --- | --- |
| `loading` | yes | Before the first response | "Loading analysis..." |
| `active` | yes | Any working stage | Progress bar |
| `awaiting_answers` | **no** | The server is waiting on the developer | Progress and the question panel |
| `submitting` | no | `submitAnswers` is in flight | Progress, question panel disabled |
| `complete` | no | Terminal | The dashboard |
| `failed` | no | Terminal: the analysis failed | The failure, from `snapshot.error` |
| `error` | only if `error.canRetry` | A request failed | A banner (retryable) or a full error screen (not) |

Polling stops by itself at `complete`, `failed`, `awaiting_answers`, and on any
non-retryable request error such as a 404. It resumes when answers are accepted. A slow poll
that returns after the job finished cannot reopen it: a terminal phase stays terminal.

### `submitAnswers(answers)`

```ts
type AnswerSubmission = {
  questionId: string;
  status: "answered" | "skipped" | "unsure";
  optionIndex?: number; // index into that question's options; for "answered"
};
```

Posts `{ answers }` to `POST /api/analyze/<id>/answers` and resumes polling. It resolves
`true` when the server accepted them. The server accepts 1 to 10 answers, each
`questionId` at most 64 characters, and only while the job is at `awaiting_answers`.

On failure it resolves `false`, and only after **one** status fetch has settled where the
job really is. The client cannot tell whether a lost response hid an accepted submission, so:

| What happened | What the user sees |
| --- | --- |
| The answers arrived but the response was lost | The finished result |
| Another tab already answered (409) | The finished result |
| The job expired (404) | A non-retryable error |
| The job is still waiting | The questions again, with the submission error in `error` |

## What `retry()` does

`retry()` does not create, restart or resubmit an analysis. It clears `error` and makes
sure the polling loop is running against the **same id**:

- **After a non-retryable request error** (a 404, which stops polling): `retry()` starts
  polling again. If the server now knows the id, the page recovers; if not, it lands on
  the same 404. `AnalysisView` does not offer this case: it shows the error screen with a
  "start over" link. The behavior exists in the hook and is covered by a test.
- **After a retryable request error** (network down, unreadable response): the loop is
  already running, so `retry()` only clears the banner immediately. If the next poll fails
  again, the error comes back. This is the button `ErrorState` shows on the banner.
- **For a `failed` analysis:** do not offer it. A failed analysis is final on the server,
  so `retry()` would only re-read the same failure. To try again, start a new analysis from
  the landing page.

To re-run an analysis, submit a new one from the landing page. There is no re-submit
function in the hook.

## Two kinds of error

| Where | What it is | Example | Retry? |
| --- | --- | --- | --- |
| `error` on the hook | A **request** error | `NETWORK_ERROR`, `NOT_FOUND`, an unreadable response, a failed answers POST | `canRetry` from the response |
| `snapshot.error` | The **analysis** failed on the server | `REPO_NOT_FOUND`, `TIMEOUT`, `SECRET_BLOCKED` | `canRetry` is the backend's own judgement |

Both are `AnalysisError = { code, title, message, canRetry }`, with fixed copy from the
backend's `ERROR_COPY`. Never show an upstream message. `canRetry` is true only for
`RATE_LIMITED`, `AI_FAILURE`, `TIMEOUT`, `SERVER_BUSY`, `UPSTREAM_RATE_LIMITED`,
`GITHUB_UNAVAILABLE`, `MODEL_OUTPUT_INVALID` and `NETWORK_ERROR`. Route error codes and
status codes are listed in `src/app/api/README.md`.

## How the GET response reaches the dashboard

```
AnalysisState in the server's in-memory store        (src/server/analysis/pipeline.ts)
  -> GET /api/analyze/[id]                           (src/app/api/analyze/[id]/route.ts)
       toAnalysisStatus       stage, stageLabel, stageIndex, stageCount
       toQuestionData         questions
       toDashboardViewModel   threatModel  (the schema ThreatModel, adapted)
       countByBasis           basisCounts
       summarizeHidden        hiddenSummary
       toAnalysisError        error
     all from src/client/adapter.ts, which runs on the server despite its folder
  -> fetchStatus() in useAnalysis.ts   (fetch with cache: "no-store")
  -> readSnapshot()   only `stage` is required; other fields fall back
  -> analysisReducer  -> { phase, snapshot, error }
  -> AnalysisView     -> Dashboard view={snapshot.view}
                         basisCounts={snapshot.basisCounts}
                         hiddenSummary={snapshot.hiddenSummary}
```

Notes:

- The JSON key is `threatModel`, but it holds the **`DashboardViewModel`**, not the raw
  schema `ThreatModel`. The hook exposes it as `snapshot.view`.
- The view model is passed through untouched. The client computes no severity, confidence,
  priority or basis, and keeps the server's threat order. The only client-side work is
  filtering the list (`filterThreats.ts`) and laying out graph nodes (`layoutGraph.ts`).
- Threats below 0.25 confidence are hidden everywhere in the view model. `basisCounts` and
  `hiddenSummary` still count them, which is how the empty state can say "N scored, all
  hidden, and why". The dashboard labels `basisCounts` "Across all scored threats".
- Repository text (titles, paths, snippets) is untrusted. Render it as text, never as HTML.

## The server-side demo

There is no client-side demo loader. The demo runs on the server, so the whole flow (start,
poll, questions, answers) works with no GitHub token, Anthropic key or Semgrep.

1. Put both variables in `.env.local` and restart `pnpm dev`:
   ```
   DEMO_FALLBACK=1
   GOLDEN_REPO_URL=https://github.com/acme/acme-notes
   ```
   The value must be exactly `1`.
2. Submit that repository URL from the landing page (any analysis level). The route
   compares canonical owner/repo, case-insensitively, so a trailing slash, `.git` or
   `http://` still matches. Any other URL runs the real pipeline.
3. The job is created with `isDemo: true` and seeded from
   `fixtures/golden-demo.json`, or `fixtures/demo-analysis.json` when that file does not
   exist (today only the second exists). `src/server/analysis/demo.ts` walks the real stage
   sequence with delays: about 0.7 s, 1.1 s, 1.4 s and 1.8 s through `loading_repo`,
   `scanning`, `mapping_architecture` and `generating_threats`, roughly 5 s in total.
4. The fixture has two developer questions, so the job pauses at `awaiting_answers`.
   Answering finishes it in about 0.4 s. **Answers are not re-scored** in the demo: the
   result is the fixture unchanged.
5. The demo skips the concurrency cap but still counts against the per-IP limit of 5 starts
   per hour, so five demo starts block the sixth until the server restarts or an hour
   passes.

The result is canned data, not a real scan. Use a real repository, with keys and Docker
set up, to test the real pipeline.

## Example: a component using the hook

```tsx
"use client";
import { useAnalysis } from "@/client/useAnalysis";

export function AnalysisPage({ id }: { id: string }) {
  const { phase, snapshot, error, submitAnswers, retry } = useAnalysis(id);

  if (phase === "error" && error && !error.canRetry) return <Fatal error={error} />;
  if (!snapshot) return <p>Loading&hellip;</p>;
  if (snapshot.stage === "failed") return <Failed error={snapshot.error} />;
  if (snapshot.stage === "complete" && snapshot.view) {
    return <Dashboard view={snapshot.view} basisCounts={snapshot.basisCounts} />;
  }
  return (
    <>
      {phase === "error" && error ? <Banner error={error} onRetry={retry} /> : null}
      <Progress stage={snapshot.stage} label={snapshot.stageLabel} />
      {(phase === "awaiting_answers" || phase === "submitting") && (
        <Questions
          questions={snapshot.questions}
          disabled={phase === "submitting"}
          error={error}
          onSubmit={(answers) => void submitAnswers(answers)}
        />
      )}
    </>
  );
}
```

Use one `useAnalysis` instance per analysis id. If a page ever switches ids without
unmounting, give the component `key={id}`: the hook keeps its state when `id` changes, and a
finished state would stop the new id from being polled. (This is from reading the code, not
tested in a browser. Today the "analyze another" link goes through `/`, which unmounts.)

## Tests

- `tests/useAnalysis.test.ts`: the reducer, `shouldPoll`, `pollsAfter`, `readSnapshot`,
  `readApiError`.
- `tests/useAnalysisHook.test.tsx`: the hook with a stubbed `fetch`: polling to complete,
  stopping on a 404, idle at `awaiting_answers`, resuming after answers, recovery from a
  failed submission, cleanup on unmount, and `retry()` restarting a stopped loop.

Run them with `pnpm vitest run tests/useAnalysis.test.ts tests/useAnalysisHook.test.tsx`.
