# app/api (Prompt V Part 2)

Thin route handlers over src/server/analysis/pipeline.ts (Part 1). No route computes a
score, calls a model directly, or holds state of its own -- all of that stays in
`pipeline.ts`; a route's job is Zod-validating the request, rate limiting, and shaping
`AnalysisState` into a response with `src/client/adapter.ts`.

| Route | Method | Does |
| --- | --- | --- |
| `analyze/route.ts` | POST | Validate `{ repoUrl, analysisLevel }` (both required; `analysisLevel` must be 0, 1, 2, 3, or 4), rate-limit by IP, `createAnalysis`, start `runAnalysis` (or the golden-demo path) without awaiting, return `{ analysisId, status }` |
| `analyze/[id]/route.ts` | GET | `getAnalysis(id)`, or 404; otherwise the adapted status, questions, dashboard view model and basis counts |
| `analyze/[id]/answers/route.ts` | POST | Only valid at `awaiting_answers`; validates `{ answers }`, starts `resumeWithAnswers` (or the demo equivalent) without awaiting |

All three set `export const runtime = "nodejs"` -- the pipeline uses MCP clients and
`node:crypto`, neither available on the Edge runtime.

**Demo switch.** When `repoUrl` names the same repo as `GOLDEN_REPO_URL` (compared as
parsed owner/repo, case-insensitive, so trailing slashes, `.git`, `http://` and casing
don't matter) and `DEMO_FALLBACK=1` is set,
`POST /api/analyze` serves `fixtures/golden-demo.json` (or `fixtures/demo-analysis.json`
until that exists) instead of running the real pipeline -- see
`src/server/analysis/demo.ts`. It still walks the same stage sequence, with real delays,
and pauses at `awaiting_answers` when the fixture carries questions, so the full 3-route
flow is demonstrable with no GitHub token, Anthropic key, or Semgrep install.

**Rate limiting.** `src/server/http/rateLimit.ts` is a simple in-memory, per-IP fixed
window (`RATE_LIMIT_MAX` per `RATE_LIMIT_WINDOW_MS`), consistent with the pipeline's own
in-memory, single-process job store -- there is no shared state across instances today.

**Errors.** Every error body is `{ error: { code, title, message, canRetry } }`. `title` and
the default `message` come from `ERROR_COPY` in `src/shared/labels.ts` (fixed copy, never an
upstream message, CLAUDE.md rule 8); a route may send a more specific message for the same
code. `canRetry` is true when the same request can succeed later. Request errors come back
with an HTTP status; a failed analysis comes back from `GET /api/analyze/[id]` as
`stage: "failed"` with the code in `error`.

| Code | Where | Means | Retry |
| --- | --- | --- | --- |
| `INVALID_URL` | 400 on POST `/api/analyze` | `repoUrl` is not a public github.com repository URL | no |
| `INVALID_REQUEST` | 400 on either POST | Body is not JSON, `analysisLevel` is not 0-4, or `answers` is malformed | no |
| `NOT_FOUND` | 404 on `[id]` routes | No analysis with that id, or it expired (HTTP-only, not a schema code) | no |
| `OWNER_NOT_ALLOWED` | 403 on POST `/api/analyze` | `ATTACKCANVAS_ALLOWED_OWNERS` is set and this repository's owner is not on it (checked before any job, rate-limit attempt, GitHub or model call; the golden demo is exempt) | no |
| `NOT_AWAITING_ANSWERS` | 409 on POST `answers` | The analysis has moved past `awaiting_answers` | no |
| `SERVER_BUSY` | 429 on POST `/api/analyze` | `MAX_CONCURRENT_ANALYSES` real analyses are already running | yes |
| `RATE_LIMITED` | 429 on POST `/api/analyze` | This address started `RATE_LIMIT_MAX` analyses within the hour | yes |
| `REPO_NOT_FOUND` | failed analysis | GitHub has no public repository (or branch) at that URL | no |
| `REPO_TOO_LARGE` | failed analysis | The tree or a response is over the loader's size limits | no |
| `INSUFFICIENT_CODE` | failed analysis | Too few application source files to model | no |
| `GITHUB_UNAVAILABLE` | failed analysis | GitHub returned a 5xx, a network error, or an unreadable response | yes |
| `UPSTREAM_RATE_LIMITED` | failed analysis | GitHub or the Claude API throttled us (429, or 403 with no quota left) | yes |
| `MODEL_REFUSED` | failed analysis | Claude declined the request (`stop_reason: "refusal"`) | no |
| `MODEL_OUTPUT_INVALID` | failed analysis | Claude's reply was cut off at `max_tokens`, over the size cap, or invalid after the correction retry | yes |
| `OUTPUT_REJECTED` | failed analysis | The output checks rejected the result (`unknown_file`, `empty_while_exposed`) | no |
| `SECRET_BLOCKED` | failed analysis | A credential survived redaction, so no model call was made (rule 3) | no |
| `TIMEOUT` | failed analysis | The whole run, one model call, or one MCP call ran past its time limit | yes |
| `AI_FAILURE` | failed analysis | Catch-all: a failure no code above describes (a rejected API request, an internal validation failure) | yes |
| `NETWORK_ERROR` | browser only | The browser could not reach the server; never sent by a route | yes |

See `pipeline.test.ts`, `analyzeRoute.test.ts`, `analyzeIdRoute.test.ts`,
`answersRoute.test.ts`, `demo.test.ts` and `rateLimit.test.ts` under `/tests` for the
verified behavior curl examples below assume.
