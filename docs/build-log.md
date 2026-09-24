# Build log

## 2026-09-19 — GitHub URL validation

Added `src/server/ingest/urlParser.ts` and `tests/urlParser.test.ts`. Validates and parses
GitHub URLs and shorthand references.

**Accepts:**
- Full URLs: `https://github.com/owner/repo`, `http://github.com/owner/repo`
- Without scheme: `github.com/owner/repo`
- With www: `www.github.com/owner/repo` (normalized)
- Shorthand: `owner/repo`
- Refs: `/tree/branch-name` (including slashes in branch names)
- Strips: query strings, fragments, `.git` suffix
- Trimmed whitespace

**Rejects:**
- Empty, >500 characters, or containing credentials (`user:pass@`)
- Other hosts (including `gist.github.com`, `github.com.evil.com`)
- Owner not matching `^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$` (39 chars max)
- Repo not matching `^[A-Za-z0-9._-]{1,100}$` (100 chars max), or starting with "." or "-"
- Repo equal to "." or ".."
- Path traversal: `..` or `%2e`/`%2E` (case-insensitive encoded dots)

**Implementation notes:**
- URL normalization is done by the `URL` class; path traversal is checked in the original
  string before parsing because `new URL()` normalizes `..` segments.
- Repo regex allows hyphens anywhere but we explicitly reject leading hyphens.
- Shorthand format is tried before URL parsing for faster matching.

**Tests:** 38 test cases covering every accept and reject rule, including edge cases
(exact length limits, case sensitivity, shorthand vs full URLs).

## 2026-09-19 — Shared schema contract

Created `src/shared/schema` (enums, repo, architecture, evidence, threat, question,
threatModel, drafts, index). Per CLAUDE.md rule 1 this is now frozen.

Decisions:

- **Zod 4.6.5** ships `z.toJSONSchema`, so `zod-to-json-schema` was not needed.
- Draft schemas **strip** unknown keys (Zod default), so a stray model-invented field
  does not consume the single retry allowed by rule 5. The generated JSON Schemas still
  carry `additionalProperties: false`, so the model is told not to add extras even though
  the parser forgives it.
- Drafts are derived with `.omit()` / `.extend()` from the canonical schemas rather than
  retyped, so a computed field can never drift back into model-visible output.
- `ThreatModel` cross-references are validated in one `superRefine`, including a
  **duplicate-id** rule beyond the four originally specified.
- Added a `ConfidenceLabel` enum (`high` / `medium` / `low`) that the enum list did not
  name but `Threat.confidenceLabel` requires. Thresholds live in `src/server/scoring`.
- `AnalysisStage` and `ErrorCode` are exported but not yet referenced; they belong to the
  API route and job state in a later prompt.

Verify:

```bash
pnpm typecheck && pnpm test && pnpm lint
pnpm try scripts/print-draft-schemas.ts
```

Expect 14 passing tests and three JSON Schemas whose `required` arrays contain no
`id`, `severity`, `confidence`, `confidenceLabel`, `basis` or `priority`.

## 2026-09-19 — User-selected analysis level

`AnalysisLevel` (0..4) was missing from the contract and has been added.

- `AnalysisLevelSchema` is a union of numeric literals, so `5`, `-1`, `2.5` and `"2"`
  are all rejected — a plain `min/max` would have let `2.5` through.
- `ANALYSIS_LEVEL_LABELS`: 0 Snapshot, 1 Basic, 2 Standard, 3 Deep, 4 Exhaustive.
- New `request.ts` holds `AnalysisRequestSchema` (`repoUrl` + `analysisLevel`). The URL is
  only shape-checked; ingest settles visibility and size.
- `ThreatModel.analysisLevel` is **required**, echoed from the request.
- It appears in **no** draft schema, so a model cannot select or change it. Two tests pin
  this: drafts strip an injected `analysisLevel`, and the generated JSON Schemas are
  asserted not to contain the string at all.

Test count is now 42.

## 2026-09-19 — View model and client adapter

Added `src/shared/viewModel.ts` (UI-ready types), `src/shared/labels.ts` (display copy) and
`src/client/adapter.ts` (`toDashboardViewModel`, `toQuestionData`, `toAnalysisStatus`,
`toAnalysisError`). `src/shared/schema` was not touched.

Decisions:

- Threats sort by priority, then risk (impact x likelihood), then confidence, then id, so the
  order is fully deterministic. `fixNow` is the first 5 `fix_now` cards in that order.
- Absent values are `null`, `[]` or `{x:0,y:0}`, never `undefined`; a test walks every output
  to enforce it.
- `QuestionData.index` and `AnalysisStatus.stageIndex` are 1-based. `failed` has no step, so
  its `stageIndex` is 0 and `stageCount` stays 8.
- `FilterOptions` lists only values that match at least one threat, in canonical order.
- OWASP names are re-exported from the schema rather than duplicated.
- `canRetry` is true for `RATE_LIMITED`, `AI_FAILURE` and `TIMEOUT` only.
- Threats below confidence 0.25 are hidden in the adapter (CLAUDE.md rule 2); see below.

### Follow-up: analysis level and low-confidence hiding

- `DashboardViewModel` now carries `analysisLevel` and `analysisLevelLabel`, copied from
  `ThreatModel.analysisLevel` and labelled with the schema's `ANALYSIS_LEVEL_LABELS`.
- Hiding is a display-layer rule. `toDashboardViewModel` builds **one** visible-threat list
  (`confidence >= 0.25`, sorted) and derives counts, `fixNow`, `threats`, node `threatCount`
  and `maxSeverity`, and `filterOptions` from it, so a hidden threat cannot leak into any of
  them. The stored `ThreatModel` is never mutated. Model-level `assumptions` and
  `limitations` are unaffected.
- 0.249 is hidden and 0.25 is visible (`>=`). Tests were mutation-checked by flipping the
  comparison, removing the filter, and pointing counts at the unfiltered list.

## 2026-09-19 — Demo and empty fixtures

Added `fixtures/demo-analysis.json` (fictional "acme-notes": 7 components, 8 flows, 3
boundaries, 2 unknowns, 14 evidence items, 9 threats, 2 questions),
`fixtures/demo-analysis.notes.md` (per-threat scoring arithmetic),
`fixtures/empty-analysis.json` (valid, zero threats, one limitation) and
`tests/fixtures.test.ts`. `src/shared/schema` was not touched.

Scoring follows the playbook's Prompt O interpretation of CLAUDE.md rule 2:

- Each confidence contribution applies once per evidence *kind*, not per item. Code points
  need a `code` item; `config` earns none. Semgrep needs scanner evidence from Semgrep, OSV
  needs dependency evidence from OSV.
- The +0.10 second-source bonus applies once, when direct evidence comes from two or more
  distinct `EvidenceSource` values. AI-sourced evidence never corroborates.
- Inference-only (+0.20) requires inference evidence and no code, scanner, dependency or
  developer-answer evidence. As written, config and assumption evidence do not switch it off.
- The assumption penalty (-0.15) applies once per threat. Confidence is clamped to 0..1 and
  rounded to 2 decimals.
- `basis` is `evidence_backed` when any cited evidence is neither inference nor assumption,
  and `assumption_dependent` otherwise. Listing an assumption does not change it.

Consequences for the demo: 6 of 9 threats are visible. Threats 4 (S3), 8 (admin panel) and
9 (search DoS) fall below 0.25 and are hidden by the adapter. Only 8 and 9 are
`assumption_dependent`; 4 is `evidence_backed` with an assumption penalty. Both developer
questions concern hidden threats, which a developer answer (+0.30) could bring into view.

Test notes:

- `tests/fixtures.test.ts` holds a reference implementation of these rules, split into small
  pure functions and unit-tested with synthetic evidence, then used to recompute every demo
  threat. It is a stand-in until `src/server/scoring` exists; switch the test to that module
  then.
- Mutation-checked: config earning code points, per-source bonus, per-assumption penalty,
  config not counting as direct, an inference-only bonus that ignores its exclusion list, no
  lower clamp, AI counted as a source, any scanner earning Semgrep points, and three
  corruptions of the fixture data were all caught.
- The OSV advisory (`GHSA-qwph-4952-7xr6`, jsonwebtoken <= 8.5.1) was verified against
  osv.dev. Semgrep rule ids are illustrative.
- `findUndefined` lives in `tests/helpers.ts`, shared by the adapter and fixture tests.

## 2026-09-19 — GitHub MCP client

Added `src/server/mcp/githubClient.ts`, `scripts/list-github-tools.ts`,
`scripts/try-github-mcp.ts`, `tests/githubClient.test.ts` and
`tests/githubClient.connection.test.ts`. `src/shared/schema` was not touched.

Discovery first, against server v1.12.2:

- The `repos` toolset exposes 13 read tools and has **no tree tool**. `get_repository_tree`
  exists in the separate `git` toolset, so the client runs `GITHUB_TOOLSETS=repos,git`.
- **No toolset exposes repository metadata.** All 55 tools under `toolsets=all` were
  checked: there is no `get_repository`. `getRepoMetadata` is therefore REST-only.
- `listTree` prefers the MCP tool and falls back to the REST tree API; both it and
  `getRepoMetadata` return `source: "mcp" | "rest"`.

Wrapper: one allowlist of 6 read-only tools, a 60 s timeout, a 1 MiB cap enforced while
text is accumulated, and typed errors. `GitHubMcpError` carries a schema `ErrorCode`;
`GitHubClientConfigError` marks a bug or a bad environment (disallowed tool, missing or
rejected token) and has no code, because no user-facing code describes it.

Notes:

- The token reaches the container through its environment only. A connection test asserts
  it never appears in argv, and a mutation that put it there failed 2 tests.
- Running the smoke script revealed that a rejected token returned `AI_FAILURE`
  ("Analysis failed"). 401 now raises `GitHubClientConfigError` with an actionable message.
- Mutation-checked: allowlist bypass, size cap off-by-one, chars-vs-bytes, ignored
  `isError`, each error-mapping branch, unpassed timeout, token in argv, read-only
  disabled, and a broken singleton were all caught.
- **Not yet verified against live GitHub.** Every test uses a mocked client, and no
  credential was available. `listTree`'s MCP path and `getFileContent` have never run
  against the real server; their parsers are written defensively for several response
  shapes. Run `pnpm try scripts/try-github-mcp.ts <owner/repo>` with a real token.

## 2026-09-19 — Fix: getFileContent returned the download status, not the file

The first live run against octocat/Hello-World showed `getFileContent` returning
`successfully downloaded text file (SHA: …)` instead of the README. Every mocked test
had passed, because the mocked response shape was invented rather than captured.

Root cause, found with the new `scripts/inspect-github-file.ts`: `get_file_contents`
returns two content blocks. The `text` block is only a status line; the body is in a
`resource` block at `resource.text` (`resource.blob` for binary). The client read text
blocks only.

Changes to `src/server/mcp/githubClient.ts`:

- `callToolResultWith` / `callToolResult` return text and resource blocks separately;
  `callToolWith` still returns text only. `extractResources` caps each resource payload on
  its own, so a file of exactly 1 MiB is not tipped over by the status text beside it.
- `getFileContent` reads the body from the resource. If the result carries no body it
  falls back to the REST Contents API (60 s timeout, 1 MiB cap on decoded bytes, typed
  errors, token in a header only). The body cap is widened for base64 inflation, so a
  file just under 1 MiB is not rejected for its encoding.
- `getFileContentWithSource` also reports `source: "mcp" | "rest"`.
- The status line is never returned as content. `isDownloadStatusMessage` is anchored to
  the whole string, so a real file that merely begins with those words is not mistaken
  for it.
- A body that arrives but is unacceptable (binary, a directory) is reported directly and
  not retried over REST. The first version retried, which a test caught: it wasted a call
  and would only have failed again.
- `listTree` and `getFileContent` now rethrow `GitHubClientConfigError` instead of falling
  back to REST.

Tests: `tests/githubResponses.ts` holds the real captured responses, used by both
`githubClient.test.ts` and the new `githubClient.getFileContent.test.ts`. The smoke test
now fails if it receives only a status message; that guard was verified by re-creating the
bug and confirming exit code 1.

Live result: octocat/Hello-World `README` returns `Hello World!` via MCP; the tree comes
via MCP and metadata via REST. Still unverified live: the REST Contents fallback (no live
case triggers it now that MCP returns the body), binary files, and large files.

## 2026-09-19 — Semgrep MCP client, and a shared MCP safety wrapper

Files added: `src/server/mcp/base.ts`, `src/server/mcp/semgrepClient.ts`,
`src/server/mcp/semgrepRules.ts`, `scripts/list-semgrep-tools.ts`,
`scripts/try-semgrep.ts`, `tests/semgrepClient.test.ts`, `tests/semgrepResponses.ts`.
Changed: `src/server/mcp/githubClient.ts`, re-expressed on top of `base.ts`.

### Discovery (`scripts/list-semgrep-tools.ts`, server v1.29.0, semgrep 1.176.0)

Seven tools. Two facts changed the design:

- **No tool takes a config or ruleset parameter.** The intended
  `p/owasp-top-ten` → `p/javascript` → default fallback is simply not reachable over
  MCP. `semgrep_scan` takes absolute *paths*; `semgrep_scan_with_custom_rule` is the
  only tool that takes file *contents*, and it requires the rule inline.
- So `extra.metadata.cwe` / `extra.metadata.owasp` are whatever our own rule declares.
  The pack in `semgrepRules.ts` carries that metadata for exactly that reason.

Scanning therefore goes through `semgrep_scan_with_custom_rule` with a AttackCanvas
rule pack. Repository content never touches disk.

### Allowlist

Only `semgrep_scan_with_custom_rule` and `get_supported_languages`. `semgrep_scan` is
deliberately **off** the allowlist despite being a scan tool: it reads absolute paths
off disk, which cannot honour "only already-redacted content reaches the scanner" —
a path argument bypasses redaction entirely. Also off: `semgrep_scan_supply_chain`
(scans the server's own workspace, not our content), `semgrep_findings` (Platform API:
needs a token, sends repo names off-box), `semgrep_rule_schema`,
`get_abstract_syntax_tree`.

### The shared wrapper

`base.ts` holds what both clients need: allowlist + timeout + size cap + typed errors
in one choke point, the response extractors, `mapErrorCode`, and the lazy-singleton
stdio connection with its shutdown hooks. Each client passes its caps and an
`ErrorFactory`, so a failure raised inside `base.ts` is still a `GitHubMcpError` to
GitHub callers and a `SemgrepMcpError` to Semgrep callers. That indirection exists
because `extractText` throws on an oversized response, and a shared base class thrown
from shared code would break `instanceof` at every call site.

`githubClient.ts` keeps every export it had. The refactor's acceptance test was the
existing suite passing unedited: 295 tests, and the identical pre-existing
MaxListeners warning, before and after.

### Snippets do not come from Semgrep

`extra.lines` is the string `"requires login"` in logged-out OSS mode — confirmed both
through the CLI and through MCP. `parseScanResponse` therefore slices the snippet from
the content we sent (max 6 lines), which is correct regardless of login state.

### A wrong diagnosis worth recording

`semgrep mcp` was first believed to be broken: a hand-rolled Python JSON-RPC probe got
a clean `initialize` and a correct `tools/list`, then hung on *every* `tools/call` —
`get_supported_languages` included — across four attempts up to 8 minutes, while
stderr logged "User doesn't have the Pro Engine installed, not running `semgrep mcp`
daemon...". That pointed at a Pro-Engine requirement. It was wrong. Driven by the
actual MCP SDK client, the same scan returns in ~2 s. The fault was in the probe's
handshake, not the server. `pipx install semgrep-mcp` was done while chasing this and
turned out to be unnecessary — that package is now a deprecated stub exposing a single
`deprecation_notice` tool, and it can be removed.

Lesson, the same one as the `get_file_contents` entry above: verify with the real
client, not with an invented approximation of it.

### Tests

56 new tests in `tests/semgrepClient.test.ts`: the parser against the saved response
(`tests/semgrepResponses.ts`, captured from the live MCP tool), parser edge cases
(fenced JSON, empty results, missing metadata, `cwe` as a bare string, 6-line snippet
truncation, skipped malformed results, garbage → typed `AI_FAILURE`), the allowlist
(including a meta-test that the path-based and platform tools stay off it), error
mapping, size cap, and batching (41 files → 40 + 1, per-batch timeout, concatenated
findings, empty-content files dropped, failing batch named by index and never by
content).

### Live result

`pnpm try scripts/try-semgrep.ts` → 7 findings in ~2.1 s across the three samples:
SQL concatenation in `src/db.js` (lines 9 and 13-15), `eval`/`new Function` in
`src/eval.js` (5, 10), hardcoded JWT secret in `src/auth.js` (7, 11), plus MD5 (15).
All 8 rules in the pack are verified to fire.

Not yet verified: batching against a real repository (every live run so far is a
single batch of 3 files), and behaviour on a file large enough to approach the 4 MiB
response cap.

## 2026-09-19 — Ingest: file classifier and repository loader

Added `src/server/ingest/classifier.ts`, `loader.ts`, `tests/classifier.test.ts`, `tests/loader.test.ts`.
`loadRepositoryWith(deps, …)` takes the GitHub client as a parameter (the `*With` pattern), so tests use a
fake and a 60-path tree; `loadRepository` binds the real client.

An audit against the original prompt found and fixed five deviations from a first version:

- **The 2 MiB limit was enforced on tree sizes**, with a missing size counted as zero, so a repository
  could exceed it. It is now enforced on the UTF-8 byte length of what was actually downloaded, committed
  in priority order. Tree sizes are used only for the prompt's 200 KB ignore rule, and that rule is also
  re-checked on the downloaded content.
- **`assets/` is ignored** (any directory segment; `src/assets.ts` is not a directory and is kept).
- **`*auth*`, `*session*`, `*login*`, `*admin*` match the whole normalized path**, so `src/admin/panel.ts`
  is high.
- **Removed an invented 1 MiB lockfile exemption** from the 200 KB limit. Consequence: a lockfile over
  200 KB (common for `package-lock.json`) is ignored, so OSV will not see it. If that matters, the fix is a
  deliberate change to the requirement, not a silent exemption.
- **`.map` is no longer ignored as binary**; it is not in the prompt's list.

Precedence, first match wins: ignore; lockfile (medium, reason `dependencies`, never model-bound; above
low and high so a lockfile under `src/auth/` is not promoted); low (tests, docs, examples, scripts); high;
medium (source in src, lib, server, api, config/**); anything else low ("other").

Other behaviour: at most 300 files are fetched (priority order), then the byte budget is applied to the
results, so a file that no longer fits is skipped and a smaller later one may still fit. Files past the
300th are not fetched even if the budget would have had room. A file that downloads as binary counts as
ignored. `modelBoundFiles()` drops lockfiles. Lockfiles never count toward the 3-source-file minimum.
`summary.frameworks` is `[]` until detectors run. Returned content is not yet redacted.

Regression tests were mutation-checked: removing the byte budget, counting characters instead of bytes,
dropping the actual-content 200 KiB check, un-ignoring assets, matching names on the file name only,
removing the size rule, promoting lockfiles, and making lockfiles model-bound each fail at least one test.

## 2026-09-19 — Security: secret redactor

Added `src/server/security/redactor.ts` and `tests/redactor.test.ts` (112 tests).
`redact`, `assertNoSecrets` and `toEvidence` are pure and synchronous; `src/shared/schema` untouched.

Two defects were found by tests written to assert an invariant rather than an example, and one by
measuring instead of assuming:

- **`redact()` was not idempotent.** The `[REDACTED:type]` marker is 20+ characters of mixed case
  assigned to a variable, and it contains a colon, so on a second pass it matched `high_entropy`,
  `generic_secret` *and* `connection_string`. `assertNoSecrets(redact(x).content)` therefore threw.
  Fixed by discarding matches that lie wholly inside an existing marker. "Wholly" matters: a match
  that starts in a marker and runs past it still covers unredacted text, so it is kept.
- **`connection_string` was quadratic.** Case-insensitive `[a-z][a-z0-9+.-]*` re-scanned a long run
  of letters from every position hunting for `://`. One 200 KB line took ~20 s, and the loader hands
  over files up to 200 KB from an untrusted repository (rule 3), so this was reachable denial of
  service. Bounding the scheme to 31 characters and anchoring it to a word start made it 4.5 ms.
  A test now redacts six pathological 200 KB inputs inside a 2 s budget; reverting the fix fails it
  at 19.8 s.
- **Two tests could not fail.** The "long low-entropy string" sample was 30 `a` characters, which the
  *hex* exclusion caught before entropy was ever consulted, so disabling the entropy threshold broke
  nothing. And no input the rules can produce actually exercises the union-widening in `mergeSpans`,
  because every rule matches either a whole quoted value or a token inside one. Fixed by using a
  non-hex low-entropy sample and by unit-testing `mergeSpans` directly on synthetic spans.

Judgment calls:

- **Summary wording** uses the raw type name: `Hardcoded credential of type aws_access_key committed
  in source`. The prompt wrote types in brackets throughout, so this stays greppable; a human label
  map is a small change if the UI wants prose.
- **Evidence ids are kebab-cased** (`secret-aws-access-key-12-1`) because `zId` requires it, and the
  index keeps them unique when one line holds two findings of the same type.
- **`lineEnd` is left unset.** A finding records one line, and a private-key block spans many, so
  claiming a range would be inventing data.
- **`assertNoSecrets` runs `high_entropy` too**, as specified. It is the most false-positive-prone
  rule, so a legitimate high-entropy literal in already-redacted content would block a model call.
  Worth revisiting once it is wired into the pipeline.

## 2026-09-19 — Deterministic detectors

Added `src/server/detect/{types,shared,frameworks,routes,auth,datastores,envNames,deployment,index}.ts`,
`scripts/try-detect.ts`, `tests/detectSamples.ts` and five `tests/detect.*.test.ts` files (264 tests).
`src/shared/schema` untouched: the fact types are local to `detect`, as `RawSemgrepFinding` is to
`semgrepClient`, and only `Evidence` crosses back into the contract.

Confirmed with the user before building: `Route.path` keeps the framework-native form and gains a
`normalizedPath` (`[id]` → `:id`); `Route` gains a stable `id` so auth facts and evidence can
reference it; detectors read raw content and never emit a value.

### Four defects, each found by a different kind of check

- **Destructured imports were invisible.** `importsIn` handled `const x = require("m")` but not
  `const { requireAuth } = require("m")`, the common Express shape. Every such middleware looked
  locally defined, so the `unknown` auth status — the whole point of which is "imported and
  unclear" — never fired. Found by running the detectors over the samples before writing
  assertions.
- **Next App Router auth was scoped to the file.** `POST` was reported as authenticated because
  the `GET` beside it called `getServerSession`. A false "authenticated" hides a threat, so the
  handler body is now the text of that export alone.
- **`req.get("Referrer")` was a route.** Accepting any receiver before `.get(` turned header reads
  and Express's own settings getter (`app.get("view engine")`) into routes: 328 "routes" in
  expressjs/express, one of them `GET Referrer`. The receiver must now look like an app or router
  **and** the path must start with `/` or be `*`. 328 → 213, all genuine.
- **`_route.ts` was a route.** An optional slash in `^app\/.*\/?route\.ts$` matched a `_`-prefixed
  private file. shadcn-ui/taxonomy ships `app/api/auth/[...nextauth]/_route.ts`, which Next does
  not serve. 11 → 9 routes.

The last two only surfaced by running against real repositories; the samples were too well-behaved.

### A test that could not fail

Mutation testing caught a hole in the security suite. A mutation that made route summaries copy
200 characters of raw file content **passed all 246 tests**: the planted secrets lived in
`src/db.js`, which produces no routes, so a route summary could quote any file it liked. Fixed by
planting a distinct AWS-shaped marker in *every* fact-producing sample and asserting none reaches
the output. Three content-copying mutations now fail 3–5 tests each.

### A redactor false positive, not a detector bug

`assertNoSecrets(JSON.stringify(result))` threw `high_entropy` with nothing secret in it. An
ordinary summary — `"GET /api/proxy/* handled here (next_app)"` — has entropy **4.23** against the
**4.2** threshold; harmless as a plain line, but `JSON.stringify` wraps it as `"summary":"…"`,
which is exactly the assignment shape the rule looks for. The suite now sweeps the string leaves
instead, which keeps the property that matters (a leaked connection string or vendor key still
fires) without the JSON artefact.

**This is worth acting on before `assertNoSecrets` is wired in front of model calls**, since the
plan is to call it on serialised payloads and it will throw on innocuous English prose. Options:
raise the threshold, require more than entropy for a prose-shaped value, or assert on leaves
rather than JSON at the call site. Left as-is here because changing it is a security judgement
call, not a detector change.

### Live results

- `expressjs/express`: 206 files, 213 routes in 0.04 s, 2 frameworks, 2 datastores. All routes read
  as unauthenticated, which is right for a repo of examples except that `restrict` in
  `examples/auth/index.js` is a real guard the name pattern does not cover — the specified pattern
  has no "restrict", and resolving a locally defined middleware's body needs the AST work.
- `shadcn-ui/taxonomy`: 9 App Router routes with dynamic segments normalised
  (`/api/posts/:postId`, `/api/auth/*`), 5 authenticated vs 4 not, 29 env names, prisma datastores.
- `assertNoSecrets` clean on both.

## 2026-09-20 — Scanners: Semgrep normalization and OSV

Added `src/shared/owaspMap.ts`, `src/server/scanners/{semgrep,osv,versions,cvss}.ts`, and tests
`owaspMap`, `semgrepScanner`, `osv`, `versions`, `cvss` plus `osvResponses.ts`. `src/shared/schema` untouched.
`versions.ts` and `cvss.ts` are two files beyond the two named in the brief: OSV needs semver comparison and
a severity order, there is no `semver` dependency, and adding one to a supply-chain scanner was not worth it.

### The schema has nowhere to put "metadata"

The brief asks for the mapped OWASP codes "as metadata on the evidence", and `Evidence` has no such field.
The schema is frozen (rule 1) and did not need to change: both scanners return `Evidence & { metadata }`,
which is assignable to `Evidence`. The catch is that `EvidenceSchema` is a plain `z.object`, so **parsing
strips `metadata`**; a test pins that, and Prompt Q must read it before validating.

### Real OSV data overturned three parts of the spec's design

OSV responses were captured live rather than invented (`tests/osvResponses.ts`), and the untidy parts
changed the code:

- **The first fix *listed* is wrong for minimist@1.2.0.** The record has two ranges, and its first fix is
  `0.2.1`, *below* the installed version. The scanner reports the **first applicable fixed version**: the
  first fix of the range that contains the installed version (`1.2.3`), with a fallback to the lowest fix
  above it.
- **One record lists many packages.** GHSA-p6mc covers lodash, lodash-es, lodash.pick and a RubyGems gem, each
  with its own fix (lodash 4.17.19, lodash-es 4.17.20). Entries are matched on package name *and* ecosystem.
- **Duplicate advisories.** lodash@4.17.15 returns six advisories that are really four issues; GHSA-35jh and
  GHSA-r5fr list each other as aliases. They are collapsed (connected components over id + aliases), which
  also freed cap slots. A collapsed group advises the *highest* fix any member needs: 35jh alone says 4.17.21,
  but its alias r5fr needs 4.18.0.

Also decided: `devDependencies` are scanned but rank below runtime dependencies of equal severity;
`peerDependencies` are not; severity is a computed CVSS v3 score (OSV carries the vector, not the number)
falling back to the advisory's label; and a batch that fails after an earlier one succeeded keeps the earlier
results and says how many dependencies went unchecked.

### Consequence of an earlier decision, worth knowing

The classifier's 200 KB limit now applies to lockfiles (the exemption was removed). A `package-lock.json` over
200 KB is never loaded, so those repositories are scanned at `versionExact: false`, from the minimum of each
range. That is the fallback the brief specifies, but for a large project it will be the common case, not the
edge case, and a range minimum can report a flaw the resolved version already fixed.

### Defects in my own first draft, and one in the tooling

- **Control characters in source.** The write tooling turned escape sequences for NUL, 0x1f and 0x7f, typed
  inside a string or regex, into *raw* control bytes: a NUL delimiter in `dedupeKey` and a control-character
  class in the summary sanitiser. Git treats a NUL as binary, so the file would have diffed as a blob. Found by
  inspecting the bytes. The sanitiser now filters by code point, so no control character appears in source.
- **A test that could not fail.** Making a collapsed group report only its representative's fix broke
  nothing, because in the real data the representative already carried the highest fix. Added a scenario
  where the more severe advisory needs the *lower* fix.
- **A mutation harness that measured nothing.** zsh does not word-split an unquoted variable, so vitest was
  handed one giant filename and ran no tests; every mutation "passed". Noticed from empty output, fixed with
  an array.
- **`< 2.0.0` was read as a lower bound**, because splitting on whitespace separated the operator from its
  version. Operators are now glued to their versions first.

### Verification

Every safety-relevant behaviour was mutation-checked: wrong fix selection, package-name and ecosystem
matching, alias collapse, group fix, cap, severity and runtime/dev ordering, batch size, concurrency, cache,
timeout, withdrawn advisories, unsafe ids, package-name validation, degrading on outage, `versionExact`,
control characters; and in the Semgrep path dedupe, both redactions, snippet cap, OWASP mapping, ordering
and the evidence kind and source. All fail at least one test. A live run against api.osv.dev returned exactly
the saved fixtures' six findings in about 0.5 s, and a 1 ms timeout degraded to a limitation message.

## 2026-09-20 — Evidence metadata: OWASP 2025 codes now survive schema parsing

The scanner entry above returned `Evidence & { metadata }` and noted that `EvidenceSchema.parse()` strips
`metadata`. That was not sufficient for the requirement, so `src/shared/schema/evidence.ts` was changed with
explicit authorization, and only this much:

```ts
export const EvidenceMetadataSchema = z.object({
  owasp2025: z.array(Owasp2025Schema).optional(),
});
// EvidenceSchema gains:   metadata: EvidenceMetadataSchema.optional(),
```

It reuses the existing `Owasp2025Schema` (and so `OWASP_LABELS`), the same way `Threat.owasp` does. It is
optional and closed, so evidence without it parses byte-for-byte as before, an invalid code is rejected, and
any other key inside `metadata` is stripped rather than carried. Nothing else in the contract changed.

`normalizeSemgrep` now returns plain schema `Evidence` with `metadata: { owasp2025 }` (omitted when a rule has
no OWASP tag), and `parse()` returns it unchanged. The price: the rule's CWE list, its 2021 tags and Semgrep's
own severity are no longer carried, because the closed schema has no field for them. Severity belongs to
scoring in any case (rule 2).

Consumers checked: the model-facing draft schemas reference evidence by id and are unaffected; the dashboard
adapter copies named fields into `EvidenceItem`, so metadata never reaches the view model; the detectors and
`toEvidence` build evidence without it. **OSV is the one that is affected:** its evidence still carries its own
`metadata` (package, version, `versionExact`, ...). It stays schema-valid, but parsing now reduces it to `{}`
instead of dropping the key. An open decision: move those fields somewhere the schema defines, or extend the
schema for them.

A stale build artefact bit again while verifying: `.next` held iCloud-style duplicates (`routes-manifest 2.json`,
`cache-life.d 2.ts`) that make `tsc` report duplicate identifiers. They are gitignored build output, and were
deleted.

## 2026-09-20 — OSV metadata carried by the schema, and an audit of the scanner requirements

Resolves the open decision in the previous entry. `EvidenceMetadataSchema` gained the OSV group, and only
the fields named for it: `package` (string), `version` (string), `versionExact` (boolean), `cve`
(`CVE-yyyy-n` strings) and `fixedVersion` (string). No `z.record`, `z.unknown`, `passthrough` or catch-all.
`package`, `version` and `versionExact` must appear together. The scanner's emitted values and field names
are unchanged; `parse()` now preserves those five and strips `dev`, `vulnId`, `aliases`, `severityScore` and
`severityLabel`, which the schema does not carry. Unknown metadata keys are **stripped, not rejected**.

An audit of each original scanner requirement found the code correct in every case but several requirements
were not pinned by a test. New tests now pin: lockfileVersion 2 and 3 separately (2 also carries a legacy
`dependencies` map that must not win), the *default* 10 s timeout as the value each request actually
receives (previously only the constant was checked), the process-wide advisory cache and its eviction, that
exactly the union of returned ids is fetched, concurrency never above 5 across 1 to 40 advisories, chunk
sizes across 11 package counts, detail-request network errors and timeouts, the osv.dev URL, and a file-wide
guard that turns any un-injected `fetch` into a failure instead of a live request.

The fixed version reported is the first *applicable* fixed version. For minimist@1.2.0 the first fix listed in
the record is 0.2.1, below the installed version, so the fix is the first one of the range that contains the
installed version. This is what the brief's "first fixed version" means for an installed package, not a
departure from it.

## 2026-09-20 — All ten OSV metadata fields carried by the schema, and lockfiles over 200 KB

### Schema

`EvidenceMetadataSchema` now carries all ten fields the OSV scanner emits, with the emitter's own types and
unchanged values: `package`, `version`, `versionExact`, `dev`, `vulnId`, `cve`, `aliases`, `severityScore`
(finite, non-negative), `severityLabel` (`LOW | MEDIUM | HIGH | CRITICAL`) and `fixedVersion`, plus Semgrep's
`owasp2025`. Still closed: no `z.record`, `z.unknown`, `passthrough` or catch-all, and unknown keys are
stripped. A coherence rule replaces the earlier three-field one: once any OSV field appears, the seven the
scanner always emits (`package`, `version`, `versionExact`, `dev`, `vulnId`, `cve`, `aliases`) must all be
present, with each missing one reported at its own path. `severityScore`, `severityLabel` and `fixedVersion`
stay optional because the scanner omits them when an advisory has no score, no label or no fix.

The five-field form from the previous entry is now rejected (it lacked `dev` and `vulnId`); the tests that
used it were rewritten, not loosened.

### Lockfiles over 200 KB

Where the limit comes from: `classifier.ts` applies a 200 KB cap to every file, and the loader re-checks the
downloaded size. That cap was applied to lockfiles when the earlier exemption was removed, so a normal
`package-lock.json` was never loaded and every dependency was scanned at `versionExact: false`.

There is no existing large-file mechanism to reuse. The hard blocker is the GitHub client's
`MAX_RESPONSE_BYTES = 1 MiB`, enforced on the MCP path and on the REST path (`githubClient.ts`), and the
Contents API returns no inline content above 1 MB either. So the achievable window is 200 KB to 1 MiB, and
anything larger genuinely cannot be fetched today.

The change, scoped to what the scanner needs:

- `package-lock.json`, and only that name, may be up to `MAX_LOCKFILE_BYTES` (1 MiB, pinned by a test to the
  client's cap). `yarn.lock`, `pnpm-lock.yaml` and every other file keep 200 KB. The 2 MiB total budget is
  unchanged, and a lockfile sorts after high-tier source, so it is the file dropped when the budget runs out.
- A lockfile is safe to relax for because it is never model-bound and is parsed as JSON.
- A latent failure fixed on the way: the tree size can be missing or wrong, and the client throws
  `REPO_TOO_LARGE` for a lockfile over its cap, which used to abort the *whole* load. That one file is now
  skipped. Any other file, and any other error on the lockfile (a rate limit), still fails the load.
- The scanner now says when versions were inferred, whatever the reason: how many dependencies were checked at
  the lowest version of their range, and that the lockfile may be missing, over 1 MiB, or not list them.

The cause (size versus absence) is not distinguished in that message: the scanner receives files, not the
loader's skip reasons.

Proof: a generated 1,400-transitive-package lockfileVersion 3 fixture (644,193 bytes, about 629 KiB, over three times the 200 KB limit) goes
through the real loader and the real scanner with saved OSV responses and a guard that fails on any network
call. lodash resolves to its locked 4.17.15 (its range's minimum would be 4.0.0), `versionExact` is true, and
neither the vulnerable transitive minimist@1.2.0 nor a nested lodash@3.0.0 is queried.

### Wording

The fixed version reported is described throughout as the **first applicable fixed version**, and the earlier
"conflict with the brief" framing is corrected in the two entries that used it.
- Predictive pivot: AttackCanvas now detects security controls that should be present but appear to be missing, rather than reporting only observed repository facts.
- This pivot follows Prompt K because the deterministic evidence, Semgrep, and OSV pipeline now provides the grounded foundation required for reliable predictions.
- This should allow AttackCanvas to generate evidence-backed predicted threats while clearly distinguishing confirmed observations from assumption-dependent gaps.

## 2026-09-21 — Prompt M: Claude client, and the cost baseline

`callStructured` (src/server/ai) is proven against the real Anthropic API: native structured output
(`output_config.format`), Zod validation, usage fields and cost all worked on the first attempt. The key in use
is an organization-level key, so requests carry an `anthropic-workspace-id` header taken from the optional
`ANTHROPIC_WORKSPACE_ID` variable; without it the API returns an HTTP 400 naming the missing workspace.

### Cost baseline: evidence-only pre-prediction

**Single-call smoke-test baseline. This is NOT the cost of a repository analysis.** It is one `callStructured`
call from `scripts/try-claude.ts` on a five-line fake README, priced at the estimated list rates in
src/server/ai/models.ts. It exists so the Day 5 reading, taken after predicted threats are generated, has a
same-shaped number to be compared against. A per-analysis figure needs the end-to-end pipeline (Prompt V1).

| Field | Value |
| --- | --- |
| Label | evidence-only pre-prediction baseline (single-call smoke test) |
| Date | 2026-09-21 |
| Profile / stage | dev / architecture |
| Model | claude-sonnet-5 |
| Input tokens | 426 |
| Output tokens | 600 |
| Cache creation tokens | 0 |
| Cache read tokens | 0 |
| Requests / attempts | 1 / 1 |
| Total measured cost | $0.0069 (printed; 426 x $2/M + 600 x $10/M = $0.006852) |

- Cache tokens are 0 because the system prompt is far below the minimum cacheable prefix, not because caching is
  misconfigured. Cache behaviour is unmeasured until a real STRIDE batch reuses a long system prompt.
- An earlier run of the same script (with the temporary diagnostic still in place) measured 426 in / 559 out,
  $0.0064. The input is fixed; output varies run to run, so read this baseline as about $0.006 to $0.007.
- The cost is an estimate from list price and reported tokens, not a billing record.
- Day 5: record the same fields again once predicted threats are being generated, and keep the delta.

## 2026-09-21 — Prompt N1: architecture inference with expected controls

The first step that asks a model to reason. `inferArchitecture`
(src/server/analysis/architecture.ts) sends the Prompt L context to Claude under
`ArchitectureDraftSchema` and gets back components, data flows, trust boundaries and
unknowns. The prompt lives in `prompts/architecture.v1.md`, so it can be diffed without
touching code and the id `architecture.v1` is recorded with whatever it produced.

### Expected controls: the part that is not a report reader

The model enumerates the controls a component of each type normally has, then splits
them three ways. A control the gap detector already proved absent produces **no**
unknown — the gap is already evidence, and duplicating it would ask the developer a
question the tools have answered. A control the evidence settles produces no unknown. A
control the context cannot settle either way becomes an `Unknown`.

Gaps and unknowns are the two halves of one idea: what we are confident is absent, and
what we cannot see either way. The first becomes evidence a threat can cite; the second
lowers confidence and becomes a candidate question. Splitting them is what keeps the
model from asserting what it cannot support.

The playbook's "Watch Out" — unknowns that are really opinions, like "consider adding a
WAF" — is pre-empted rather than fixed later: the prompt requires every unknown to name
a control and a component and to be answerable yes or no by a developer in one sentence.

### Decisions

- **N1 validates no evidence reference.** The prompt requires real refs; N2 rule 1 drops
  components whose files or refs resolve to nothing and records each drop in
  `limitations`. Two implementations of one rule would be two things to keep in sync.
- **The cap of 12 is prompt-only.** N2 rule 5 caps after merging, ranked by gap
  certainty. Trimming in N1 could discard a model unknown N2 would have kept.
- **`ARCHITECTURE_MAX_TOKENS = 12_000`,** above the client's 8000 default. A draft with a
  dozen components and 12 unknowns runs long, and a reply cut off at `max_tokens` spends
  the single retry rule 5 allows on length rather than on the schema error it exists for.
- **`inferArchitecture` takes a built `BuiltContext`,** not `RepoFacts`. STRIDE reuses the
  same context, so the pipeline builds it once.

### Correction to the playbook

N1 names `src/server/ai/client.ts`. That file does not exist; the client is
`src/server/ai/claude.ts`, exporting `callStructured`. No duplicate was created. Prompt
caching and profile-based model selection already live there, so N1 adds neither.

### Verification

`pnpm typecheck`, `pnpm lint` and `pnpm test` all exit 0. The suite is 31 files and 1893
tests, up from 30 and 1870; `pnpm test architecture` runs the 23 new ones.

Three mutation checks confirmed the tests bite: forcing the debug dump to always write
failed 4 tests, deleting the "already reported as a gap" bullet from the prompt failed 1,
and wrapping the context text instead of sending it verbatim failed 1. Each file was
restored and diffed byte-for-byte afterwards.

`scripts/try-architecture.ts` was written in this prompt and run once against a real repository afterwards;
see "N1 live verification" below.

## 2026-09-21 — Prompt N1: live verification and two prompt corrections

### Live-run result

**One `inferArchitecture` call, not a complete repository analysis.** It excludes Semgrep, OSV, STRIDE, questions
and remediation. It must not be read as the cost of analysing a repository, which needs the end-to-end pipeline
(Prompt V1).

| Field | Value |
| --- | --- |
| Label | N1 architecture inference, single call, no scanners |
| Repository | bezkoder/node-js-express-login-example @ master (16 files loaded, 5 gaps) |
| Profile / stage / model | dev / architecture / claude-sonnet-5 |
| Prompt | architecture.v1 |
| Exit code / attempts / requests | 0 / 1 / 1 |
| Input tokens | 7,908 |
| Output tokens | 9,748 |
| Cache write tokens | 3,860 |
| Cache read tokens | 0 |
| Measured cost | **$0.1229** (estimate from list price and reported tokens, not a billing record) |

The pre-call estimate was $0.03-0.08, so the call cost about 60% more than expected, for the reason under
"Follow-ups". Cache reads are 0 because this was the first call; the 3,860 cache-write tokens are the system
prompt.

Outcome: 3 components, 9 data flows, 2 trust boundaries, 6 unknowns. The draft parsed against
`ArchitectureDraftSchema` and carried no scoring or position keys. Every cited file and evidence reference (about 60)
resolved against the context that was sent. No unknown duplicated a control gap. The repository contained no
instruction-like text, so the untrusted-data defence was not exercised by this run.

### Two prompt corrections made from the run

1. **Route-id example.** The prompt said `r-1`; the context builder emits `route-1`. The model cited `route-N`
   correctly anyway, but a weaker model could have followed the prompt literally. Fixed, and a test now derives the
   format from the real context builder so the two cannot drift.
2. **Unknowns must name their component.** Only 2 of 6 unknowns named the component in their text; the rest named a
   file, route or endpoint. The prompt now requires the component by `name` or `id`, says a file, route or endpoint
   does not count, and requires every `affectsComponentIds` entry to appear in the description. The tests check that
   the instruction is present; they cannot show a model obeys it, and that has not been re-measured (no second paid
   call was made).

### Follow-ups, recorded and deliberately not fixed in this branch

- **Redactor let hardcoded database credentials through.** `db.config.js` reached the model with a database user and
  a short literal password under upper-case `USER` and `PASSWORD` keys unredacted, while the `secret` value in
  `auth.config.js` was redacted (values deliberately not reproduced here). A public example repository, so no harm
  here, but a real blind spot for short literals under credential-named keys (Prompt F territory).
- **Prompt L's 3.5 characters per token understates real usage.** The context builder estimated about 5,130 tokens;
  the API measured at least 7,908 uncached input tokens for it, roughly 2.3 characters per token on this content. The
  60,000-token context budget is therefore nearer 90,000 real tokens. It still fits every model window, but the
  "conservative" claim in `context.ts` does not hold for this model.
- **9,748 output tokens billed for a much smaller visible reply; cause not proven.** The reply text was 7,128
  characters (roughly 2,000-3,500 tokens). The remaining ~6,000-7,700 tokens are unaccounted for. Hidden reasoning
  tokens are the likeliest explanation: the request sets no `thinking` option and the client reads only text blocks,
  so such tokens would be billed but invisible. That is an inference, not an observation. If it holds, the 12,000
  `max_tokens` cap was 81% used on a three-component repository, and a larger one could be cut off, spending the
  single retry on length. Needs a look at the response's content block types and usage breakdown before anyone
  changes a token limit.

## 2026-09-21 — Prompt N2: deterministic architecture merge

`mergeArchitecture(draft, facts)` in `src/server/analysis/architecture.ts`. Pure, no I/O, no paid call. It drops invented
references, adds back detected datastores and deployment targets, binds every control gap to a component, turns
low-certainty gaps into unknowns, caps unknowns at 12, lays components out with dagre and validates the result. Schema
files, the N1 prompt, model and token limits, the redactor and the Prompt L estimator are untouched.

### Decisions (some refine the written prompt)

- **Evidence for synthesized components is found, never counted.** Evidence is matched to a datastore or deployment fact
  by file, line and the summary the detector wrote for that kind of fact. No `ev-datastore-N` is built from a position,
  and a reference is attached only if that exact id is in the returned evidence array. Tests use ids that break the
  counting pattern and a reversed array.
- **Identity needs a compatible type and an anchor.** A draft component is "the same" as a detected fact only with a
  compatible type AND the same evidence or the same source file. Names and technologies can break a tie between anchored
  candidates but never establish identity. Two candidates, or one component anchored to two facts, is ambiguous: nothing
  is merged, the detector's component is added, and a limitation is recorded. "Owned path" is implemented as the exact
  file only; a directory does not anchor, which errs toward synthesizing.
- **Every gap is bound.** Order: a component listing the file; the components whose file directories are the longest
  prefix of the gap's directory (ownership flows downward; a component rooted at `src/api/` does not own `src/`); the
  api/backend components; every component. Steps 2-4 record a limitation naming the gap and the chosen ids. Repository-scope
  gaps go straight to api/backend then all, as the prompt says, and record no limitation because they have no file owner by
  definition. With no components at all the binding is empty and that is recorded.
- **Deployment targets are `external_service`.** The schema has no deployment or infrastructure type. `backend` would
  have pulled repository-scope gaps onto the deployment component. This is a modelling compromise, not a claim.
- **Model unknowns rank after gap-derived ones** (their rank certainty is the 0.7 threshold, and every gap-derived
  unknown is below it), so the cap drops a model unknown first. The prompt did not say where they sit.
- **Dedupe needs both** the gap's normalized control name in the model unknown's text and at least one shared component
  id. The gap-derived wording is kept.
- The result carries `gapBindings`, `componentEvidence` and `flowEvidence` beside the six fields the prompt lists, because
  the contract's `Component` has no `evidenceRefs` and Prompt P consumes the binding.

### Verified

Real exit codes: `pnpm typecheck` 0, `pnpm test` 0, `pnpm lint` 0 with 0 warnings, `git diff --check` 0. 21 mutations
(threshold, boundary, prefix, cap, ranking, evidence lookup file/line/summary, identity, type, ambiguity, dedupe, drops,
fallbacks, layout, add-back) were each broken on purpose and each killed by a test; one initially survived (evidence lookup
ignoring the file) and a test was added. The live `try-architecture` run was not made (paid call).

### Known limitations

- Repository-wide files are classified by the detectors' own file helpers at any depth, so in a monorepo a gap in one
  package's `package.json` binds to api/backend components repo-wide rather than to that package's components.
- The identity and dedupe rules are heuristics on model prose; they are deliberately conservative but unmeasured on a
  real model reply.
- Follow-ups from N1 (redactor blind spot, Prompt L token estimate, unexplained output tokens) remain open and unfixed.

### N2 review corrections (same branch, before commit)

- **Repository-wide files.** A gap in a dependency manifest, lockfile or deployment config (`package.json`, lockfiles,
  Dockerfile, compose, serverless, terraform, `vercel.json`) now binds to the api/backend components, else to every
  component, and records a "repository-wide fallback binding" limitation. Before this, a synthesized datastore whose
  `files` included `package.json` owned a gap in that file exactly, and the gap bound to the datastore alone. A regression
  test reproduces it.
- **J2 follow-up: none needed for supply chain.** `detectGaps` already gives `supply_chain_integrity` `scope: "repository"`,
  so the detector is not misassigning it; the regression fixture uses file scope on purpose. One consequence worth knowing:
  the compose "database port published" gap is file scope on a compose file, and is now bound repository-wide rather than to
  the synthesized deployment component. That follows the instruction that deployment-wide config is repository-wide.
- **Deployment compromise is visible.** Every deployment target synthesized as `external_service` records a limitation
  saying the schema has no deployment type.
- **Layout robustness bug found by a hostile fixture.** dagre stores nodes in plain objects, so a component id of
  `__proto__` lost its node and got a non-finite position. Nodes are now keyed by array index, never by model-supplied id.
- **Invariants now tested:** after a drop no flow, boundary, unknown, binding or evidence entry refers to the removed
  component, and every reference in the result points at an object in the result; validation failures come back as typed
  issues and the merge does not throw on schema-invalid model output; every component has a finite position; every evidence
  reference resolves; every gap has a `gapBindings` entry (empty, with a limitation, only when there are no components).

## 2026-09-21 — Scoring module (Prompt O)

Added `src/server/scoring/index.ts` and `tests/scoring.test.ts` (28 tests). Schema untouched.

- Categories (each counted once): code (any non-gap `code`/`config` item), gap, semgrep, osv,
  developer, inference. Gap check runs first because gap evidence has kind `code`/`config`.
- Gap term uses the strongest gap's certainty once; the floor (0.40) needs a gap-only
  threat whose gap certainties sum to >= 0.8. A gap missing from the map, or with a non-finite certainty, counts as 0 and reports "control gap not scored: missing or invalid certainty" instead of a numeric line; a finite out-of-range certainty is clamped to 0..1 and the clamped value is shown.
- The -0.15 assumption penalty is **per assumption**, as Prompt O specifies. The Prompt D
  stand-in in `tests/fixtures.test.ts` applies it once per threat and has no gap term, so it
  is left alone and the demo fixture numbers are unchanged. Switching it to this module is a
  separate decision.
- `basis` is redefined, not extended, to avoid changing the frozen schema union: a threat is
  `evidence_backed` when any cited item is neither a gap, an inference nor an assumption.
- Hiding stays a display rule; `isHidden` (< 0.25) is exported for callers.

Note: `tests/fixtures.test.ts` still contains the legacy Prompt D stand-in confidence logic
(assumption penalty once per threat, no gap term, kind-based categories). It is **not** the
production scoring implementation, which is `src/server/scoring`. It is left unchanged for
now, so its results can differ from the real module for some threats. `severityOf` was
compared read-only against all 9 demo threats and agrees with every stated severity.

## 2026-09-21 — Prompt P1: STRIDE threat prompt and batch payload

`prompts/threats.v1.md` plus `src/server/analysis/threatPrompt.ts` (`buildThreatBatch`), with
`tests/threatPrompt.test.ts` (46 tests). No model call, so nothing here was paid for. The
batching engine, the dedupe and the scoring are Prompt P2 and Q and are deliberately absent.
Schema files untouched; the only edit outside the new files is exporting `formatEvidenceLine`
from `context.ts` so one evidence formatter serves both prompts.

The prompt runs two passes in one call: evidence-driven first, then gap-driven over the
applicable categories that produced nothing. Silence is stated as a correct answer, and the
four-part test (element by id, missing control, concrete attacker action, asset reached) is
the drop rule for both passes.

### Decisions (some refine the written prompt)

- **`src/server/ai/client.ts` does not exist.** The prompt named it; the client is
  `src/server/ai/claude.ts` (`callStructured`, stage `"stride"`). Read as that.
- **An injection threat cites no path as evidence.** The prompt asks for "the file path as
  evidence", but `evidenceIds` holds `zId` values and a path is not one. Changing that would
  be a schema change (rule 1), so the prompt instead requires the path in `attackScenario` and
  in `assumptions`, and lets the threat cite whatever real evidence the element already
  carries for that file. Nothing invented enters the evidence set.
- **The missing control has no field.** `DraftThreat` has nowhere to put part 2 of the
  four-part test, so the prompt requires it inside `attackScenario` and the mitigation.
- **Data flows are described from their endpoints.** The contract gives a flow no
  description, assets or files, and `gapBindings` binds gaps to components only. A flow gets a
  description built from its label, protocol, classification and endpoint names; assets and
  files as the union of both endpoints'; the endpoints' gaps, each tagged with the
  `viaComponentId` it came from; and the unknowns affecting either end. Its own evidence comes
  from `flowEvidence` and is not unioned, because a flow's citations are its own.
- **Only ids in the merged evidence are offered.** `componentEvidence`/`flowEvidence` entries
  are filtered against `MergedArchitecture.evidence`, so the model is never shown an id that
  P2 would then drop. A binding naming a gap the detector did not report contributes nothing.
- **Element blocks are never dropped for budget; excerpts are.** The elements are the batch.
  Excerpts are spent whole-file in element order, and a file that does not fit is recorded in
  `droppedFiles` rather than cut.
- **A citation past the end of a file falls back to the coverage excerpt.** `windowAround`
  clamps the end of a range to the file but not the start, so a stale line number produced an
  empty range and crashed `renderFile`. Found by the hostile-content test, not by review.
  Clamped locally; `context.ts` is left alone, since its own callers cannot reach that state.

### Verified

Real exit codes: `pnpm typecheck` 0, `pnpm test` 0 (34 files, 2058 tests), `pnpm lint
--max-warnings 0` 0, `git diff --check` 0. 22 mutations were each applied on purpose and each
killed by a test: the STRIDE table per type, the flow's S-on-boundary rule, evidence leaking
between elements, unfiltered invented ids, ignoring the binding map, gap ordering, the flow's
`viaComponentId`, unknown filtering, skipping redaction, dropping the range clamp, ignoring
the budget, whole-file excerpts, skipping the secret guard, and six prompt mutations (removing
"silence is a correct answer", softening the four-part test, allowing severity back, letting
likelihood absorb certainty, dropping the untrusted-data section, and a stale table row).
Three initially survived — unredacted content, the softened four-part test and the stale table
row — and a test was added or tightened for each before the pass was clean.

No live run was made. Whether pass 2 fires at a sensible rate on a real repository is a P2
question and needs a paid call.

## 2026-09-21 — Prompt P2: threat engine (batching, validation, dedupe, ids)

`generateThreats` in `src/server/analysis/threats.ts`, with `tests/threats.test.ts` (75 tests) and
`scripts/try-threats.ts`. It uses the existing client (`src/server/ai/claude.ts`, stage `"stride"`) and P1's
`buildThreatBatch`; it scores nothing and builds no ThreatModel. No shared schema file was touched. The
engine returns `EngineThreat[]` (a `DraftThreat` plus `id`), the evidence those threats cite, limitations, a
per-batch report, per-call usage and the prompt id.

### Decisions (some refine the written prompt)

- **The model returns `{ threats: [...] }`, not a bare array.** The client sends the schema as a structured-output
  contract, whose root is an object (as with the architecture draft). The wrapper lives in `threats.ts`; one
  sentence of `prompts/threats.v1.md` was changed to match. That is a genuine integration defect in P1, not a rewrite.
- **The API rejects `minimum`/`maximum` on integers** (HTTP 400: "For 'integer' type, properties maximum, minimum are
  not supported"), and `impact` and `likelihood` generate them. That is a property of the endpoint, not of this engine,
  so `toApiSchema` lives in `src/server/ai/claude.ts` and every structured call sends the converted schema: a deep copy
  without minimum, maximum, exclusiveMinimum, exclusiveMaximum and multipleOf at any depth (objects, arrays,
  anyOf/oneOf/allOf, definitions). Names under `properties`, `$defs` and the like are kept as names, and
  `enum`/`const`/`default`/`examples` are copied as data. The caller's schema is not mutated. The reply is still parsed
  with the caller's full Zod schema, so 1-5 is still enforced. Found by the first live call; no mocked test could show it.
- **Per-call deadline.** `callStructured` takes an optional `timeoutMs` (positive, finite; default `TIMEOUT_MS`, 120 s, so
  existing callers are unchanged) and the TIMEOUT error reports the deadline that expired. Threat batches ask for
  `THREATS_TIMEOUT_MS` = 300 s. Retry behaviour is untouched (a timeout is still not retried). A timed-out batch aborts
  the whole run and no partial result is returned.
- **Batches are two elements, output is capped at 12,000 tokens.** The prompt allows up to four; live runs at four elements
  never completed, so `THREATS_BATCH_SIZE` is 2 (concurrency 3 and the 300 s deadline unchanged). A 6,000-token ceiling was
  tried first and truncated (see the live runs), so it is back at 12,000. The saved bezkoder architecture has 14 elements.
- **Batching is first-fit.** Units are a component plus the flows it sources, taken in id order and placed whole in the first
  batch with room, else a new one; a unit larger than a batch is split with the component first. First-fit rather than strictly
  sequential because sequential packing left the 14-element saved shape at 8 batches; first-fit gives the minimum, 7. It can leave a
  short batch (one extra call) in exchange for an assignment that is obvious and stable. Input order is irrelevant.
- **Reference rules are stricter than "exists".** Component and flow ids must exist AND at least one must belong to the
  threat's batch. Evidence and unknown ids must be ones the batch was SHOWN, so evidence belonging only to an unrelated
  element is dropped even though it exists. A threat that cites no evidence and states no assumption is dropped too
  (the prompt's own rule). Nothing is repaired; each drop is a limitation naming the threat, the batch and every reason.
- **Dedupe candidates must be related, then similar.** Related means they share a component, share a data flow, or one
  cites a flow whose source or target is a component the other cites (`areRelated`, symmetric; the engine passes the
  architecture's flows). Similarity is Jaccard over title plus scenario tokens with a small stopword list (no security
  vocabulary removed), threshold >= 0.60. Groups are connected components over a
  canonically sorted list, so the result cannot depend on the model's order; the cost is that similarity is
  transitive. The evidence-backed threat (one citing a non-gap item) speaks for the group; ties fall to the canonical
  order. Evidence, assumptions, unknown ids, elements, categories and mappings are unioned; impact and likelihood take
  the maximum, each WITH the reason written for that maximum. Unioning elements, categories and mappings goes beyond
  the three unions the prompt lists, because a merged threat that names only the winner's elements would lose claims.
- **Ids** are `threat-N` from a total order: first element id, then first STRIDE category, then the record itself.
- **Usage is recorded when a response is RECEIVED**, before parsing or validation, as one ledger entry per call that grows in
  place (`UsageLedger.update`, matched by identity) so a validation retry is never counted twice and a call whose reply later
  fails still appears. It carries input, output, thinking, cache-read and cache-write tokens, the configured and reported
  model, and the stop reason. A request that got no response records nothing. Thinking tokens are inside `output_tokens`, so
  they are reported but not priced separately.
- **A `max_tokens` truncation is not retried.** It is deterministic (same prompt, schema and limit cut off at the same place),
  so the correction retry only bought a second failure. The client fails at once with `AI_FAILURE` and a safe message naming
  the configured limit; the truncated response's usage stays in the ledger.
- **Any failed batch fails the run (fail-fast).** No partial result is returned: a list silently missing a batch's
  elements would read as "nothing found there". No new batch starts after the first failure; batches already in flight
  finish, because the client cannot cancel a call, and their results are discarded.
- **Safe SDK error diagnostics.** `AiError` messages for `AI_FAILURE` now say what kind of failure it was, e.g.
  `connection error: APIConnectionError cause=TypeError/UND_ERR_HEADERS_TIMEOUT - Connection error.`. Every SDK error class
  is named "Error", so the class comes from the constructor. Kept: kind (connection timeout, connection error, HTTP error,
  error, non-Error value), class, HTTP status, a short code (system code or API error type, identifiers only), the cause's
  class and code, and, for an error with NO status, a message that is redacted, whitespace-collapsed and capped at 300
  characters. Never read: headers, request, response, the API's body, or a thrown non-Error's value (only its typeof).
  Retry behaviour is unchanged. Deviation from the request: an HTTP status error's message is NOT kept. It is the
  provider's response body, which can echo the request in a form no redactor recognises; `tests/ai.workspace.test.ts` (a 400
  that echoes the workspace id and key) fails if it is included. The status, class and API error type still tell an
  invalid request from a rate limit.

### Verified

Real exit codes: `pnpm typecheck` 0, `pnpm test` 0, `pnpm lint --max-warnings 0` 0, `git diff --check` 0. 68 mutations
(batch size, flow attachment, sorting, splitting, flushing, pool ordering and limit, error selection, each reference
check, gap evidence offered, limitation recording, threshold and boundary, shared-element rule, stopwords, preference,
each union, maximum and its reason, normalisation, id numbering and order, failure policy, wrapper key, schema
stripping) were each applied and each killed. Six initially survived and a test was added or tightened for each:
a preference test the alphabetical tiebreak could pass, a union test whose winner already held every element, a reasons
test whose winner owned both maxima, an oversize split with no exact layout, lowest-index error selection, and keywords
nested in arrays.

### Live runs

Attempts 1-5 (four-element batches, then two-element batches at 6,000 and 12,000 tokens) never completed a batch: an integer-keyword
HTTP 400, a 120 s TIMEOUT, a dropped connection, a 6,000-token truncation, and a 12,000-token truncation whose recorded usage showed
`output 12000 (thinking 12000)`: the model spent the whole budget on hidden reasoning. Fixes: the client strips unsupported schema
keywords, takes a per-call `timeoutMs` and a per-call `thinking` setting, records every provider response, and does not retry a
`max_tokens` truncation. Threat calls alone send `thinking: { type: "disabled" }`.

6. Smoke (`express-api`, `df-api-db`, thinking disabled, 12,000 tokens, 300 s): succeeded in 96.0 s, one response, out 6,109 tokens
   (thinking 0), $0.0886, 10 threats after one drop. Several threats cited route evidence ("POST /api/auth/signin handled here") as
   if it proved a weakness, which would have made assumption-based threats look evidence-backed.
7. `prompts/threats.v1.md` gained a DIRECT-SUPPORT RULE (cite only evidence that directly establishes the claimed weak control; route
   evidence proves only that an endpoint exists; otherwise state an assumption or drop the threat; bad-versus-good example). Tests pin
   every clause and mutants removing each are killed.
8. Full run, whole saved bezkoder architecture, 7 batches of 2, concurrency 3: 7 of 7 completed, 194.4 s, 7 provider responses (all
   `end_turn`, thinking 0), in 36,263 / out 22,549 / cache-read 22,748 / cache-write 17,061, $0.3452. The model returned 39 threats;
   6 were dropped and 33 survived validation and dedupe (no merges): 6 with a non-gap citation, 20 gap-only, 7 assumption-only. Pass 2
   fired; the gap-only share was 61% (expected 25-50%).

Findings from reading the 33 threats against the repository:

- **Six threats were dropped for a data-flow id in `componentIds`** (`df-signup` five times, `df-api-db` once). The engine is right to
  drop them (nothing is repaired) but the model lost real findings by putting a flow id in the wrong field; the prompt does not say
  that a flow element's id belongs in `dataFlowIds`. Not changed.
- **The direct-support rule worked where the evidence was absent**: the hardcoded database and JWT secrets (both real) now cite nothing
  and state an assumption, as the "good" example says.
- **It did not stop route-only citations for absence claims.** threat-1 (no rate limiting), threat-2 (no audit trail) and threat-13
  (signout does not invalidate the token; true, `req.session = null` and a 24 h JWT) cite only route-detection evidence, which shows
  the endpoint exists and not the weakness. threat-3 (no TLS) cites a `mysql declared as a dependency` datastore item, which shows
  MySQL is used and not that TLS is absent. threat-8 and threat-19 are directly supported by a gap item and only supplemented by a
  route item, yet are counted "confirmed" because the route item is not a gap.
- **The "confirmed" count therefore overstates.** It means "cites at least one non-gap item", not "directly supported". Scoring's
  `basis` uses the same test, so those threats would be scored `evidence_backed`. Scoring is unchanged; the sound fix is a
  relevance check on what counts as positive evidence (for example, route and datastore-declaration evidence shown as supplementary
  only), or a stricter prompt.
- Minor: threat-4 (database credentials) depends on `unk-jwt-secret-source`, an unrelated unknown; threat-9 says signin is a
  protected resource.

9. Two prompt corrections after the full run (`prompts/threats.v1.md` only; no schema, scoring, batching, dedupe or client change):
   - **Identifier placement rule.** `componentIds` holds only component ids and `dataFlowIds` only flow ids from the batch's typed
     element records (`### ELEMENT express-api (component, backend)`, `### ELEMENT df-api-db (data flow, data_flow)`); a flow and
     its endpoints go in `dataFlowIds` and `componentIds` respectively; ids are copied exactly. Bad-versus-good example on
     `express-api` and `df-api-db`. A test checks that the quoted record shapes are what `buildThreatBatch` really emits.
   - **Basis preservation**, a subsection of the direct-support rule. Context evidence that proves only existence, location or
     reachability must not support a different weakness; route evidence proves a route exists and datastore-declaration evidence
     proves a datastore or dependency exists, neither alone proves a control missing or weak; a gap-only threat cites only its gap;
     supplementary positive evidence only when it directly supports part of the claim; contextual-only evidence becomes an
     assumption; contextual evidence never promotes a gap-only or assumption-only threat. Examples: missing rate limiting (cite the
     gap, not the signin route) and missing TLS for MySQL (the dependency shows MySQL is used, not that TLS is absent).
   Pinned by independent prompt tests, one per clause and example; 235 mutants over the code and prompt plus the 22 original P1
   mutants (257) are all killed.
10. Targeted verification, `express-api` + `df-api-db`, thinking disabled, 12,000 tokens, 300 s: succeeded in 56.7 s, one response,
   in 7,417 / out 5,298 / thinking 0 / cache-write 6,802, $0.0848. 10 threats, 0 dropped, no limitations: 0 evidence-backed, 6
   gap-only, 4 assumption-only. Acceptance: no mistyped component/flow reference (none was dropped, and validation checks each field
   against its own set), no evidence-backed threat resting on route or datastore context (no threat cites either), no gap-driven
   threat promoted by context (every gap-only threat cites only gap evidence). The hardcoded database and JWT secrets and the
   missing TLS are all assumption-only with no citation, as the rules say. Not re-run on the whole repository, so the earlier
   6 dropped flow-id threats and the route-only "confirmed" threats are not re-measured end to end.

Process note: one mutation-pass run left a single mutant in `claude.ts` (`status-less errors retried`), most likely because two
harness runs overlapped. `pnpm test` caught it (8 retry tests failed), the line was restored, every patch was re-checked against the
sources, and the whole mutation pass was re-run from a verified-clean start.

## 2026-09-21 — Secret-redaction regression found by the P2 full run

A threat from the full run quoted the sample repository's database password back in its scenario, so a
credential had reached a model (CLAUDE.md rule 3). Traced with `scripts/verify-threat-payloads.ts`, which
renders every batch locally, makes no model call, and prints counts and locations only.

**Root cause.** One data path: **file excerpts**. `buildThreatBatch` already redacted every file, so the
redactor itself was the hole. `generic_secret` required a value of at least `MIN_SECRET_LENGTH` (8)
characters; the sample password is 6, so `PASSWORD: "<6 chars>"` did not match and was excerpted verbatim.
The JWT secret (19 characters) was redacted correctly all along, which is why only one of the two leaked.
Architecture descriptions, unknowns, gap text, evidence summaries and limitations were all clean: the
detectors never copy matched text (`ControlGap` carries names and paths, `toEvidence` carries no snippet).

**Fix, in the central redactor** (`src/server/security/redactor.ts`), not a threat-prompt-local one:

- A value under a credential key is redacted at ANY length when it holds no whitespace; the 8-character
  floor still applies to values that contain whitespace, so `{"passwordResetExpiry": "1 hour"}` stays.
- `pwd` joins the keyword list (password, passwd, pwd, secret, token, api_key, private_key, client_secret),
  matched case-insensitively anywhere in a key, so jwtSecret/JWT_SECRET/DB_PASSWORD/clientSecret are covered.
- A TypeScript annotation between key and value is allowed: `const jwtSecret: string = "..."`.
- A fallback literal after an environment reference is redacted while the reference is kept:
  `process.env.JWT_SECRET || "..."`, `cfg.get("k") ?? "..."`.
- Pure environment references are never redacted, in `generic_secret` and in `high_entropy` alike:
  `${VAR}`, `$VAR`, `%VAR%`, `process.env.VAR`, `import.meta.env.VAR`. `${VAR:-default}` and
  `prefix${VAR}` are NOT pure references, because each carries a literal.
- Ordinary prose is untouched: the rules still need a key, an assignment and a quoted value.

**Defence in depth at the model boundary** (`threatPrompt.ts`, `threats.ts`): every untrusted string in a
batch — element name, description, assets, file paths, flow label and protocol, gap control/expectation/file,
evidence summary/path/ruleId — now goes through the central redactor BEFORE it is flattened and capped, so a
truncation can never leave half a credential. Ids, kinds, types, numbers and the trusted system prompt are
untouched. `assertBatchClean` runs the existing guard over the final text and every path, in the builder and
again in the engine immediately before the request; it throws `SecretLeakError` (type and line, never a
value) and nothing is sent. Fail-closed is tested with the builder mocked, so only the engine's own guard
stands between the text and the client.

**Verified.** `pnpm typecheck` 0, `pnpm test` 0 (37 files, 2,370 tests), `pnpm lint --max-warnings 0` 0,
`git diff --check` 0. 304 mutations killed (282 + 22 P1) from a verified-clean source state with one harness
process; the sources were re-checked for leftover mutants afterwards. Three mutants initially survived, all
"redact before truncate": the sentinel sat past the cap, so truncating first deleted it rather than leaving a
fragment. The tests now place the value straddling the cap, and the flow-label case uses a sentinel
containing a space, because a fragment next to the template's own closing quote would otherwise be tidied
away by the outer redaction pass and hide the bug.

Local seven-batch verification of the saved bezkoder analysis, no model call: **0 sentinel occurrences** in
any model-bound payload (previously 2), 10 redaction markers where the values were, batch ids and structure
unchanged, and the architecture around each value (`HOST`, `USER`, `DB`, `dialect`) still readable.

**Known, not fixed here:** `.debug/try-architecture-.../architecture.attempt-1.txt`, written by the Prompt N1
run on 2026-09-20 before this fix, still contains the sample password. It is a gitignored local artefact of
an old run, not a code path; deleting it is the user's call.

## 2026-09-21 — Prompt U, Part 1: prompt-injection defenses and canary test

`src/server/security/injection.ts` (`SECURITY_PREAMBLE`, `injectionFindings`, `injectionEvidence`,
`checkModelOutput`), applied in `src/server/ai/prompts.ts` (`loadPrompt` now returns `text` = preamble +
`body`, and `body` = the file verbatim). Canary repository in `tests/fixtures/canary-repo/` (a genuinely
unauthenticated admin route, no rate-limit package, planted injection text in the README, the manifest
description, a source comment and a string literal), loaded via `tests/canaryRepo.ts`, which re-paths
on-disk files to repository-relative form — `isScannable()` drops any path containing a `tests/` or
`fixtures/` segment, so skipping that step collapses five gaps to one and both target gaps disappear
(measured before writing the fixture). `tests/security.test.ts` (36 tests, offline) and
`tests/canary.live.test.ts` (gated on `ANTHROPIC_API_KEY`, skipped otherwise). `docs/security-design.md`
created with the three rows Part 1 earns.

### Decisions and deviations from the playbook (recorded, not silently patched over)

- **No forced "submit" tool exists.** `callStructured` uses native `output_config.format` structured
  output, and `src/server/ai/claude.ts` documents the tool fallback as deliberately unimplemented on this
  SDK. The test asserts the stronger property instead: no `tools`, `tool_choice`, `mcp_servers` or
  `container` on any request body, and `output_config.format.type === "json_schema"`.
- **"Full certainty" is 0.90 / 0.85, not 1.0.** `authn_missing` has no 1.0 path; `rate_limit_missing` is a
  flat 0.85. The canary asserts those exact values.
- **The preamble is prepended at load time**, not pasted into the questions/remediation prompts the
  playbook names — only `architecture.v1.md` and `threats.v1.md` exist yet (Prompts S and R build the
  others). A test loops over every file in `prompts/` so a future prompt cannot land without it.
- **Injection evidence does not reach the model context.** The context prefix renders facts, gaps, scanner
  findings and file excerpts; detector evidence is not rendered there. Injection evidence reaches the
  merged architecture and the assembler (a threat CAN cite it, and the model sees the raw text in the file
  excerpt either way), but nothing today gives the model a citable id for it directly. Documented as a
  Part 1 non-goal rather than worked around.
- **Detection scans whole-file text, not line by line**, because the gap-suppression sentence in the
  canary README wraps across three lines and a line-at-a-time scan would miss it entirely — caught while
  building the fixture, before it reached a test.
- **A 107-character injected string literal had Shannon entropy 4.54** (threshold 4.2): the redactor would
  have blanked it and `assertNoSecrets` would have thrown, silently breaking the live canary. Split into
  two shorter literals (4.16 and 4.04), each safe, before any live call was made.

### Verified (offline)

`pnpm typecheck` 0, `pnpm test` 0 (39 files, 2,441 tests, 1 skipped — the gated live canary), `pnpm lint
--max-warnings 0` 0, `git diff --check` 0. 17 mutations applied over `injection.ts`, `canaryRepo.ts` and
`prompts.ts`; 16 killed, one (`snippet` added to injection evidence) is equivalent — `EvidenceBuilder`
structurally drops any `snippet` field, so the mutation cannot change behaviour. Three mutants initially
survived and each exposed a real test gap: a summary assertion that compared the constant to itself, no
test naming *which* rule fired for a given line, and an id-ordering test that only held because the
canary happened to already be path-sorted (added an explicit reversed-input case).

### Live runs — corrected accounting

The live canary ran twice, both against `ANTHROPIC_API_KEY`, both making real, billed requests.

- **Invocation 1** (123.70 s): both model calls completed — architecture inference, then one threat batch
  forced via `generateThreats`'s `batches` seam to the component carrying the admin route. The test then
  **failed on an incorrect local assertion**, not a defense failure: it asserted no threat text ever
  contains a planted phrase, but a correct answer quotes the injection while reporting it (the model
  raised three separate threats, one per injected file, each naming the phrase and the file it came from).
  That assertion was replaced with `checkModelOutput`, which reads for compliance (an empty or downgraded
  analysis, or a threat *title* echoing an instruction) rather than for the phrase's mere presence.
- **Invocation 2** (107.62 s): same pipeline, corrected assertion, passed. The admin route was still
  reported, findings were not suppressed, and no threat title echoed an instruction.

**Call accounting.** Each invocation makes exactly 2 *logical* model calls in the success path — one
architecture inference, one forced single-element threat batch — so **4 logical calls across both
invocations**. That is a count of intended call sites in the code, not a measured total: neither run
printed `CallUsage.attempts`, so a validation retry on either call (permitted once, per CLAUDE.md rule 5)
would raise the true provider-request count above 4, and nothing here can rule that out after the fact.

**Tokens and cost: unavailable.** Neither invocation printed or persisted `engine.usage`,
`architecture.usage`, or any `UsageLedger` total — the test only logged threat titles and severities. The
ledger was constructed fresh in-process each run and never surfaced. `writeDebugContext` /
`writeArchitectureDraft` only write when `NODE_ENV === "development"`, which `vitest run` does not set, so
no `.debug/` artifact exists for either run (`.debug/` still holds only the older `bezkoder` and
`try-architecture-bezkoder` runs). Exact input/output/cache tokens and `costUsd` for both invocations are
permanently lost. Fixed going forward: `tests/canary.live.test.ts` now accumulates and prints per-attempt
usage, stop reasons, token totals and estimated cost on both success and failure, so a future live run
cannot lose this again.

## 2026-09-22 — Adapter: evidence ordering, basis copy, and a deferred confidence-breakdown gap

Updated `src/client/adapter.ts` and `src/shared/labels.ts`; `tests/adapter.test.ts` grew from 51 to 61
tests. Schema and `src/shared/viewModel.ts` untouched.

- `BASIS_LABELS` copy changed: `evidence_backed` → "Confirmed by evidence",
  `assumption_dependent` → "Predicted from a missing control". Display text only, no type change.
- A threat card's evidence list now sorts gap evidence (a `ruleId` with an exact `"gap:"` prefix,
  the same test `src/server/scoring`'s `isGapEvidence` uses) after every positive finding, so a user
  scanning a card sees what was actually found before the missing-control reasoning. The predicate is
  duplicated locally in `adapter.ts` rather than imported from `@/server/scoring`, since `src/client`
  code does not pull in `src/server` modules. `Array.prototype.sort` is spec-stable, so relative order
  within each group (positive-first, gap-last) is preserved.
- **Deferred: no confidence-breakdown strings on the card.** `confidenceOf` in
  `src/server/scoring/index.ts` computes a human-readable `breakdown: string[]` (the "Prompt O" lines,
  e.g. `+0.35 code evidence`), but `assembleThreatModel` only keeps `scoreThreat(...).threat` from that
  result — the breakdown is discarded and never reaches `ThreatModel`. Surfacing it on a card would
  need either a new field on `ThreatSchema` (frozen, CLAUDE.md rule 1) or a new field on
  `ThreatCardData` in `src/shared/viewModel.ts`, both out of scope for this change (the latter
  explicitly instructed not to touch). Nothing was built for it; this is a scoping decision, not an
  oversight, and needs a separate decision on which contract absorbs the new field before it can be
  built.
- `highlightIds`, per-node `threatCount`/`maxSeverity`, the priority-then-risk-then-confidence sort
  behind `fixNow`, and the visible-only `filterOptions` were already correct against the existing test
  fixture; regression-tested but not changed.

**Verified.** `pnpm typecheck` 0, `pnpm test` 0 (42 files, 2,543 tests, 1 skipped — the gated live
canary), `pnpm lint --max-warnings 0` 0, `git diff --check` 0. 18 hand-written mutations applied over
`adapter.ts` and `labels.ts` (basis-label swap/collapse, three gap-classification variants, both
gap-last comparator directions, an accidental in-place sort of `model.threats`, a missing-evidence-id
crash, `highlightIds`/`threatCount`/`maxSeverity`/filter-option regressions, and two `fixNow`
boundary bugs); all 18 killed. One mutant (`fixNow` silently accepting `fix_soon`) survived on the
first pass because the existing fixture already has 6 `fix_now` candidates saturating the 5-slot cap,
masking the leak — added a small dedicated fixture with only 1 `fix_now` and 1 `fix_soon` threat so
the bug is directly observable, then reran clean.

## 2026-09-23 — Codebase-wide bug sweep (all modules, uncommitted on `feat/w-dashboard-ui`)

A review of every module in `src/` (reviewed in five areas in parallel, every finding reproduced with a
scratch script before it was fixed). Baseline was green (typecheck, 2,966 tests, lint, diff-check); only
`pnpm build` warned. 40 code defects fixed, plus one wrong doc comment and one untested hook. Every code
fix except the build annotation has a regression test that fails with the fix reverted and passes with it
restored. No `src/shared/schema` change. Not committed.

**Security (CLAUDE.md rule 3).**
- Unquoted config secrets reached the model: `POSTGRES_PASSWORD: ...` in compose YAML, `DB_PASSWORD=...`
  in `.properties`/`.env`-style files. New config-file-only `generic_secret` rule in `redactor.ts`
  (never applied by the path-less prompt guards, so `password: hashedPassword` in JS still passes).
  `classifier.ts` now also refuses `.envrc`, `.env-*`, `.env_*` and `*.env`; `.env.example` stays
  loaded (envNames reads it) with its values redacted.
- `redact()` now keeps the line count (a PEM block leaves its newlines behind the marker). Before, a
  52-line key shifted every later excerpt line and a gap past the redacted end crashed `buildContext`.
  `context.ts` also skips/clamps any excerpt window past end of file.
- Redaction markers are blanked before matching and `redact()` repeats to a fixed point, so a marker's
  colon can no longer turn `postgres://[REDACTED:...]svc@db` into a connection-string finding that
  failed the whole analysis.
- Three quadratic regexes (`role_override`, JWT, `generic_secret`) took 6-74 s on 200 KB of hostile
  input; now linear. A first `generic_secret` fix bounded the key length, which let a 100+ character
  identifier carry its value past redaction; caught in review and replaced by a linear key test.
- Rate limit keyed on the client-controlled first `X-Forwarded-For` hop (a fresh budget per request);
  now the rightmost hop, with expired windows swept and a 10,000-key cap. The concurrency check now runs
  before the rate limit, so a "server busy" 429 no longer spends the caller's hourly quota.
- `log()` checked the JSON-serialised line, where `"` became `\"`, so quoted secrets passed; each
  string is now checked before serialising. URL parser rejected `owner%2e` but not `%2e%2e`; refs are
  now decoded once.

**Pipeline and API.**
- Answering after the 10-minute job budget had elapsed discarded a finished, paid analysis as TIMEOUT;
  a resume now gets a fresh deadline from the job's own budget.
- Two overlapping answers POSTs both got 202 while one was silently dropped; the route now re-checks
  the stage after reading the body (409). Answers capped at 10, `questionId` at 64 chars; grouping was
  quadratic (60k answers ~3 s).
- An omitted, conflicting or invalid answer skipped the cautious default entirely, making the result
  look safer than an explicit skip; such questions now take the skip path with a limitation.
- Scoring gap floor summed certainties in floating point (0.7 + 0.1 < 0.8); now integer thousandths.
  Not reachable with today's certainties. `timeoutMs` above 2^31-1 (setTimeout clamps it to 1 ms) is
  rejected, in `createAnalysis` and in `scripts/try-pipeline-lib.ts`.

**AI stage.**
- A threat could cite evidence offered only to another element of the same batch and be scored
  evidence-backed/fix_now; citations are now checked per element.
- The questions schema sent `minItems: 2`/`maxItems: 4`, which the structured-output endpoint does not
  support (the SDK's own transform strips them); `toApiSchema` now strips them. The questions call
  (claude-sonnet-5, 4,000 max tokens) ran adaptive thinking by default; now disabled like the
  architecture and threat calls.

**Detectors and scanners.** Commented-out routes and comments inside route arguments produced 0.9
`authn_missing` gaps; a regex such as `/\/*$/` opened a fake block comment; one path-scoped guard
(`app.use("/admin", requireAuth)`) or a rate limiter named `authLimiter` suppressed every authn gap in
the repo; `export { handler as GET }` and `export const POST = withAuth(...)` read as unauthenticated;
`vercel.json`/`_headers` header config was invisible; `zod/v4` imports did not count as validation;
Express 5 got the async error-handling gap. OSV: `>X` was read as `>=X` (and the test asserted it),
npm aliases and git deps were queried under the wrong package, a parent lockfile was applied to a
non-workspace subproject, an open-ended affected range still reported a fix version, manifest line
numbers pointed at the first occurrence of the name, and a CVSS value like `A:constructor` gave NaN.

**Dashboard.** A lost answers response stranded the user on the question panel (every resubmit 409'd,
no poll); the "Fix now" tile showed the top-5 list length instead of the total; clearing the component
filter left the graph dimmed on the old node; a flow id equal to a component id leaked into the
component filter. `tests/useAnalysisHook.test.tsx` now exercises the real polling hook.

**Build.** `pnpm build` warned that `writeArchitectureDraft`'s runtime `.debug` path made Turbopack trace
the whole project (`.debug` dumps, `.env.local`) into the route bundles; annotated
`/*turbopackIgnore: true*/` in `architecture.ts` and `context.ts`.

**Decisions and deviations.**
- A GitHub 5xx or network error on one file now fails the load (it used to drop the file silently and
  count it as ignored). `githubClient.ts` has no retry, so one transient 502 now fails the analysis.
  "Not text" is recognised by exact message; a typed error in `githubClient.ts` would be sturdier.
- The Next `middleware.ts` auth heuristic is unchanged: a matcher-aware rule would flood apps using the
  standard catch-all matcher with 0.9 false positives.
- `basisCounts` behaviour unchanged (it counts hidden threats, as the UI's label says); its doc comment
  was corrected.
- An omitted question's new limitation text is new wording; an explicit skip still adds none.

**Left for a decision (not changed).**
- `callStructured` does not retry a `max_tokens`-truncated reply; CLAUDE.md rule 5 says retry once, and
  `src/server/ai/README.md` and `architecture.ts` say it does. Code, comment and test agree on no retry.
- `basisOf` and the gap floor treat `inference` evidence as non-positive, stricter than rule 2's
  literal "ruleId does not start with gap:". Not reachable today; `tests/scoring.test.ts` pins it.

**Verified.** `pnpm typecheck` 0; `pnpm test` 0 twice (60 files, 3,176 tests, 1 skipped, the gated live
canary); `pnpm lint` 0 with 0 warning lines; `git diff --check` 0; `pnpm build` 0 with no warnings. The
new hook test passed 15 isolated runs and 5 under CPU load. No live GitHub, Semgrep, OSV or Anthropic
call was made, so the redactor, detector and questions-schema changes are unverified against a real
repository and the real API.

## 2026-09-23 — Descriptive error codes (schema change, authorised)

The user asked for more descriptive error codes and chose, when asked, to add codes to the frozen
`ErrorCodeSchema` (CLAUDE.md rule 1 exception, given in chat) rather than only reword messages or rename
the existing codes. The seven original codes stay; eleven are added; each old code is narrowed to one
meaning.

**Why.** `AI_FAILURE` covered about 15 situations (Claude errors, refusals, invalid output, GitHub 5xx and
network errors, output-check rejections, a malformed answers body, a 409), all shown as "Analysis failed".
`RATE_LIMITED` covered our 5-per-hour limit, the 2-analysis concurrency cap and GitHub/Claude 429s, all
shown as "We're being rate limited right now". `TIMEOUT` also covered the browser losing its connection.
`INVALID_URL` was also sent for a non-JSON body and a bad `analysisLevel`.

**Codes.** Added `INVALID_REQUEST`, `NOT_AWAITING_ANSWERS`, `SERVER_BUSY`, `UPSTREAM_RATE_LIMITED`,
`GITHUB_UNAVAILABLE`, `MODEL_REFUSED`, `MODEL_OUTPUT_INVALID`, `OUTPUT_REJECTED`, `SECRET_BLOCKED` and
`NETWORK_ERROR` (client only). `RATE_LIMITED` is now only our own per-address limit; `AI_FAILURE` is the
catch-all. Every code has its own title and message in `ERROR_COPY`; the routes add the configured
numbers to `RATE_LIMITED` and `SERVER_BUSY` messages. `AnalysisError.code` in `src/shared/viewModel.ts`
now also admits the HTTP-only `"NOT_FOUND"`, which the client's unreadable-404 fallback now uses instead
of `AI_FAILURE`. Code table in `src/app/api/README.md`.

**Where they come from.** `mcp/base.ts` maps an upstream 429 to `UPSTREAM_RATE_LIMITED`, and an
unclassified MCP failure to the client's own `unclassified` code (`GITHUB_UNAVAILABLE` for GitHub,
`AI_FAILURE` for Semgrep, whose failures only degrade the run). `githubClient.ts`'s REST fallback and
`loader.ts`'s not-text check key on `GITHUB_UNAVAILABLE` where they keyed on `AI_FAILURE`. `claude.ts`:
refusal `MODEL_REFUSED`; truncation, second validation failure and the response-size cap
`MODEL_OUTPUT_INVALID`; persistent 429 `UPSTREAM_RATE_LIMITED`. `pipeline.ts`: `SecretLeakError`
`SECRET_BLOCKED`; output-check rejection `OUTPUT_REJECTED`. Retryable: `RATE_LIMITED`, `AI_FAILURE`,
`TIMEOUT`, `SERVER_BUSY`, `UPSTREAM_RATE_LIMITED`, `GITHUB_UNAVAILABLE`, `MODEL_OUTPUT_INVALID`,
`NETWORK_ERROR`.

**Decisions.**
- `SERVER_BUSY` stays HTTP 429 (not 503) so no client handling changes.
- A single Claude or MCP call timing out stays `TIMEOUT` (a time budget ran out), not `AI_FAILURE`.
- Assembled/finalized/answered model validation failures stay `AI_FAILURE`: they indicate our own bug,
  not a bad model reply, so `MODEL_OUTPUT_INVALID`'s "trying again often works" would mislead.
- `OUTPUT_REJECTED`, `MODEL_REFUSED` and `SECRET_BLOCKED` are not retryable: the same repository is
  likely to fail the same way, and each retry is a paid run.

**Polling race found while verifying.** `tests/useAnalysisHook.test.tsx` failed intermittently in full
runs (4 GETs where 3 were expected). Cause: the loop rescheduled after every response and relied on
React's commit to cancel it, so a commit landing later than the poll interval let one more request out
after a terminal response. The loop now decides from the response itself (`pollsAfter`, which runs the
reducer on a nominal polling state and asks `shouldPoll`, so it cannot disagree with the UI). A new test
counts the loop's own `setTimeout` calls; it fails 5/5 with the fix removed and passes with it.

**Verified.** 21 mutations (every new mapping, both GitHub fallback sites, the retryable set, the client
codes, a duplicated title) each failed at least one test and were restored byte-identical.
`pnpm typecheck` 0; `pnpm test` 0 three times (60 files, 3,194 tests, 1 skipped); `pnpm lint` 0 with 0
warning lines; `git diff --check` 0; `pnpm build` 0 with no warnings. No live API call was made, so the
new copy has not been seen in the running app.

## 2026-09-23 — Truncation retry (rule 5) and inference wording (rule 2)

Two decisions from the user, both left open by the bug sweep.

**A reply cut off at max_tokens now gets rule 5's one retry.** Before, `callStructured` failed at once on
`stop_reason: "max_tokens"`, calling truncation deterministic; CLAUDE.md, `src/server/ai/README.md` and
`architecture.ts` all said the retry happened. Now the truncation is the validation failure: the retry
carries the existing "cut off at max_tokens; return the complete JSON, more briefly" issue, and gets:
- **A larger output budget.** `truncationRetryTokens`: twice the first budget, capped at
  `NON_STREAMING_MAX_TOKENS` (21,333). The cap is the SDK's own: it refuses a non-streaming request it
  expects to run past 10 minutes at 128,000 tokens/hour (`calculateNonstreamingTimeout` in the installed
  `@anthropic-ai/sdk`). Architecture and threat calls (12,000) retry at 21,333; questions (4,000) at
  8,000. `callStructured` now rejects a first budget at or above the cap, so the retry always gets
  strictly more.
- **Time to use it.** The whole-call deadline used to cover both attempts, and a cut-off reply had
  already spent most of it: at the ~85 tokens/s recorded in `threatPrompt.ts`, 12,000 tokens take ~140 s
  of a threat call's 300 s, and 21,333 more would take ~250 s. So the retry gets a fresh deadline:
  the first attempt's measured time scaled to the new budget, plus 25%, and never less than the call's
  own deadline (`truncationRetryTimeoutMs`). `ClaudeDeps` gained an injectable `now` for this. The
  pipeline's 10-minute budget still bounds the whole run, so a cutoff late in a large run can still end
  in TIMEOUT.
A second cutoff ends the call with `MODEL_OUTPUT_INVALID`, naming the retry's limit; a truncation after
an ordinary validation failure gets no second retry. CLAUDE.md rule 5 now says this.

**Inference evidence is a conclusion, not direct supporting evidence.** Behaviour unchanged, now
explicit: it never makes a threat `evidence_backed` (even with a non-`gap:` ruleId), is never a second
independent source, and neither blocks nor counts toward the gap floor, so a near-certain gap plus an
inference still gets 0.40, an inference alone gets 0.20, and inferences add no certainty toward 0.8.
CLAUDE.md rule 2's wording, `scoring/index.ts` comments and `scoring/README.md` say so;
`tests/scoring.test.ts` pins each case.

**Verified.** 10 mutations (budget not raised, old deadline kept, margin dropped, deadline allowed to
shrink, cap removed, first-budget check removed, partial value accepted, truncation not retried,
inference counted as positive, inference counted as supporting) each failed at least one test and were
restored byte-identical. `pnpm typecheck` 0; `pnpm test` 0 twice (60 files, 3,204 tests, 1 skipped);
`pnpm lint` 0 with 0 warning lines; `git diff --check` 0; `pnpm build` 0 with no warnings. Not verified
live: no real call was made, so the retry's pacing estimate is untested against the API.

## 2026-09-24 — Questions engine: Prompt M's original value formula, component linking, fact drops

Reworked `src/server/questions` to match the original Prompt M spec, which the first build (commit
9d54f5e) had approximated rather than implemented exactly.

**Split `index.ts` into `engine.ts` (pure) + `index.ts` (the model-calling orchestrator).** `engine.ts`
is new: `linkUnknowns`, `answeredByFacts`, the value formula, `rankCandidates`, `selectCandidates`, and
the unchanged option-effects/cautious-default machinery. `index.ts` re-exports everything so no caller's
import path changes.

**The value formula is now exact:** `value = maxSeverityWeight * uncertainty * log2(1 + affectedCount)`,
weights critical 4 / high 3 / medium 2 / low 1, kept at raw value >= `MIN_VALUE` (1.5). The old formula
(weights 0.2-1.0, a `reachWeightOf` ratio normalized by total threat count, a 1.5x `GAP_BOOST`, clamped
to [0, 1], cut at 0.15) is gone. `DeveloperQuestion.valueScore` (frozen 0..1, CLAUDE.md rule 1) is now
`toStoredValueScore(raw) = min(1, raw / 8)` rather than the ranking value itself.

**An unknown now also links to a threat by shared component**, not only `dependsOnUnknownIds`
(`linkUnknowns`). This widens which unknowns are worth asking about, but an applied answer still only
re-scores the `dependsOnUnknownIds` threats (`QuestionEffects.appliesToThreatIds`, new field) -- a
component-only link makes the unknown worth asking without letting its answer touch an unrelated threat
that merely shares a component. `answers.ts` now folds deltas into `effect.appliesToThreatIds`, not
`question.affectedThreatIds`.

**Unknowns the repository's own facts already answer are dropped** (`answeredByFacts`): narrow today --
an exposure-worded unknown whose every affected component maps by name to a Compose service with no
published host port. `SelectQuestionsInput` gained optional `components`/`deployment`; `pipeline.ts`
passes them and logs `skippedReasons` at debug level.

**Every drop is now structured**, not just prose limitations: `SelectQuestionsResult.skippedReasons`,
one entry per unknown considered and not asked about, with a `SkipReason` (`no_affected_threats`,
`answered_by_facts`, `below_threshold`, `over_cap`, `no_usable_draft`, `no_cautious_default`).

Prompt M (`prompts/questions.v1.md`) gained explicit "answerable in under 10 seconds" and "never ask
what a fact already answers" wording; both were already enforced by code (the model still returns
`optionMeanings`, not deltas -- CLAUDE.md rule 2 unchanged).

**Verified.** `pnpm typecheck` 0; `pnpm test` 0 (63 files, 3,265 tests, 1 skipped); `pnpm lint` 0;
`pnpm build` 0 with no warnings; `git diff --check` 0. Two mutations (MIN_VALUE 1.5 -> 1.6; dropping the
component-link branch in `linkUnknowns`) each broke at least one test and were restored byte-identical.
Verified live: the user exercised the question-and-answer flow in the browser against this branch.
