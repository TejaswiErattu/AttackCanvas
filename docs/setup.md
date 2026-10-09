# Setup and pinned MCP versions

Environment variables, external tools, and exactly which versions of them AttackCanvas is
built and tested against (CLAUDE.md rule 4: read-only MCP configuration; Prompt U Part 2:
MCP hardening).

## Environment

Copy `.env.example` to `.env.local` (gitignored) and fill in:

| Variable | Used by | Notes |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | `src/server/ai/claude.ts` | Never logged; `assertNoSecrets` runs on every outbound call. |
| `GITHUB_PERSONAL_ACCESS_TOKEN` | `src/server/mcp/githubClient.ts` | **Fine-grained token, public read access only, no write scopes.** Read from the environment and handed to the MCP server's child process through its environment only -- never argv, never logged. |
| `ATTACKCANVAS_MODEL_PROFILE` | `src/server/ai/models.ts` | `dev` or `demo`; picks which Claude model each stage calls. Unset or blank means `dev`; any other value throws on the first model call. Renamed with the project: the variable under the previous project prefix is no longer read, so a machine that still sets only the old name silently runs `dev`. Set this one on the demo machine. |
| `ATTACKCANVAS_MAX_RUN_USD` | `src/server/ai/spendGuard.ts` | Optional. Most one analysis may spend, in USD (default 6). See "Working without paying" below. |
| `ATTACKCANVAS_ALLOWED_OWNERS` | `src/server/http/ownerAllowlist.ts` | Optional. Comma-separated GitHub owners (`acme,widgets-inc`); a request for any other owner gets 403 `OWNER_NOT_ALLOWED`. Unset or blank means every owner is allowed. A set value with no valid owner refuses everyone. See "Responsible use" in `docs/security-design.md`. |

## Working without paying

Model calls are the only thing that costs money, and almost all of them happen in four
places: the architecture call, the STRIDE batches, the questions call and, when you run one,
an evaluation. These switches avoid paying for them again. All but the cap are development
only and are ignored when `NODE_ENV=production`. Details are in `scripts/README.md` under the
same heading; the cap is explained in `docs/cost.md`.

| Variable | What it does | Where it lives |
| --- | --- | --- |
| `ATTACKCANVAS_REPLAY_DIR` | `POST /api/analyze` serves `<dir>/<owner>__<repo>.json` if it validates as a ThreatModel, with no GitHub or model call, and the dashboard shows a "Replayed" pill. `fixtures/replay` holds the NodeGoat one. | `src/server/analysis/replay.ts` |
| `ATTACKCANVAS_MODEL_CACHE=1` | A repeated model call (same model, system text, messages and output schema) is served from `.cache/model/` at zero cost. A call that failed validation is never saved. A cache hit needs no API key. | `src/server/ai/modelCache.ts` |
| `ATTACKCANVAS_CHECKPOINT_DIR` | A run saves its load, detect, scanners and architecture stages. Point it inside `.cache/`: the files hold raw repository content. Enables `replay-stage.ts` and `eval/mini.ts`. | `src/server/analysis/checkpoints.ts` |
| `ATTACKCANVAS_MAX_RUN_USD` | **Not development only.** The most one analysis may spend, default 6. The next model call is refused and the job fails with `SPEND_CAP`. A guard against a surprise, not a way to avoid paying. | `src/server/ai/spendGuard.ts` |
| `ATTACKCANVAS_MODEL_PROFILE=dev` | Cheaper models at every level (see `docs/cost.md`). Not free. | `src/server/ai/models.ts` |

### Commands that never call a model

| Command | What it does | Needs |
| --- | --- | --- |
| `pnpm typecheck`, `pnpm test`, `pnpm lint` | The checks. Tests use fake model clients. | nothing |
| `pnpm bench` | Detector and Semgrep recall on the seeded repositories. | optional local `semgrep` |
| `ATTACKCANVAS_REPLAY_DIR=fixtures/replay pnpm dev` | The whole app on a saved NodeGoat result. | nothing |
| `pnpm try scripts/eval/label.ts`, `gapSheet.ts`, `sampleSecond.ts` | Build the hand-label sheets from a saved result. | nothing |
| `pnpm try scripts/eval/score.ts`, `consistency.ts` | Score labels and compare saved runs. | nothing |
| `pnpm try scripts/eval/mini.ts <name> <ids> --dry-run` | Show which STRIDE batches the mini benchmark would run. | saved checkpoints |
| `pnpm try scripts/verify-threat-payloads.ts <owner>/<repo>` | Render the threat prompts and check for credentials. | GitHub token, Docker |
| `pnpm try scripts/try-detect.ts`, `try-gaps.ts`, `try-semgrep.ts` | Run the detectors or Semgrep on a repository. | GitHub token, Docker, `semgrep` |
| `pnpm try scripts/export-nodegoat-sample.ts` | Re-export the saved NodeGoat sample. | nothing |

Commands that **can** pay: `try-pipeline.ts`, `try-architecture.ts`, `try-threats.ts`,
`try-claude.ts`, `eval/run.ts`, `replay-stage.ts` and `eval/mini.ts` (without
`--dry-run`). The last two cost nothing once their calls are in the model cache.

## GitHub MCP server

Run over stdio via Docker (`src/server/mcp/githubClient.ts`):

```
docker run -i --rm \
  -e GITHUB_PERSONAL_ACCESS_TOKEN -e GITHUB_TOOLSETS -e GITHUB_READ_ONLY \
  ghcr.io/github/github-mcp-server:v1.12.2@sha256:508a0857ec762b1ab1cece29193345b501fab1dd9d1228a7b617062954cecac6
```

- **Pinned image: tag `v1.12.2` plus digest `sha256:508a0857ec762b1ab1cece29193345b501fab1dd9d1228a7b617062954cecac6`.** The tag alone is
  mutable (the registry can re-point it), so the digest is what makes the pin real:
  Docker runs exactly those bytes or fails to resolve the image. Not `:latest` -- an unpinned tag lets the
  maintainer change the server's tool surface or behavior out from under
  `ALLOWED_TOOLS` at any time, with no signal that anything changed. `v1.12.2` is the
  exact version this client's allowlist and response handling were verified against
  (`scripts/list-github-tools.ts`; see `docs/build-log.md`'s 2026-09-19 entry and
  `tests/githubResponses.ts`, whose fixtures were captured from that same version).
  The pin has exactly **one** authoritative definition: `IMAGE`, exported from
  `src/server/mcp/githubClient.ts`. `scripts/list-github-tools.ts` imports that
  constant rather than repeating the string, so the discovery script and the production
  client cannot drift apart. `tests/githubClient.connection.test.ts` asserts all three
  properties: the value carries an explicit tag (not bare, not `:latest`) and a
  `@sha256:` digest, the script
  contains no hardcoded `ghcr.io/...` literal, and the script imports `IMAGE` from the
  client.
- **Bumping it is a deliberate action**, documented at the `IMAGE` constant: pull the
  new tag, read its digest with `docker image inspect <tag> --format '{{json .RepoDigests}}'`,
  re-run `scripts/list-github-tools.ts` against it, confirm `ALLOWED_TOOLS` still
  matches what the server exposes, then update the constant, the connection test, and
  this file together.
- **Read-only, minimal toolset.** `GITHUB_READ_ONLY=1` and
  `GITHUB_TOOLSETS=repos,git` (the `git` toolset is needed only for
  `get_repository_tree`; `repos` alone has no tree tool). Verified by
  `tests/githubClient.connection.test.ts` ("pins read-only mode and the toolsets that
  expose the tree tool").
- **Tool allowlist.** `ALLOWED_TOOLS` in `githubClient.ts` names exactly 6 read tools
  (`get_repository_tree`, `get_file_contents`, `list_branches`, `list_tags`,
  `list_commits`, `get_commit`) out of the far larger surface the server exposes.
  `callToolResultWith` (`src/server/mcp/base.ts`) refuses any other tool name before
  ever calling it. Verified by `tests/githubClient.test.ts` (every allowed tool
  succeeds; a disallowed one throws `/not in ALLOWED_TOOLS/`).
- **Response size cap.** `MAX_RESPONSE_BYTES = 1 MiB`, enforced while a response's text
  is accumulated (`extractText`/`extractResources` in `base.ts`), so an oversized
  payload is rejected rather than assembled in memory. Verified by
  `tests/githubClient.test.ts` ("reports an oversized response as REPO_TOO_LARGE").

## Semgrep MCP server

Run locally as `semgrep mcp` (`src/server/mcp/semgrepClient.ts`) -- no Docker image,
no network call, no credential.

- **Tested version: Semgrep CLI `1.176.0`. Not enforced in code:** the client runs
  whatever `semgrep` is first on `PATH` and never checks its version, so keeping it at
  1.176.0 is up to whoever sets up the machine. Install with `pipx install semgrep==1.176.0`
  (or `pip install semgrep==1.176.0`; Homebrew's `semgrep` formula is also 1.176.0 at the
  time of writing, but Homebrew upgrades it on `brew upgrade`).
  This is the version `scripts/list-semgrep-tools.ts` discovery ran against (MCP server
  `v1.29.0`; `docs/build-log.md`'s "GitHub MCP client" entry's sibling Semgrep entry) and
  the version this client's parser (`tests/semgrepResponses.ts`, captured live) was
  built against. An untested newer Semgrep can change a rule's output shape (message
  wording, `cwe`/`owasp` tag format) under the parser without any code here changing.
  Confirm your installed version before relying on this client:

  ```
  semgrep --version
  ```

  If it does not print `1.176.0`, either pin it to that version or re-run
  `scripts/list-semgrep-tools.ts` and `scripts/try-semgrep.ts` against the new one and
  update `tests/semgrepResponses.ts` and this file together. This is weaker than the
  GitHub image above, which is pinned by digest and cannot drift.
- **Tool allowlist.** `ALLOWED_TOOLS` names exactly 2 tools
  (`semgrep_scan_with_custom_rule`, `get_supported_languages`) out of the server's
  larger surface, each excluded tool for a written reason in `semgrepClient.ts`'s
  header comment (`semgrep_scan` takes a path and would bypass redaction;
  `semgrep_findings` sends repo names to the Semgrep Platform API; etc.). Verified by
  `tests/semgrepClient.test.ts` (every allowed tool succeeds; anything else is asserted
  absent from the allowlist).
- **Response size cap.** `MAX_RESPONSE_BYTES = 4 MiB`. Verified by
  `tests/semgrepClient.test.ts` (an oversized response is reported `REPO_TOO_LARGE`).
- **Content, not paths.** `semgrep_scan_with_custom_rule` is the only allowed scan tool
  because it takes file contents inline; the excluded `semgrep_scan` takes absolute
  paths and reads them off disk, which would scan un-redacted content. Repository
  content is redacted (`src/server/security/redactor.ts`) before it ever reaches this
  client.

## Confirmed present (this file's own audit, Prompt U Part 2 item 1)

| Client | Allowlist | Response cap | Read-only config |
| --- | --- | --- | --- |
| GitHub | `ALLOWED_TOOLS`, 6 tools, `src/server/mcp/githubClient.ts` | `MAX_RESPONSE_BYTES = 1 MiB` | `GITHUB_READ_ONLY=1` |
| Semgrep | `ALLOWED_TOOLS`, 2 tools, `src/server/mcp/semgrepClient.ts` | `MAX_RESPONSE_BYTES = 4 MiB` | No credential; no write-capable tool is in the allowlist |

Both allowlists are enforced by the single choke point `callToolResultWith` in
`src/server/mcp/base.ts` (CLAUDE.md rule 4), not re-implemented per client.
