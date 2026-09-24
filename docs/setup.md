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
