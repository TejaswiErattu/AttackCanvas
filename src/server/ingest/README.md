# server/ingest

Loads a public GitHub repo (via MCP), filters files and redacts secrets.

## `urlParser.ts`

Validates and parses GitHub URLs and shorthand references, extracting owner, repo, and optional branch ref.

Accepts: `https://github.com/owner/repo`, `github.com/owner/repo`, `owner/repo` shorthand, http/https,
www.github.com, `/tree/branch-name`, query strings and fragments (stripped), `.git` suffix (stripped).

Rejects: empty, >500 chars, credentials, other hosts (gist.github.com, etc.), invalid owner/repo patterns,
path traversal, encoded dots, repo="." or ".." or starting with "." or "-".

## `classifier.ts`

`classifyPath(path, size?)` → `{ tier: "high" | "medium" | "low" | "ignore", reason }`. Pure, path and size only.
Precedence, first match wins: ignore; lockfile (medium, reason `"dependencies"`: OSV only, never sent to a
model); low (tests, docs, examples, scripts); high; medium; otherwise low.
`.env` and `.env.*` (except `.env.example`) are always `ignore`, so the loader never fetches them.
Files over 200 KB are ignored. The one exception is `package-lock.json`, which the dependency scanner reads and
which is allowed up to 1 MiB (the GitHub client's response cap); other lockfiles keep the 200 KB limit.

## `loader.ts`

`loadRepository(owner, repo, ref?)` → `{ summary, files, skipped: { ignored, overLimit }, truncated }`.
Classifies the tree, fetches at most 300 files (high > medium > low) with concurrency 5, then keeps files in
that order while their actual UTF-8 size fits in 2 MiB. Throws `IngestError` with `REPO_TOO_LARGE` (tree over
20,000 entries) or `INSUFFICIENT_CODE` (fewer than 3 source files; lockfiles do not count). Use
`modelBoundFiles(files)` before sending anything to a model. Returned content is **not yet redacted**.
