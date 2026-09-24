# server/mcp

MCP client wrapper: tool allowlist, timeouts, response size caps, read-only config.
All MCP calls go through here (CLAUDE.md rule 4).

`githubClient.ts` talks to `ghcr.io/github/github-mcp-server` over stdio, with
`GITHUB_READ_ONLY=1` and `GITHUB_TOOLSETS=repos,git`.

Discovery (`pnpm try scripts/list-github-tools.ts`) found two gaps in the server's
tool surface, so two calls do not go through MCP:

| Function | Path |
|---|---|
| `getFileContent` | MCP `get_file_contents` (body is in a `resource` block), falling back to the REST Contents API |
| `listTree` | MCP `get_repository_tree`, falling back to the REST tree API |
| `getRepoMetadata` | REST only: no toolset exposes repository metadata |

Both `listTree` and `getRepoMetadata` report which path ran in `source`.

## `get_file_contents` result shape

Captured live with `pnpm try scripts/inspect-github-file.ts <owner/repo> <path>`. The
result has **two** content blocks, and the file body is in the second:

```
[ { type: "text",     text: "successfully downloaded text file (SHA: …)" },
  { type: "resource", resource: { uri, mimeType: "text/plain; charset=utf-8", text: "<the file>" } } ]
```

The text block is only a status line. Reading text blocks alone returns that status line
as if it were the file. Binary files are expected as `resource.blob` (base64) and are
refused, as is any content containing a NUL byte.
