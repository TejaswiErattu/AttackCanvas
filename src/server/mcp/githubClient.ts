import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { ErrorCode } from "@/shared/schema";
import {
  callToolResultWith as callToolResultBase,
  createStdioConnection,
  extractResources as extractResourcesBase,
  extractText as extractTextBase,
  mapErrorCode,
  toTypedError as toTypedErrorBase,
  type ErrorFactory,
  type ResourceContent,
  type SafeCallOptions,
  type ToolCaller,
  type ToolOutput,
} from "@/server/mcp/base";

export { mapErrorCode };
export type { ResourceContent, ToolCaller, ToolOutput };

/**
 * Read-only GitHub access for the ingest stage. Every MCP call in AttackCanvas goes
 * through callTool() here (CLAUDE.md rule 4): one allowlist, one timeout, one size
 * cap, one place that maps upstream failures to a typed ErrorCode. The wrapper itself
 * lives in src/server/mcp/base.ts and is shared with the Semgrep client; this module
 * supplies the GitHub-specific caps, allowlist, errors and transport.
 *
 * Discovery (scripts/list-github-tools.ts, server v1.12.2) found that the "repos"
 * toolset has no tree tool and that no toolset has a repo-metadata tool, so:
 *   - listTree prefers the MCP tool get_repository_tree (toolset "git") and falls
 *     back to the REST tree API;
 *   - getRepoMetadata is REST only.
 * Both report which path they used in `source`.
 *
 * The token is read from the environment and handed to the child process through its
 * environment only. It never appears in argv, in a log line, or in an error message.
 */

/**
 * Pinned by tag AND digest, not `:latest` (CLAUDE.md Prompt U Part 2: MCP hardening).
 * A tag alone is mutable: the registry can re-point `v1.12.2` at different bytes, and
 * Docker would run them. With `@sha256:...` Docker runs exactly these bytes or fails to
 * resolve the image. The digest is the local v1.12.2 image (built 2026-09-16) that the
 * 2026-09-19 discovery ran against. An unpinned tag
 * lets the maintainer change the server's tool surface, behavior, or base image out
 * from under this allowlist at any time -- exactly the "MCP tool misuse" and
 * supply-chain risk docs/security-design.md tracks. Pinned to v1.12.2, the version
 * this client's allowlist and response handling were verified against
 * (scripts/list-github-tools.ts, docs/build-log.md's 2026-09-19 entry). Bumping this
 * is a deliberate action: pull the new tag, read its digest with
 * `docker image inspect <tag> --format '{{json .RepoDigests}}'`, re-run
 * scripts/list-github-tools.ts against it first, confirm ALLOWED_TOOLS below still matches what the server exposes, then
 * update this constant, tests/githubClient.connection.test.ts, and docs/setup.md
 * together.
 */
export const IMAGE =
  "ghcr.io/github/github-mcp-server:v1.12.2@sha256:508a0857ec762b1ab1cece29193345b501fab1dd9d1228a7b617062954cecac6";

/** "git" is needed for get_repository_tree; "repos" alone does not expose it. */
const TOOLSETS = "repos,git";

export const TIMEOUT_MS = 60_000;
export const MAX_RESPONSE_BYTES = 1024 * 1024;

const GITHUB_API = "https://api.github.com";

/**
 * Read-only tools this client may call, chosen from the discovery output. It is
 * deliberately narrower than the server's read surface: adding a tool here is a
 * conscious decision, not a side effect of enabling a toolset.
 */
export const ALLOWED_TOOLS = [
  "get_repository_tree",
  "get_file_contents",
  "list_branches",
  "list_tags",
  "list_commits",
  "get_commit",
] as const;

export type AllowedTool = (typeof ALLOWED_TOOLS)[number];

const ALLOWED = new Set<string>(ALLOWED_TOOLS);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * An upstream failure a caller can surface to the user, carrying a schema ErrorCode.
 */
export class GitHubMcpError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "GitHubMcpError";
  }
}

/**
 * A bug or a misconfigured environment: a tool outside the allowlist, or a missing
 * token. Never shown to a user, and deliberately not carrying an ErrorCode, because
 * no user-facing code describes "we called the wrong tool".
 */
export class GitHubClientConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GitHubClientConfigError";
  }
}

/**
 * How the shared wrapper builds this client's errors, so a failure raised inside
 * base.ts is still a GitHubMcpError to everyone catching one.
 */
const errors: ErrorFactory = {
  tool: (code, message, options) => new GitHubMcpError(code, message, options),
  config: (message) => new GitHubClientConfigError(message),
  unclassified: "GITHUB_UNAVAILABLE",
};

const isTyped = (cause: unknown): boolean => cause instanceof GitHubMcpError;
const isConfigError = (cause: unknown): boolean => cause instanceof GitHubClientConfigError;

/** Re-throws anything as a typed error, preserving an already-typed code. */
function toTypedError(cause: unknown, context: string): Error {
  return toTypedErrorBase(cause, context, errors, isTyped);
}

// ---------------------------------------------------------------------------
// Response handling
// ---------------------------------------------------------------------------

/**
 * Concatenates the "text" items of an MCP result, enforcing the size cap as it goes
 * so an oversized response is rejected rather than assembled.
 */
export function extractText(content: unknown): string {
  return extractTextBase(content, MAX_RESPONSE_BYTES, errors);
}

/**
 * Collects the resource blocks of an MCP result. Each payload is capped on its own, so
 * a file of exactly the cap is accepted regardless of the status text beside it.
 */
export function extractResources(content: unknown): ResourceContent[] {
  return extractResourcesBase(content, MAX_RESPONSE_BYTES, errors);
}

const DOWNLOAD_STATUS = /^successfully downloaded [a-z]+ file(?: \(SHA: [0-9a-f]+\))?\.?$/i;

/**
 * True for the status line get_file_contents puts in its text block, e.g.
 * "successfully downloaded text file (SHA: 980a0d5…)". It describes the download; it is
 * never the file's content. Anchored to the whole string so a real file that merely
 * begins with those words is not mistaken for it.
 */
export function isDownloadStatusMessage(text: string): boolean {
  return DOWNLOAD_STATUS.test(text.trim());
}

/** Decodes file bytes as UTF-8 text, refusing binary content (any NUL byte). */
function decodeText(bytes: Buffer, label: string): string {
  if (bytes.includes(0)) {
    throw new GitHubMcpError("GITHUB_UNAVAILABLE", `${label} looks binary, not text`);
  }
  return bytes.toString("utf8");
}

/** The file body carried by resource blocks, or undefined if there is none. */
export function bodyFromResources(
  resources: ResourceContent[],
  label: string,
): string | undefined {
  for (const resource of resources) {
    if (resource.text !== undefined) return resource.text;
    if (resource.blob !== undefined) {
      return decodeText(Buffer.from(resource.blob, "base64"), label);
    }
  }
  return undefined;
}

function safeCallOptions(timeoutMs: number): SafeCallOptions {
  return {
    allowed: ALLOWED,
    allowedLabel: `ALLOWED_TOOLS (${ALLOWED_TOOLS.join(", ")})`,
    errors,
    isTyped,
    maxResponseBytes: MAX_RESPONSE_BYTES,
    timeoutMs,
  };
}

/**
 * The single choke point for MCP calls: allowlist, timeout, size cap, typed errors.
 * Exported with an explicit client so it can be unit-tested without Docker. Returns the
 * text blocks and the resource blocks separately, because tools such as
 * get_file_contents put their payload in a resource block.
 */
export async function callToolResultWith(
  client: ToolCaller,
  name: string,
  args: Record<string, unknown> = {},
  timeoutMs: number = TIMEOUT_MS,
): Promise<ToolOutput> {
  return callToolResultBase(client, name, args, safeCallOptions(timeoutMs));
}

/** callToolResultWith(), keeping only the text blocks. */
export async function callToolWith(
  client: ToolCaller,
  name: string,
  args: Record<string, unknown> = {},
  timeoutMs: number = TIMEOUT_MS,
): Promise<string> {
  return (await callToolResultWith(client, name, args, timeoutMs)).text;
}

// ---------------------------------------------------------------------------
// Connection (lazy singleton)
// ---------------------------------------------------------------------------

function readToken(): string {
  const token = process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
  if (!token) {
    throw new GitHubClientConfigError(
      "GITHUB_PERSONAL_ACCESS_TOKEN is not set. Put it in .env.local (gitignored).",
    );
  }
  return token;
}

const DOCKER_ARGS = [
  "run",
  "-i",
  "--rm",
  "-e",
  "GITHUB_PERSONAL_ACCESS_TOKEN",
  "-e",
  "GITHUB_TOOLSETS",
  "-e",
  "GITHUB_READ_ONLY",
  IMAGE,
];

/**
 * How to start the server. Locally: `docker run` of the pinned IMAGE. On a host with no
 * Docker (the production container), GITHUB_MCP_BINARY names the server binary copied
 * out of that same pinned image (see Dockerfile), run with the image's own `stdio`
 * command. The read-only env below is identical on both paths.
 */
export function launchCommand(env: Partial<Record<string, string>>): { command: string; args: string[] } {
  const binary = env.GITHUB_MCP_BINARY?.trim();
  if (binary) return { command: binary, args: ["stdio"] };
  return { command: "docker", args: [...DOCKER_ARGS] };
}

const connection = createStdioConnection({
  get command() {
    return launchCommand(process.env).command;
  },
  get args() {
    return launchCommand(process.env).args;
  },
  // Read lazily: the token must be re-read on every reconnect, not captured once.
  get env() {
    return {
      GITHUB_PERSONAL_ACCESS_TOKEN: readToken(),
      GITHUB_TOOLSETS: TOOLSETS,
      GITHUB_READ_ONLY: "1",
    };
  },
  clientName: "attackcanvas",
  clientVersion: "0.1.0",
  errors,
  isTyped,
  isConfigError,
  startFailureContext: "could not start the GitHub MCP server",
  preflight: readToken,
});

/** Connects on first use and reuses the connection afterwards. */
export async function getClient(): Promise<Client> {
  return connection.getClient();
}

export async function closeClient(): Promise<void> {
  return connection.closeClient();
}

/** callToolWith() against the shared connection. */
export async function callTool(
  name: string,
  args: Record<string, unknown> = {},
): Promise<string> {
  const client = await getClient();
  return callToolWith(client as unknown as ToolCaller, name, args);
}

/** callToolResultWith() against the shared connection. */
export async function callToolResult(
  name: string,
  args: Record<string, unknown> = {},
): Promise<ToolOutput> {
  const client = await getClient();
  return callToolResultWith(client as unknown as ToolCaller, name, args);
}


// ---------------------------------------------------------------------------
// REST fallback
// ---------------------------------------------------------------------------

/** Which path produced a result, so callers can tell MCP from the REST fallback. */
export type Source = "mcp" | "rest";

/**
 * Chooses the error for a failed REST status. A 401 is a rejected credential, which is
 * a setup problem rather than something to show a user as "analysis failed", so it is
 * a config error. A 403 is rate limiting only when the remaining-quota header says so;
 * otherwise the token simply cannot see the repository.
 */
export function restErrorFor(
  status: number,
  rateLimitRemaining: string | null,
  path: string,
): GitHubMcpError | GitHubClientConfigError {
  if (status === 401) {
    return new GitHubClientConfigError(
      `GET ${path} returned 401: GITHUB_PERSONAL_ACCESS_TOKEN is missing, expired or revoked.`,
    );
  }

  const rateLimited =
    status === 429 || (status === 403 && rateLimitRemaining === "0");
  if (rateLimited) {
    return new GitHubMcpError("UPSTREAM_RATE_LIMITED", `GET ${path} returned ${status}`);
  }

  if (status === 404 || status === 403) {
    return new GitHubMcpError("REPO_NOT_FOUND", `GET ${path} returned ${status}`);
  }

  return new GitHubMcpError("GITHUB_UNAVAILABLE", `GET ${path} returned ${status}`);
}

/**
 * The Contents API wraps a file in JSON as base64 (about 4/3 the file's size, plus a
 * newline every 60 characters). Allow for that so a file just under the 1 MiB cap is
 * not rejected merely for its encoding; the cap itself is re-checked on decoded bytes.
 */
const CONTENTS_MAX_BODY_BYTES = Math.ceil(((MAX_RESPONSE_BYTES * 4) / 3) * 1.05) + 16 * 1024;

async function githubRest<T>(
  path: string,
  maxBytes: number = MAX_RESPONSE_BYTES,
): Promise<T> {
  const token = readToken();
  const url = `${GITHUB_API}${path}`;

  let response: Response;
  try {
    response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "attackcanvas",
      },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (cause) {
    // The URL is safe to name; the token lives in a header, not the URL.
    throw toTypedError(cause, `GET ${path} failed`);
  }

  if (!response.ok) {
    throw restErrorFor(
      response.status,
      response.headers.get("x-ratelimit-remaining"),
      path,
    );
  }

  const body = await response.text();
  if (Buffer.byteLength(body, "utf8") > maxBytes) {
    throw new GitHubMcpError("REPO_TOO_LARGE", `GET ${path} exceeded the size cap`);
  }

  try {
    return JSON.parse(body) as T;
  } catch (cause) {
    throw new GitHubMcpError("GITHUB_UNAVAILABLE", `GET ${path} returned invalid JSON`, { cause });
  }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

export type TreeEntry = {
  path: string;
  type: "file" | "dir";
  size?: number;
};

export type TreeResult = {
  entries: TreeEntry[];
  source: Source;
  /** GitHub caps very large trees; when true, entries are incomplete. */
  truncated: boolean;
};

export type RepoMetadata = {
  defaultBranch: string;
  languages?: string[];
  sizeKb?: number;
  source: Source;
};

type RawEntry = {
  path?: unknown;
  name?: unknown;
  type?: unknown;
  size?: unknown;
};

function normalizeEntry(raw: RawEntry): TreeEntry | null {
  const path = typeof raw.path === "string" ? raw.path : raw.name;
  if (typeof path !== "string" || path.length === 0) return null;

  const type = raw.type === "tree" || raw.type === "dir" || raw.type === "directory"
    ? "dir"
    : "file";
  const size = typeof raw.size === "number" ? raw.size : undefined;

  return size === undefined ? { path, type } : { path, type, size };
}

/**
 * Accepts the shapes the tree can arrive in: a bare array, GitHub's { tree: [...] },
 * or an { entries: [...] } wrapper, with either blob/tree or file/dir type names.
 */
export function parseTree(text: string): { entries: TreeEntry[]; truncated: boolean } {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (cause) {
    throw new GitHubMcpError("GITHUB_UNAVAILABLE", "tree response was not JSON", { cause });
  }

  const container = data as { tree?: unknown; entries?: unknown; truncated?: unknown };
  const raw = Array.isArray(data)
    ? data
    : Array.isArray(container?.tree)
      ? container.tree
      : Array.isArray(container?.entries)
        ? container.entries
        : null;

  if (!raw) {
    throw new GitHubMcpError("GITHUB_UNAVAILABLE", "tree response had no entries array");
  }

  return {
    entries: (raw as RawEntry[]).flatMap((item) => {
      const entry = normalizeEntry(item ?? {});
      return entry ? [entry] : [];
    }),
    truncated: container?.truncated === true,
  };
}

/**
 * Accepts raw text, GitHub's base64 { content, encoding }, or a { text } wrapper.
 * A directory listing is rejected: callers asked for a file.
 */
export function parseFileContent(text: string): string {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return text;

  let data: unknown;
  try {
    data = JSON.parse(trimmed);
  } catch {
    return text; // Not JSON after all: it is the file's own content.
  }

  if (Array.isArray(data)) {
    throw new GitHubMcpError("GITHUB_UNAVAILABLE", "expected a file but received a directory");
  }

  const object = data as { content?: unknown; encoding?: unknown; text?: unknown };

  if (typeof object.content === "string") {
    if (object.encoding === "base64") {
      const decoded = Buffer.from(object.content, "base64");
      if (decoded.byteLength > MAX_RESPONSE_BYTES) {
        throw new GitHubMcpError("REPO_TOO_LARGE", "file exceeds the size cap");
      }
      return decoded.toString("utf8");
    }
    return object.content;
  }

  if (typeof object.text === "string") return object.text;

  return text;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * REST only: discovery found no repo-metadata tool in any toolset, so `source` is
 * always "rest". Languages come from a second call and are omitted if it fails,
 * since they are optional context rather than something to fail the analysis over.
 */
export async function getRepoMetadata(
  owner: string,
  repo: string,
): Promise<RepoMetadata> {
  const repoPath = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;

  const data = await githubRest<{ default_branch?: string; size?: number }>(repoPath);
  if (typeof data.default_branch !== "string") {
    throw new GitHubMcpError("REPO_NOT_FOUND", `${owner}/${repo} has no default branch`);
  }

  let languages: string[] | undefined;
  try {
    languages = Object.keys(await githubRest<Record<string, number>>(`${repoPath}/languages`));
  } catch {
    languages = undefined;
  }

  return {
    defaultBranch: data.default_branch,
    ...(languages && languages.length > 0 ? { languages } : {}),
    ...(typeof data.size === "number" ? { sizeKb: data.size } : {}),
    source: "rest",
  };
}

/**
 * Prefers the MCP tool get_repository_tree, falling back to the REST tree API if the
 * tool is unavailable (an older server image, or "git" not enabled). A REST fallback
 * is not attempted for a genuine upstream failure such as a missing repository.
 */
export async function listTree(
  owner: string,
  repo: string,
  ref: string,
): Promise<TreeResult> {
  try {
    const text = await callTool("get_repository_tree", {
      owner,
      repo,
      tree_sha: ref,
      recursive: true,
    });
    return { ...parseTree(text), source: "mcp" };
  } catch (cause) {
    if (cause instanceof GitHubClientConfigError) throw cause;
    if (cause instanceof GitHubMcpError && cause.code !== "GITHUB_UNAVAILABLE") throw cause;

    const path =
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}` +
      `/git/trees/${encodeURIComponent(ref)}?recursive=1`;
    const data = await githubRest<unknown>(path);
    return { ...parseTree(JSON.stringify(data)), source: "rest" };
  }
}

type ContentsResponse = {
  type?: unknown;
  encoding?: unknown;
  content?: unknown;
  size?: unknown;
};

/**
 * Reads a Contents API response for a single file. Files over the API's 1 MB inline
 * limit come back with encoding "none" and no content; those, and anything decoding to
 * more than the size cap, are REPO_TOO_LARGE.
 */
export function parseContentsResponse(data: unknown, path: string): string {
  if (Array.isArray(data)) {
    throw new GitHubMcpError("GITHUB_UNAVAILABLE", `${path} is a directory, not a file`);
  }

  const file = data as ContentsResponse | null;
  if (!file || typeof file !== "object" || file.type !== "file") {
    throw new GitHubMcpError("GITHUB_UNAVAILABLE", `${path} is not a regular file`);
  }

  if (typeof file.size === "number" && file.size > MAX_RESPONSE_BYTES) {
    throw new GitHubMcpError("REPO_TOO_LARGE", `${path} exceeds ${MAX_RESPONSE_BYTES} bytes`);
  }
  if (file.encoding === "none") {
    throw new GitHubMcpError("REPO_TOO_LARGE", `${path} is too large to fetch inline`);
  }
  if (file.encoding !== "base64" || typeof file.content !== "string") {
    throw new GitHubMcpError("GITHUB_UNAVAILABLE", `${path} came back in an unsupported encoding`);
  }

  const bytes = Buffer.from(file.content, "base64");
  if (bytes.byteLength > MAX_RESPONSE_BYTES) {
    throw new GitHubMcpError("REPO_TOO_LARGE", `${path} exceeds ${MAX_RESPONSE_BYTES} bytes`);
  }
  return decodeText(bytes, path);
}

/** Read-only REST Contents API, used when the MCP result carries no file body. */
async function getFileContentRest(
  owner: string,
  repo: string,
  ref: string,
  path: string,
): Promise<string> {
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  const apiPath =
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}` +
    `/contents/${encodedPath}?ref=${encodeURIComponent(ref)}`;

  return parseContentsResponse(await githubRest<unknown>(apiPath, CONTENTS_MAX_BODY_BYTES), path);
}

export type FileResult = { content: string; source: Source };

/**
 * Returns the file's actual content. get_file_contents delivers the body in a resource
 * block and puts only a status line in its text block, so the body is read from the
 * resource. If the result carries no body (an older server, or a status line alone) the
 * REST Contents API is used instead. The status line is never returned as content.
 *
 * REST is used only when MCP gave no usable result: the call failed in an unclassified
 * way, or it returned no body. A genuine upstream failure (missing file, rate limit) is
 * not retried, and neither is a body that arrived but is unacceptable (binary, a
 * directory): REST would only return the same thing.
 */
export async function getFileContentWithSource(
  owner: string,
  repo: string,
  ref: string,
  path: string,
): Promise<FileResult> {
  let output: ToolOutput | undefined;
  try {
    output = await callToolResult("get_file_contents", { owner, repo, ref, path });
  } catch (cause) {
    if (cause instanceof GitHubClientConfigError) throw cause;
    if (cause instanceof GitHubMcpError && cause.code !== "GITHUB_UNAVAILABLE") throw cause;
  }

  if (output) {
    const body = bodyFromResources(output.resources, path);
    if (body !== undefined) return { content: body, source: "mcp" };

    // No resource block: the text is either the bare status line, which is not content,
    // or a wrapper from an older server, which parseFileContent understands.
    if (output.text.trim() !== "" && !isDownloadStatusMessage(output.text)) {
      return { content: parseFileContent(output.text), source: "mcp" };
    }
  }

  return { content: await getFileContentRest(owner, repo, ref, path), source: "rest" };
}

export async function getFileContent(
  owner: string,
  repo: string,
  ref: string,
  path: string,
): Promise<string> {
  return (await getFileContentWithSource(owner, repo, ref, path)).content;
}
