import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import type { ErrorCode } from "@/shared/schema";

/**
 * The parts of the MCP safety wrapper that every AttackCanvas MCP client shares
 * (CLAUDE.md rule 4): one allowlist, one timeout, one response size cap, one place
 * that maps an upstream failure to a typed ErrorCode, and one lazy connection with
 * shutdown hooks.
 *
 * Nothing here is GitHub- or Semgrep-specific. Callers supply their own caps and
 * their own error classes through an ErrorFactory, so each client keeps its own
 * error identity: a caller catching GitHubMcpError still catches everything the
 * GitHub client throws, including failures raised inside this module.
 *
 * Nothing in this module logs. Server credentials reach a child process through its
 * environment only, never through argv and never through an error message.
 */

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** An upstream failure a caller can surface to the user, carrying a schema ErrorCode. */
export type TypedError = Error & { readonly code: ErrorCode };

/**
 * How a client builds its own errors. `tool` produces a user-surfaceable failure;
 * `config` produces a bug-or-bad-environment error, which deliberately carries no
 * ErrorCode because no user-facing copy describes "we called the wrong tool".
 */
export type ErrorFactory = {
  tool(code: ErrorCode, message: string, options?: { cause?: unknown }): TypedError;
  config(message: string): Error;
  /**
   * The code for a failure mapErrorCode cannot classify: GITHUB_UNAVAILABLE for the
   * GitHub client (its REST fallback keys on it), AI_FAILURE for Semgrep, whose failures
   * only ever degrade the run and never reach the user.
   */
  unclassified: ErrorCode;
};

/**
 * Maps an upstream error message to the closest schema ErrorCode, or `unclassified` when
 * nothing matches. A 429 here is always an upstream service throttling us, so it is
 * UPSTREAM_RATE_LIMITED, never our own per-caller RATE_LIMITED.
 */
export function mapErrorCode(message: string, unclassified: ErrorCode = "AI_FAILURE"): ErrorCode {
  const text = message.toLowerCase();

  if (/timed out|timeout|etimedout|aborted|abort/.test(text)) return "TIMEOUT";

  const rateLimited =
    /rate limit|secondary rate|too many requests|\b429\b/.test(text) ||
    (/\b403\b|forbidden/.test(text) && /limit|quota|abuse/.test(text));
  if (rateLimited) return "UPSTREAM_RATE_LIMITED";

  // A 403 without a rate-limit hint means the credential cannot see this resource,
  // which is indistinguishable from "missing" for a read-only tool.
  if (/\b404\b|not found|\b403\b|forbidden/.test(text)) return "REPO_NOT_FOUND";

  if (/too large|exceeds|size limit/.test(text)) return "REPO_TOO_LARGE";

  return unclassified;
}

export function asError(cause: unknown): Error {
  return cause instanceof Error ? cause : new Error(String(cause));
}

/**
 * Re-throws anything as the caller's typed error, preserving a code that is already
 * there. `isTyped` decides what "already typed" means for that client, so a GitHub
 * error is never quietly rewrapped as a Semgrep one.
 */
export function toTypedError(
  cause: unknown,
  context: string,
  errors: ErrorFactory,
  isTyped: (cause: unknown) => boolean,
): Error {
  if (isTyped(cause)) return cause as Error;
  const error = asError(cause);
  return errors.tool(mapErrorCode(error.message, errors.unclassified), `${context}: ${error.message}`, {
    cause,
  });
}

// ---------------------------------------------------------------------------
// Response handling
// ---------------------------------------------------------------------------

type TextContent = { type: string; text?: unknown };

/**
 * Concatenates the "text" items of an MCP result, enforcing the size cap as it goes
 * so an oversized response is rejected rather than assembled.
 */
export function extractText(
  content: unknown,
  maxBytes: number,
  errors: ErrorFactory,
): string {
  if (!Array.isArray(content)) return "";

  const parts: string[] = [];
  let bytes = 0;

  for (const item of content as TextContent[]) {
    if (!item || item.type !== "text" || typeof item.text !== "string") continue;
    bytes += Buffer.byteLength(item.text, "utf8");
    if (bytes > maxBytes) {
      throw errors.tool("REPO_TOO_LARGE", `response exceeds ${maxBytes} bytes`);
    }
    parts.push(item.text);
  }

  return parts.join("\n");
}

/**
 * A `resource` content block. Observed live (GitHub MCP server v1.12.2):
 * get_file_contents returns a text block holding only a status message, followed by a
 * resource block whose `resource.text` is the actual file body.
 */
export type ResourceContent = {
  uri?: string;
  mimeType?: string;
  text?: string;
  blob?: string;
};

/**
 * Collects the resource blocks of an MCP result. Each payload is capped on its own, so
 * a file of exactly the cap is accepted regardless of the status text beside it.
 */
export function extractResources(
  content: unknown,
  maxBytes: number,
  errors: ErrorFactory,
): ResourceContent[] {
  if (!Array.isArray(content)) return [];

  const resources: ResourceContent[] = [];
  for (const item of content as { type?: unknown; resource?: unknown }[]) {
    if (!item || item.type !== "resource") continue;
    const raw = item.resource as Record<string, unknown> | null | undefined;
    if (!raw || typeof raw !== "object") continue;

    const text = typeof raw.text === "string" ? raw.text : undefined;
    const blob = typeof raw.blob === "string" ? raw.blob : undefined;
    const bytes =
      text !== undefined
        ? Buffer.byteLength(text, "utf8")
        : blob !== undefined
          ? Buffer.byteLength(blob, "base64")
          : 0;

    if (bytes > maxBytes) {
      throw errors.tool("REPO_TOO_LARGE", `resource exceeds ${maxBytes} bytes`);
    }

    resources.push({
      ...(typeof raw.uri === "string" ? { uri: raw.uri } : {}),
      ...(typeof raw.mimeType === "string" ? { mimeType: raw.mimeType } : {}),
      ...(text !== undefined ? { text } : {}),
      ...(blob !== undefined ? { blob } : {}),
    });
  }
  return resources;
}

// ---------------------------------------------------------------------------
// The choke point
// ---------------------------------------------------------------------------

/** The slice of the MCP client this wrapper needs, so tests can supply a stub. */
export type ToolCaller = {
  callTool(
    params: { name: string; arguments?: Record<string, unknown> },
    resultSchema?: unknown,
    options?: { timeout?: number },
  ): Promise<unknown>;
};

type ToolResult = { content?: unknown; isError?: boolean };

export type ToolOutput = { text: string; resources: ResourceContent[] };

export type SafeCallOptions = {
  allowed: ReadonlySet<string>;
  allowedLabel: string;
  errors: ErrorFactory;
  isTyped: (cause: unknown) => boolean;
  maxResponseBytes: number;
  timeoutMs: number;
};

/**
 * The single choke point for MCP calls: allowlist, timeout, size cap, typed errors.
 * Takes the client explicitly so it can be unit-tested without spawning a server.
 * Returns text blocks and resource blocks separately, because tools such as
 * get_file_contents put their payload in a resource block.
 */
export async function callToolResultWith(
  client: ToolCaller,
  name: string,
  args: Record<string, unknown>,
  options: SafeCallOptions,
): Promise<ToolOutput> {
  const { allowed, allowedLabel, errors, isTyped, maxResponseBytes, timeoutMs } = options;

  if (!allowed.has(name)) {
    throw errors.config(`tool "${name}" is not in ${allowedLabel}`);
  }

  let result: ToolResult;
  try {
    result = (await client.callTool({ name, arguments: args }, undefined, {
      timeout: timeoutMs,
    })) as ToolResult;
  } catch (cause) {
    throw toTypedError(cause, `MCP tool ${name} failed`, errors, isTyped);
  }

  const text = extractText(result?.content, maxResponseBytes, errors);

  if (result?.isError) {
    throw errors.tool(mapErrorCode(text, errors.unclassified), `MCP tool ${name} failed: ${text}`);
  }

  return { text, resources: extractResources(result?.content, maxResponseBytes, errors) };
}

// ---------------------------------------------------------------------------
// Connection (lazy singleton)
// ---------------------------------------------------------------------------

export type StdioConnectionConfig = {
  command: string;
  args: string[];
  /** Extra environment for the child. Merged over getDefaultEnvironment(). */
  env?: Record<string, string>;
  clientName: string;
  clientVersion: string;
  errors: ErrorFactory;
  isTyped: (cause: unknown) => boolean;
  isConfigError: (cause: unknown) => boolean;
  /** Prefixes the error when the server cannot be started. */
  startFailureContext: string;
  /** Read just before connecting, to fail fast on a missing credential. */
  preflight?: () => void;
};

export type Connection = {
  getClient(): Promise<Client>;
  closeClient(): Promise<void>;
};

// Shutdown handlers are process-wide, not per connection: each connection only adds
// its closer to this set, and one exit/SIGINT/SIGTERM listener set closes them all.
// The state lives on globalThis so a reloaded module (dev HMR, vi.resetModules) shares
// it instead of stacking another listener set on `process`.
type ShutdownState = { closers: Set<() => Promise<void>>; registered: boolean };
const SHUTDOWN_KEY = Symbol.for("attackcanvas.mcp.shutdown");
const shutdownState: ShutdownState = ((globalThis as Record<symbol, unknown>)[SHUTDOWN_KEY] ??= {
  closers: new Set(),
  registered: false,
}) as ShutdownState;
const openConnections = shutdownState.closers;

function closeAll(): Promise<unknown> {
  return Promise.allSettled([...openConnections].map((close) => close()));
}

function registerShutdownOnce(): void {
  if (shutdownState.registered) return;
  shutdownState.registered = true;

  process.once("exit", () => {
    void closeAll();
  });

  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => {
      void closeAll().finally(() => {
        // Our listener suppressed the default action, so when it was the only one, put
        // that back by re-raising. When someone else is listening they got this signal
        // too and own the decision to exit; re-raising would invoke them a second time.
        if (process.listenerCount(signal) === 0) process.kill(process.pid, signal);
      });
    });
  }
}

/**
 * Connects on first use and reuses the connection afterwards, closing it on exit and
 * on SIGINT/SIGTERM. A failed connection is not cached, so the next call retries, and
 * neither is one that dies later: when the server process exits after connecting, the
 * SDK drops its transport and every later call would fail with "Not connected" until
 * the app restarts, so the cached client is forgotten and the next call reconnects.
 */
export function createStdioConnection(config: StdioConnectionConfig): Connection {
  let clientPromise: Promise<Client> | null = null;

  async function closeClient(): Promise<void> {
    const pending = clientPromise;
    clientPromise = null;
    openConnections.delete(closeClient);
    if (!pending) return;
    try {
      const client = await pending;
      await client.close();
    } catch {
      // Shutting down: nothing useful to do with a close failure.
    }
  }

  async function connect(onClosed: () => void): Promise<Client> {
    config.preflight?.();

    const transport = new StdioClientTransport({
      // getDefaultEnvironment() supplies PATH so the command resolves. Any credential
      // is only ever a value in this map, never an argv entry.
      env: { ...getDefaultEnvironment(), ...config.env },
      command: config.command,
      args: config.args,
      stderr: "ignore",
    });

    const client = new Client({ name: config.clientName, version: config.clientVersion });
    // Protocol.onclose: fired once the transport has closed, whoever closed it.
    client.onclose = onClosed;
    await client.connect(transport);
    openConnections.add(closeClient);
    registerShutdownOnce();
    return client;
  }

  return {
    async getClient(): Promise<Client> {
      if (!clientPromise) {
        // Forget this connection once it closes -- but only if it is still the cached
        // one, so a late close event never evicts a newer, healthy connection.
        const forget = () => {
          if (clientPromise === pending) clientPromise = null;
        };
        const pending: Promise<Client> = connect(forget).catch((cause) => {
          clientPromise = null; // let the next call retry instead of caching the failure
          throw config.isConfigError(cause)
            ? cause
            : toTypedError(cause, config.startFailureContext, config.errors, config.isTyped);
        });
        clientPromise = pending;
      }
      return clientPromise;
    },
    closeClient,
  };
}
