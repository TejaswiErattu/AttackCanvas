import { z } from "zod";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { ErrorCode } from "@/shared/schema";
import {
  callToolResultWith as callToolResultBase,
  createStdioConnection,
  mapErrorCode,
  type ErrorFactory,
  type SafeCallOptions,
  type ToolCaller,
  type ToolOutput,
} from "@/server/mcp/base";
import { SECURITY_RULESET } from "@/server/mcp/semgrepRules";

export type { ToolCaller, ToolOutput };

/**
 * Semgrep scanning for the analysis stage, over the Semgrep MCP server. Like the
 * GitHub client, every call goes through one choke point (CLAUDE.md rule 4): the
 * shared wrapper in src/server/mcp/base.ts, bound here to this server's allowlist,
 * timeout and size cap.
 *
 * Discovery (scripts/list-semgrep-tools.ts, server v1.29.0) found:
 *   - semgrep_scan takes absolute *paths*, not contents;
 *   - semgrep_scan_with_custom_rule is the only tool that takes file contents, and it
 *     requires the rule inline;
 *   - no tool takes a config/ruleset parameter, so a registry pack such as
 *     "p/owasp-top-ten" is not reachable over MCP.
 * So scanning goes through semgrep_scan_with_custom_rule with the pack in
 * semgrepRules.ts, and repository content is never written to disk.
 *
 * No credential is read or sent. Semgrep runs locally and nothing here logs.
 */

/**
 * Whatever `semgrep` is first on PATH. Its version is NOT checked here: docs/setup.md
 * names the tested version (1.176.0) and how to confirm it. Unlike the GitHub image,
 * which is pinned by digest, this can drift with the host's package manager.
 */
const COMMAND = "semgrep";
const ARGS = ["mcp"];

/** Per batch. Semgrep is CPU-bound and a cold server pays a one-off startup cost. */
export const TIMEOUT_MS = 120_000;

/** Files per scan call. Large enough to amortise the round trip, small enough to cap
 * the JSON a single response has to carry. */
export const BATCH_SIZE = 40;

export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/** A finding's snippet is context, not the file. Six lines is enough to read it. */
export const SNIPPET_MAX_LINES = 6;

/**
 * Tools this client may call.
 *
 * Deliberately excluded, each for a reason:
 *   - semgrep_scan takes absolute paths and reads them off disk, which would bypass
 *     redaction entirely. A path argument cannot honour "only already-redacted
 *     content reaches the scanner", so the tool is not callable from here at all.
 *   - semgrep_scan_supply_chain scans the server's own workspace directory, not the
 *     content we pass it.
 *   - semgrep_findings queries the Semgrep AppSec Platform API: it needs a token and
 *     sends repository names off-box.
 *   - semgrep_rule_schema and get_abstract_syntax_tree are authoring aids we do not
 *     need at analysis time.
 */
export const ALLOWED_TOOLS = [
  "semgrep_scan_with_custom_rule",
  "get_supported_languages",
] as const;

export type AllowedTool = (typeof ALLOWED_TOOLS)[number];

const ALLOWED = new Set<string>(ALLOWED_TOOLS);

const SCAN_TOOL: AllowedTool = "semgrep_scan_with_custom_rule";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** An upstream failure a caller can surface to the user, carrying a schema ErrorCode. */
export class SemgrepMcpError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "SemgrepMcpError";
  }
}

/**
 * A bug or a misconfigured environment: a tool outside the allowlist, or a missing
 * semgrep binary. Never shown to a user, and deliberately not carrying an ErrorCode.
 */
export class SemgrepClientConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SemgrepClientConfigError";
  }
}

const errors: ErrorFactory = {
  tool: (code, message, options) => new SemgrepMcpError(code, message, options),
  config: (message) => new SemgrepClientConfigError(message),
  // A Semgrep failure degrades the run (droppedStages) and never reaches the user, so
  // the catch-all is enough here.
  unclassified: "AI_FAILURE",
};

const isTyped = (cause: unknown): boolean => cause instanceof SemgrepMcpError;
const isConfigError = (cause: unknown): boolean => cause instanceof SemgrepClientConfigError;

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/**
 * A file that has already been through redaction.
 *
 * scanFiles never reads from disk and never takes a path argument, so what a caller
 * passes here is exactly and only what Semgrep sees. Anything that failed redaction
 * must be dropped by the caller before it gets this far.
 */
export type RedactedFile = { path: string; content: string };

export type SemgrepSeverity = "error" | "warning" | "info";

/**
 * One Semgrep result, flattened. Severity stays as Semgrep reported it: mapping it to
 * a AttackCanvas severity is scoring's job, never a scanner's (CLAUDE.md rule 2).
 */
export type RawSemgrepFinding = {
  ruleId: string;
  path: string;
  startLine: number;
  endLine: number;
  message: string;
  severity: SemgrepSeverity;
  cwe: string[];
  owasp: string[];
  snippet?: string;
};

/**
 * Semgrep's JSON envelope, read leniently: unknown keys are normal (the shape grows
 * between versions) and a malformed individual result is skipped rather than fatal.
 */
const SemgrepResultSchema = z
  .object({
    check_id: z.string().min(1).optional(),
    path: z.string().min(1).optional(),
    start: z.object({ line: z.number().int().optional() }).loose().optional(),
    end: z.object({ line: z.number().int().optional() }).loose().optional(),
    extra: z
      .object({
        message: z.string().optional(),
        severity: z.string().optional(),
        lines: z.string().optional(),
        metadata: z
          .object({
            cwe: z.union([z.string(), z.array(z.string())]).optional(),
            owasp: z.union([z.string(), z.array(z.string())]).optional(),
          })
          .loose()
          .optional(),
      })
      .loose()
      .optional(),
  })
  .loose();

const SemgrepEnvelopeSchema = z
  .object({
    results: z.array(z.unknown()).optional(),
    errors: z.array(z.unknown()).optional(),
  })
  .loose();

/** Normalises cwe/owasp, which Semgrep allows as a bare string or an array. */
function toStringList(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  for (const item of value) {
    if (typeof item === "string" && item.length > 0) seen.add(item);
  }
  return [...seen];
}

function toSeverity(value: unknown): SemgrepSeverity {
  switch (String(value).toUpperCase()) {
    case "ERROR":
      return "error";
    case "WARNING":
      return "warning";
    default:
      return "info";
  }
}

/** A fenced block that is the WHOLE response, not one found somewhere inside it. */
const WHOLE_FENCE = /^```(?:json)?[ \t]*\r?\n?([\s\S]*)\r?\n?```$/;

/**
 * Parses the JSON object in a tool response. The MCP text block has been observed to
 * carry bare JSON, so that is tried first, as a whole. Only if it does not parse is a
 * wrapper considered: a fenced block spanning the entire text, or prose around one
 * object (first "{" to last "}").
 *
 * Never a fence found inside the text: the response echoes repository file paths
 * (results[].path, paths.scanned), a path may legally contain backticks, and
 * "src/a```{}```.js" made the old unanchored fence search read "{}" as the whole
 * response, silently dropping every finding in the batch.
 */
function parsePayload(text: string): unknown {
  const trimmed = text.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    // Not bare JSON: look for a wrapper below.
  }

  const body = WHOLE_FENCE.exec(trimmed)?.[1]?.trim() ?? trimmed;
  const start = body.indexOf("{");
  const end = body.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) {
    throw new SemgrepMcpError("AI_FAILURE", "Semgrep response contained no JSON object");
  }
  return JSON.parse(body.slice(start, end + 1));
}

/**
 * Takes the snippet from the content we sent, not from the response.
 *
 * Semgrep's own `extra.lines` is "requires login" in logged-out OSS mode, so it cannot
 * be relied on. We already hold the file, and slicing it here keeps the snippet
 * correct regardless of login state.
 */
function sliceSnippet(
  content: string | undefined,
  startLine: number,
  endLine: number,
): string | undefined {
  if (content === undefined) return undefined;
  const lines = content.split("\n");
  const from = Math.max(0, startLine - 1);
  if (from >= lines.length) return undefined;
  const to = Math.min(lines.length, Math.max(endLine, startLine), from + SNIPPET_MAX_LINES);
  const slice = lines.slice(from, to);
  return slice.length > 0 ? slice.join("\n") : undefined;
}

/**
 * Parses a Semgrep JSON response into findings. Pure, so it is unit-tested against a
 * saved response without a server.
 *
 * `contentByPath` supplies the snippet source; without it findings simply carry no
 * snippet. Results missing an id, a path or a start line are skipped rather than
 * throwing, because one malformed result should not lose a whole batch.
 */
export function parseScanResponse(
  text: string,
  contentByPath: ReadonlyMap<string, string> = new Map(),
): RawSemgrepFinding[] {
  let parsed: unknown;
  try {
    parsed = parsePayload(text);
  } catch (cause) {
    if (cause instanceof SemgrepMcpError) throw cause;
    throw new SemgrepMcpError("AI_FAILURE", "Semgrep returned invalid JSON", { cause });
  }

  const envelope = SemgrepEnvelopeSchema.safeParse(parsed);
  if (!envelope.success) {
    throw new SemgrepMcpError(
      "AI_FAILURE",
      `Semgrep response did not match the expected shape: ${envelope.error.message}`,
    );
  }

  const findings: RawSemgrepFinding[] = [];

  for (const raw of envelope.data.results ?? []) {
    const result = SemgrepResultSchema.safeParse(raw);
    if (!result.success) continue;

    const { check_id: ruleId, path, start, end, extra } = result.data;
    const startLine = start?.line;
    if (!ruleId || !path || typeof startLine !== "number" || startLine < 1) continue;

    const endLine =
      typeof end?.line === "number" && end.line >= startLine ? end.line : startLine;
    const snippet = sliceSnippet(contentByPath.get(path), startLine, endLine);

    findings.push({
      ruleId,
      path,
      startLine,
      endLine,
      message: extra?.message?.trim() ?? "",
      severity: toSeverity(extra?.severity),
      cwe: toStringList(extra?.metadata?.cwe),
      owasp: toStringList(extra?.metadata?.owasp),
      ...(snippet !== undefined ? { snippet } : {}),
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Connection and calls
// ---------------------------------------------------------------------------

const connection = createStdioConnection({
  command: COMMAND,
  args: ARGS,
  // Semgrep phones home for metrics and version checks by default. This is a local
  // scan of someone else's repository; neither belongs on the wire.
  env: {
    SEMGREP_SEND_METRICS: "off",
    SEMGREP_ENABLE_VERSION_CHECK: "0",
  },
  clientName: "attackcanvas",
  clientVersion: "0.1.0",
  errors,
  isTyped,
  isConfigError,
  startFailureContext:
    'could not start the Semgrep MCP server ("semgrep mcp"); install it with "brew install semgrep"',
});

export async function getClient(): Promise<Client> {
  return connection.getClient();
}

export async function closeSemgrepClient(): Promise<void> {
  return connection.closeClient();
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
 * The single choke point for Semgrep MCP calls: allowlist, timeout, size cap, typed
 * errors. Exported with an explicit client so it can be unit-tested without spawning
 * a server.
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
// Scanning
// ---------------------------------------------------------------------------

/** Splits into fixed-size batches, preserving order. */
export function batch<T>(items: readonly T[], size: number): T[][] {
  if (size < 1) throw new SemgrepClientConfigError(`batch size must be >= 1, got ${size}`);
  const batches: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    batches.push(items.slice(index, index + size));
  }
  return batches;
}

/**
 * Scans already-redacted files and returns every finding.
 *
 * Batches of BATCH_SIZE, called one after another rather than in parallel: Semgrep is
 * CPU-bound and the server is a single process, so concurrency buys nothing and makes
 * the per-batch timeout meaningless. A failing batch fails the scan, identified by
 * index — never by content, which is untrusted repository data (CLAUDE.md rule 3).
 */
export async function scanFilesWith(
  client: ToolCaller,
  files: readonly RedactedFile[],
  timeoutMs: number = TIMEOUT_MS,
): Promise<RawSemgrepFinding[]> {
  const scannable = files.filter((file) => file.path !== "" && file.content !== "");
  if (scannable.length === 0) return [];

  const contentByPath = new Map(scannable.map((file) => [file.path, file.content]));
  const findings: RawSemgrepFinding[] = [];
  const batches = batch(scannable, BATCH_SIZE);

  for (const [index, group] of batches.entries()) {
    let text: string;
    try {
      text = await callToolWith(
        client,
        SCAN_TOOL,
        {
          code_files: group.map(({ path, content }) => ({ path, content })),
          rule: SECURITY_RULESET,
        },
        timeoutMs,
      );
    } catch (cause) {
      if (cause instanceof SemgrepClientConfigError) throw cause;
      const error = cause instanceof Error ? cause : new Error(String(cause));
      const code =
        cause instanceof SemgrepMcpError ? cause.code : mapErrorCode(error.message, errors.unclassified);
      throw new SemgrepMcpError(
        code,
        `Semgrep scan failed on batch ${index + 1} of ${batches.length}: ${error.message}`,
        { cause },
      );
    }

    findings.push(...parseScanResponse(text, contentByPath));
  }

  return findings;
}

/** scanFilesWith() against the shared connection. */
export async function scanFiles(
  files: readonly RedactedFile[],
): Promise<RawSemgrepFinding[]> {
  if (files.length === 0) return [];
  const client = await getClient();
  return scanFilesWith(client as unknown as ToolCaller, files);
}

/** The languages this Semgrep build can parse. Useful for filtering before a scan. */
export async function getSupportedLanguages(): Promise<string[]> {
  const client = await getClient();
  const text = await callToolWith(client as unknown as ToolCaller, "get_supported_languages");

  try {
    return toStringList(JSON.parse(text.trim()));
  } catch {
    // Some builds return a plain list rather than a JSON array.
    return text
      .split(/[\n,]/)
      .map((line) => line.trim().replace(/^[-*]\s*/, ""))
      .filter((line) => line.length > 0);
  }
}
