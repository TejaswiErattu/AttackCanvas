/**
 * The one function every AI step calls.
 *
 * Sends a system prompt and a block of data, constrains the reply to a JSON Schema,
 * validates it with Zod, retries once with the validation errors quoted back, and
 * records what the call cost. Every later prompt (architecture, STRIDE, questions,
 * remediation) is then just a schema and some text.
 *
 * Structured output: @anthropic-ai/sdk 0.126.0 supports `output_config.format` with a
 * JSON Schema, so that is what this uses. The forced-"submit"-tool fallback the
 * playbook describes is deliberately NOT implemented -- on this SDK version it would be
 * unreachable code, and an untested fallback is worse than none. If the SDK is ever
 * downgraded below native structured output, this is the place that changes.
 *
 * Zod validation still runs on top of the constrained output (CLAUDE.md rule 5),
 * because JSON Schema can express shape but not the business rules the contract
 * carries -- "this evidence id must exist", "a threat cites evidence or states an
 * assumption".
 *
 * Nothing here logs prompt text outside development (CLAUDE.md rule 8), and the user
 * block is checked for credentials before it goes on the wire (rule 3).
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import Anthropic from "@anthropic-ai/sdk";
import type { z } from "zod";
import { modelFor, type AiStage, type ModelId } from "@/server/ai/models";
import {
  addTokens,
  estimateCostUsd,
  usageLedger,
  NO_TOKENS,
  type CallUsage,
  type TokenCounts,
  type UsageLedger,
} from "@/server/ai/usage";
import { assertNoSecretsInPrompt, redact } from "@/server/security/redactor";
import {
  isWellFormedText,
  sliceWithoutSplitting,
  toWellFormedText,
} from "@/server/security/unicode";
import type { ErrorCode } from "@/shared/schema";

// ---------------------------------------------------------------------------
// Knobs
// ---------------------------------------------------------------------------

export const DEFAULT_MAX_TOKENS = 8000;

/** Whole-call deadline, including backoff sleeps and the validation retry. */
export const TIMEOUT_MS = 120_000;

/**
 * The largest max_tokens the SDK accepts on a non-streaming request with no explicit
 * timeout: it refuses a request it expects to run past 10 minutes at 128,000 output
 * tokens an hour, which is 600 * 128,000 / 3,600 = 21,333 tokens. Every request here is
 * non-streaming, so no budget, first attempt or retry, may exceed it.
 */
export const NON_STREAMING_MAX_TOKENS = 21_333;

/**
 * Head-room on the time a truncation retry is given: its larger budget at the first
 * attempt's measured pace, plus a quarter, so a slightly slower second reply is not cut
 * off by the deadline instead of by max_tokens.
 */
export const TRUNCATION_RETRY_TIME_MARGIN = 1.25;

/**
 * The output budget for the one retry of a reply cut off at max_tokens (CLAUDE.md rule
 * 5): twice the first budget, capped at NON_STREAMING_MAX_TOKENS. The same budget would
 * only repeat the cutoff. callStructured requires a first budget below the cap, so the
 * retry always gets strictly more.
 */
export function truncationRetryTokens(maxTokens: number): number {
  return Math.min(maxTokens * 2, NON_STREAMING_MAX_TOKENS);
}

/**
 * The deadline for a truncation retry: the time the first attempt took, scaled to the
 * retry's larger budget, with TRUNCATION_RETRY_TIME_MARGIN on top, and never less than
 * the call's own deadline. The first attempt's pace is the best estimate of the second's:
 * a retry held to what is left of the original deadline would time out instead of
 * finishing, since the cut-off reply already used most of it.
 */
export function truncationRetryTimeoutMs(
  timeoutMs: number,
  firstAttemptMs: number,
  maxTokens: number,
  retryTokens: number,
): number {
  const paced = (firstAttemptMs * retryTokens * TRUNCATION_RETRY_TIME_MARGIN) / maxTokens;
  return Math.max(timeoutMs, Math.ceil(paced));
}

/**
 * JSON Schema keywords the structured-output endpoint rejects with HTTP 400 (for
 * example "For 'integer' type, properties maximum, minimum are not supported"). They
 * describe ranges, which the endpoint cannot enforce; the reply is still parsed with the
 * caller's Zod schema, so the range is enforced there and only the schema SENT changes.
 * A mocked client cannot reveal this class of failure; a live call did.
 *
 * Array length limits are "complex array constraints", also unsupported: `maxItems` is
 * always dropped, and `minItems` is kept only as 0 or 1 (see MIN_ITEMS_KEPT), the same
 * rule the installed SDK's own transform-json-schema.js applies. The questions schema's
 * `.min(2).max(4)` options are the case this covers; Zod still enforces both.
 */
const UNSUPPORTED_SCHEMA_KEYWORDS: ReadonlySet<string> = new Set([
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
  "maxItems",
]);

/** The only `minItems` values the endpoint accepts; any other is dropped from the wire. */
const MIN_ITEMS_KEPT: ReadonlySet<unknown> = new Set([0, 1]);

/** Keys whose value maps a NAME to a schema: the names are fields, not keywords. */
const SCHEMA_MAP_KEYS: ReadonlySet<string> = new Set([
  "properties",
  "patternProperties",
  "$defs",
  "definitions",
  "dependentSchemas",
]);

/** Keys whose value is data, not a schema, so it is copied and never rewritten. */
const SCHEMA_DATA_KEYS: ReadonlySet<string> = new Set([
  "enum",
  "const",
  "default",
  "examples",
]);

/**
 * The schema to put on the wire: a deep copy of `schema` without the keywords above, at
 * any depth (objects, arrays, anyOf/oneOf/allOf, items, definitions). Structural and
 * descriptive keywords (type, properties, required, description, enum, pattern, ...) are
 * kept. The caller's object is never modified.
 */
export function toApiSchema(schema: unknown): unknown {
  if (Array.isArray(schema)) return schema.map(toApiSchema);
  if (typeof schema !== "object" || schema === null) return schema;

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(schema)) {
    if (UNSUPPORTED_SCHEMA_KEYWORDS.has(key)) continue;
    if (key === "minItems" && !MIN_ITEMS_KEPT.has(value)) continue;
    if (SCHEMA_DATA_KEYS.has(key)) {
      out[key] = structuredClone(value);
    } else if (
      SCHEMA_MAP_KEYS.has(key) &&
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value)
    ) {
      out[key] = Object.fromEntries(
        Object.entries(value).map(([name, sub]) => [name, toApiSchema(sub)]),
      );
    } else {
      out[key] = toApiSchema(value);
    }
  }
  return out;
}

/** Transport attempts per request: the first try plus two backoffs. */
export const MAX_TRANSPORT_ATTEMPTS = 3;

/** 1s, then 2s. Exponential from here if MAX_TRANSPORT_ATTEMPTS ever grows. */
export const BACKOFF_BASE_MS = 1_000;

/** Where development dumps land. Gitignored. */
export const DEBUG_DIR = ".debug";

/** Model responses this long are a runaway, not an answer. */
const MAX_RESPONSE_CHARS = 4_000_000;

/** Enough of a bad reply to see what went wrong, short enough not to blow the retry. */
const ECHO_MAX_CHARS = 20_000;

/** Statuses worth trying again: rate limit, overloaded, and any server-side fault. */
function isRetryableStatus(status: number): boolean {
  return status === 429 || status === 529 || status >= 500;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type ValidationIssue = { path: string; message: string };

/**
 * A model call that cannot be recovered from. Carries a schema ErrorCode so the API
 * layer can map it to user-facing copy without re-inspecting the cause, and the Zod
 * issues when the failure was a shape one.
 *
 * `issues` holds paths and messages only, never the values at those paths: this error
 * gets logged, and the value at a path is model output derived from repository content.
 */
/**
 * The shape of a request the provider rejected with a 4xx: structure only. Never the
 * provider's own error message, never message text, headers or the request body.
 */
export type RequestDiagnostic = {
  status: number;
  /** The provider's error type ("invalid_request_error", ...), when it is a safe code. */
  errorType?: string;
  requestId?: string;
  stage: AiStage;
  /** The validation attempt the rejected request belonged to: 1, or 2 for the retry. */
  attempt: number;
  messages: { role: string; chars: number; utf8Bytes: number }[];
  systemChars: number;
  allMessagesNonEmpty: boolean;
  allMessagesWellFormed: boolean;
};

export class AiError extends Error {
  readonly issues: readonly ValidationIssue[];
  readonly request?: RequestDiagnostic;

  constructor(
    readonly code: ErrorCode,
    message: string,
    options?: {
      cause?: unknown;
      issues?: readonly ValidationIssue[];
      request?: RequestDiagnostic;
    },
  ) {
    super(message, options);
    this.name = "AiError";
    this.issues = options?.issues ?? [];
    if (options?.request) this.request = options.request;
  }
}

// ---------------------------------------------------------------------------
// Injection points
// ---------------------------------------------------------------------------

/**
 * The slice of the SDK this module uses. Narrow on purpose: a test double implements
 * one method instead of the whole client, and nothing in a test can reach the network.
 */
export type MessagesApi = {
  create(
    body: Anthropic.MessageCreateParamsNonStreaming,
    options?: { signal?: AbortSignal },
  ): Promise<Anthropic.Message>;
};

/** Schedules `fn` after `ms` and returns a canceller. Injected so tests never wait. */
export type Schedule = (ms: number, fn: () => void) => () => void;

const realSchedule: Schedule = (ms, fn) => {
  const handle = setTimeout(fn, ms);
  return () => clearTimeout(handle);
};

const realSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Writes one debug dump. Replaced in tests; a no-op outside development. */
export type DebugWriter = (
  analysisId: string,
  file: string,
  body: string,
) => void;

const realDebugWriter: DebugWriter = (analysisId, file, body) => {
  const dir = join(DEBUG_DIR, analysisId);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, file), body, "utf8");
};

export type ClaudeDeps = {
  client: MessagesApi;
  sleep: (ms: number) => Promise<void>;
  schedule: Schedule;
  ledger: UsageLedger;
  /** Development only. CLAUDE.md rule 8: prompts never leave the machine in prod. */
  isDevelopment: boolean;
  writeDebug: DebugWriter;
  /** Milliseconds, for timing an attempt. Injectable so tests control the pace. */
  now: () => number;
};

/** Sent when ANTHROPIC_WORKSPACE_ID is set. Organization-level keys need it. */
export const WORKSPACE_HEADER = "anthropic-workspace-id";

/** Workspace ids are letters, digits, underscores and hyphens. Nothing else is sent. */
const WORKSPACE_ID = /^[A-Za-z0-9_-]{1,128}$/;

/**
 * Constructor options for the real client. `maxRetries: 0` because this module owns
 * the retry policy -- the SDK's own retries would multiply against the backoff below
 * and quietly turn three attempts into nine.
 *
 * ANTHROPIC_WORKSPACE_ID, when set and non-empty, is sent as a default header on every
 * request. Unset or blank leaves the options exactly as they were. The id is validated
 * against a strict pattern before it becomes a header value, and a value that fails is
 * reported WITHOUT the value: this error is logged, and the id is configuration.
 */
export function clientOptions(
  env: Record<string, string | undefined> = process.env,
): { maxRetries: number; defaultHeaders?: Record<string, string> } {
  const workspaceId = env.ANTHROPIC_WORKSPACE_ID?.trim();
  if (!workspaceId) return { maxRetries: 0 };
  if (!WORKSPACE_ID.test(workspaceId)) {
    throw new Error(
      "ANTHROPIC_WORKSPACE_ID has an invalid format (expected letters, digits, _ and -)",
    );
  }
  return { maxRetries: 0, defaultHeaders: { [WORKSPACE_HEADER]: workspaceId } };
}

let lazyClient: Anthropic | undefined;

function defaultClient(): MessagesApi {
  lazyClient ??= new Anthropic(clientOptions());
  return lazyClient.messages;
}

function resolveDeps(overrides?: Partial<ClaudeDeps>): ClaudeDeps {
  return {
    client: overrides?.client ?? defaultClient(),
    sleep: overrides?.sleep ?? realSleep,
    schedule: overrides?.schedule ?? realSchedule,
    ledger: overrides?.ledger ?? usageLedger,
    isDevelopment:
      overrides?.isDevelopment ?? process.env.NODE_ENV === "development",
    writeDebug: overrides?.writeDebug ?? realDebugWriter,
    now: overrides?.now ?? Date.now,
  };
}

// ---------------------------------------------------------------------------
// Public shape
// ---------------------------------------------------------------------------

export type CallStructuredOptions<T> = {
  stage: AiStage;
  /** Instructions. Ours, never repository-derived. Sent as a cacheable block. */
  system: string;
  /** The data the model reasons over. Repository-derived, so secret-checked. */
  user: string;
  schema: z.ZodType<T>;
  /** JSON Schema for the same shape, from src/shared/schema's *JsonSchema exports. */
  jsonSchema: Record<string, unknown>;
  /**
   * Output budget for the first attempt. A positive integer below
   * NON_STREAMING_MAX_TOKENS, so a reply cut off at it can be retried with a larger one
   * (truncationRetryTokens). Defaults to DEFAULT_MAX_TOKENS.
   */
  maxTokens?: number;
  /**
   * Whole-call deadline in milliseconds, covering backoff sleeps and the validation
   * retry. Defaults to TIMEOUT_MS; a call that legitimately generates a lot (the STRIDE
   * batches) asks for longer. Must be a positive finite number. A truncation retry is
   * the exception: it gets a fresh deadline sized to its budget
   * (truncationRetryTimeoutMs), never a shorter one.
   */
  timeoutMs?: number;
  /**
   * Extended-thinking control. Left out (the default), the request carries no `thinking`
   * field and the model behaves as it always has for this stage. `{ type: "disabled" }`
   * turns thinking off for this call only: reasoning tokens count against `max_tokens`
   * and can consume all of it, leaving no room for the JSON. Set per call, never globally.
   */
  thinking?: { type: "disabled" };
  /**
   * Distinguishes several calls of one stage in the same analysis (a threat batch's
   * index), so their development dumps do not overwrite one another. Letters, digits,
   * "_" and "-" only; anything else is dropped from the file name.
   */
  dumpKey?: string;
  analysisId: string;
  deps?: Partial<ClaudeDeps>;
};

export type CallStructuredResult<T> = {
  value: T;
  /** The whole call: every provider response summed, retries included. */
  usage: CallUsage;
  /** One entry per provider response, as recorded in the ledger. */
  attemptUsage: CallUsage[];
  /** 1 when the first reply validated, 2 when the retry saved it. */
  attempts: number;
};

// ---------------------------------------------------------------------------
// callStructured
// ---------------------------------------------------------------------------

export async function callStructured<T>(
  options: CallStructuredOptions<T>,
): Promise<CallStructuredResult<T>> {
  const {
    stage,
    system,
    user,
    schema,
    jsonSchema,
    maxTokens = DEFAULT_MAX_TOKENS,
    timeoutMs = TIMEOUT_MS,
    thinking,
    dumpKey,
    analysisId,
  } = options;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`timeoutMs must be a positive finite number, got ${timeoutMs}`);
  }
  if (!Number.isInteger(maxTokens) || maxTokens <= 0 || maxTokens >= NON_STREAMING_MAX_TOKENS) {
    throw new Error(
      `maxTokens must be a positive integer below ${NON_STREAMING_MAX_TOKENS}, got ${maxTokens}`,
    );
  }
  const deps = resolveDeps(options.deps);
  const model = modelFor(stage);

  // Rule 3. Before anything else, and before any debug dump: if a secret survived the
  // redactor this call must not happen, and the dump must not be written either. The
  // prompt-aware form, so a generated <repo_file path="..."> wrapper is not itself read
  // as a secret assignment; its path is still checked on its own.
  assertNoSecretsInPrompt(user);

  const controller = new AbortController();
  let timedOut = false;
  const onDeadline = (): void => {
    timedOut = true;
    controller.abort();
  };
  let cancelDeadline = deps.schedule(timeoutMs, onDeadline);

  const messages: Anthropic.MessageParam[] = [
    { role: "user", content: user },
  ];
  // Every provider response is billable, so each is recorded as its own ledger entry the
  // moment it is RECEIVED, before parsing or validation: a reply that later fails still
  // shows up, and a validation retry adds a second entry rather than hiding inside the
  // first. A request that got no response (a connection failure) records nothing, so no
  // usage is invented. The ledger ignores a repeated (callId, attempt), so one response
  // cannot be counted twice.
  const callId = nextCallId();
  const attemptUsage: CallUsage[] = [];
  const onResponse = (received: Received): void => {
    const recorded = deps.ledger.record(
      analysisId,
      finishUsage(
        stage,
        model,
        received.tokens,
        received.requests,
        received.stopReason,
        received.model,
        callId,
        received.attempt,
      ),
    );
    if (!attemptUsage.includes(recorded)) attemptUsage.push(recorded);
  };

  try {
    // Two attempts at most: the original, then one correction carrying the Zod issues
    // (CLAUDE.md rule 5). A third would cost a second retry's tokens to fix a model
    // that has already failed the same schema twice. A reply cut off at max_tokens is a
    // failure like any other, but its retry gets a larger budget and the time to use it:
    // the same budget would only repeat the cutoff.
    let budget = maxTokens;
    let deadlineMs = timeoutMs;
    for (let attempt = 1; attempt <= 2; attempt++) {
      const startedAt = deps.now();
      const sent = await send({
        deps,
        model,
        system,
        messages,
        jsonSchema,
        maxTokens: budget,
        signal: controller.signal,
        timeoutMs: deadlineMs,
        isTimedOut: () => timedOut,
        onResponse,
        attempt,
        thinking,
        stage,
      });

      if (deps.isDevelopment) {
        writeDump(deps, analysisId, stage, attempt, system, messages, sent.text, dumpKey);
      }

      const parsed = parseAndValidate(schema, sent.text, sent.truncated);
      if (parsed.ok) {
        return {
          value: parsed.value,
          usage: sumAttempts(attemptUsage),
          attemptUsage,
          attempts: attempt,
        };
      }

      if (attempt === 2) {
        throw new AiError(
          "MODEL_OUTPUT_INVALID",
          sent.truncated
            ? `${stage}: structured output was truncated at the configured token limit (${budget} tokens)`
            : `${stage}: model response failed validation twice`,
          { issues: parsed.issues },
        );
      }

      if (sent.truncated) {
        const retryTokens = truncationRetryTokens(budget);
        deadlineMs = truncationRetryTimeoutMs(
          timeoutMs,
          deps.now() - startedAt,
          budget,
          retryTokens,
        );
        budget = retryTokens;
        cancelDeadline();
        cancelDeadline = deps.schedule(deadlineMs, onDeadline);
      }

      // The reply becomes an assistant turn and the correction a user turn, so the
      // model sees its own answer next to what was wrong with it. For a cut-off reply
      // the issue asks for the complete JSON, more briefly.
      messages.push(
        { role: "assistant", content: echoOf(sent.text) },
        { role: "user", content: toWellFormedText(correctionMessage(parsed.issues)) },
      );
    }

    // The loop returns or throws on both attempts; TypeScript cannot see that.
    throw new AiError("AI_FAILURE", `${stage}: unreachable`);
  } finally {
    cancelDeadline();
  }
}

// ---------------------------------------------------------------------------
// One request, with backoff
// ---------------------------------------------------------------------------

type SendResult = {
  text: string;
  /** The model hit max_tokens: the JSON is cut off mid-structure. */
  truncated: boolean;
};

/** What one received response contributes to a call's usage. */
type Received = {
  tokens: TokenCounts;
  /** Requests it took to get this response: 1, plus any backoff retries before it. */
  requests: number;
  /** Which response of the call this is: 1, or 2 after a validation retry. */
  attempt: number;
  stopReason?: string;
  model?: string;
};

async function send(args: {
  deps: ClaudeDeps;
  model: ModelId;
  system: string;
  messages: readonly Anthropic.MessageParam[];
  jsonSchema: Record<string, unknown>;
  maxTokens: number;
  signal: AbortSignal;
  timeoutMs: number;
  isTimedOut: () => boolean;
  /** Called with a response's usage as soon as it arrives, before anything reads its text. */
  onResponse: (received: Received) => void;
  /** The validation attempt this request belongs to (1 or 2). */
  attempt: number;
  thinking?: { type: "disabled" };
  stage: AiStage;
}): Promise<SendResult> {
  const { deps, model, jsonSchema, maxTokens, signal } = args;
  // Every string on the wire is well-formed UTF-16: a lone surrogate cannot be encoded
  // and gets the whole request rejected with a 400. A no-op for well-formed text.
  const system = toWellFormedText(args.system);
  const messages = args.messages.map(wellFormedMessage);

  const body: Anthropic.MessageCreateParamsNonStreaming = {
    model,
    max_tokens: maxTokens,
    // A cacheable block. The system prompt is identical across the STRIDE batches,
    // so caching it turns the per-batch input cost into a cache read.
    system: [
      { type: "text", text: system, cache_control: { type: "ephemeral" } },
    ],
    messages,
    output_config: {
      format: { type: "json_schema", schema: toApiSchema(jsonSchema) as Record<string, unknown> },
    },
    ...(args.thinking ? { thinking: args.thinking } : {}),
  };

  let lastError: unknown;
  for (let attempt = 1; attempt <= MAX_TRANSPORT_ATTEMPTS; attempt++) {
    try {
      const response = await deps.client.create(body, { signal });
      // Before textOf(), which throws on a refusal or an oversized reply: the response
      // was received and billed either way.
      args.onResponse({
        tokens: tokensOf(response),
        requests: attempt,
        attempt: args.attempt,
        stopReason:
          typeof response.stop_reason === "string" ? response.stop_reason : undefined,
        model: safeCode(response.model),
      });
      return {
        text: textOf(response),
        truncated: response.stop_reason === "max_tokens",
      };
    } catch (error) {
      if (args.isTimedOut()) {
        throw new AiError("TIMEOUT", `model call exceeded ${args.timeoutMs}ms`, {
          cause: error,
        });
      }
      if (error instanceof AiError) throw error;

      const status = statusOf(error);
      if (status === undefined || !isRetryableStatus(status)) {
        throw new AiError("AI_FAILURE", `model call failed: ${reasonOf(error)}`, {
          cause: error,
          ...clientErrorDiagnostic(error, status, args.stage, args.attempt, system, messages),
        });
      }
      lastError = error;
      if (attempt < MAX_TRANSPORT_ATTEMPTS) {
        await deps.sleep(BACKOFF_BASE_MS * 2 ** (attempt - 1));
      }
    }
  }

  const status = statusOf(lastError);
  throw new AiError(
    status === 429 ? "UPSTREAM_RATE_LIMITED" : "AI_FAILURE",
    `model call failed after ${MAX_TRANSPORT_ATTEMPTS} attempts: ${reasonOf(lastError)}`,
    {
      cause: lastError,
      ...clientErrorDiagnostic(lastError, status, args.stage, args.attempt, system, messages),
    },
  );
}

/** A message with its text made well formed: string content, or each text block's text. */
function wellFormedMessage(message: Anthropic.MessageParam): Anthropic.MessageParam {
  if (typeof message.content === "string") {
    return { ...message, content: toWellFormedText(message.content) };
  }
  return {
    ...message,
    content: message.content.map((block) =>
      block.type === "text" ? { ...block, text: toWellFormedText(block.text) } : block,
    ),
  } as Anthropic.MessageParam;
}

function textLengthOf(message: Anthropic.MessageParam): string {
  if (typeof message.content === "string") return message.content;
  return message.content.map((block) => (block.type === "text" ? block.text : "")).join("");
}

/**
 * For a 4xx only: the rejected request's structure. The provider's error message is left
 * out on purpose -- it can quote the request -- as are all message text and headers.
 */
function clientErrorDiagnostic(
  error: unknown,
  status: number | undefined,
  stage: AiStage,
  attempt: number,
  system: string,
  messages: readonly Anthropic.MessageParam[],
): { request?: RequestDiagnostic } {
  if (status === undefined || status < 400 || status > 499) return {};
  const body = (error as { error?: { error?: { type?: unknown }; type?: unknown } } | null)?.error;
  const errorType = safeCode(body?.error?.type) ?? safeCode(body?.type);
  const rawId =
    (error as { request_id?: unknown; requestID?: unknown } | null)?.request_id ??
    (error as { requestID?: unknown } | null)?.requestID;
  const requestId = safeCode(rawId);
  const texts = messages.map(textLengthOf);
  return {
    request: {
      status,
      ...(errorType ? { errorType } : {}),
      ...(requestId ? { requestId } : {}),
      stage,
      attempt,
      messages: messages.map((message, i) => ({
        role: message.role,
        chars: texts[i].length,
        utf8Bytes: Buffer.byteLength(texts[i], "utf8"),
      })),
      systemChars: system.length,
      allMessagesNonEmpty: texts.every((text) => text.trim().length > 0),
      allMessagesWellFormed: texts.every(isWellFormedText),
    },
  };
}

// ---------------------------------------------------------------------------
// Response reading
// ---------------------------------------------------------------------------

/** The concatenated text blocks. A refusal never reaches here. */
function textOf(response: Anthropic.Message): string {
  if (response.stop_reason === "refusal") {
    throw new AiError("MODEL_REFUSED", "model declined the request", {
      cause: response.stop_details ?? undefined,
    });
  }
  const text = response.content
    .filter((block): block is Anthropic.TextBlock => block.type === "text")
    .map((block) => block.text)
    .join("");
  if (text.length > MAX_RESPONSE_CHARS) {
    throw new AiError(
      "MODEL_OUTPUT_INVALID",
      `model response of ${text.length} chars exceeds the ${MAX_RESPONSE_CHARS} cap`,
    );
  }
  return text;
}

function tokensOf(response: Anthropic.Message): TokenCounts {
  const usage = response.usage;
  return {
    inputTokens: usage?.input_tokens ?? 0,
    outputTokens: usage?.output_tokens ?? 0,
    thinkingTokens: usage?.output_tokens_details?.thinking_tokens ?? 0,
    cacheReadTokens: usage?.cache_read_input_tokens ?? 0,
    cacheWriteTokens: usage?.cache_creation_input_tokens ?? 0,
  };
}

/**
 * Reads an HTTP status off an SDK error. Structural rather than `instanceof` so a test
 * double can raise a 429 without constructing a real APIError, which needs a Response.
 */
function statusOf(error: unknown): number | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const status = (error as { status?: unknown }).status;
  return typeof status === "number" ? status : undefined;
}

/** The longest message kept from a thrown error. */
export const ERROR_MESSAGE_MAX_CHARS = 300;

/** Bounds the work redact() does on a hostile or enormous message. */
const ERROR_MESSAGE_SCAN_CHARS = 20_000;

/** Class names and codes are identifiers; anything else is not echoed. */
const SAFE_NAME = /^[A-Za-z0-9_$]{1,64}$/;
const SAFE_CODE = /^[A-Za-z0-9_.-]{1,64}$/;

export type ErrorKind =
  | "connection_timeout"
  | "connection_error"
  | "http_error"
  | "error"
  | "non_error";

export type ErrorClassification = {
  kind: ErrorKind;
  /** The SDK or JavaScript class, e.g. "APIConnectionError". The SDK leaves `name` as "Error". */
  className?: string;
  /** HTTP status, when the error carries one. */
  status?: number;
  /** A short code: a system code ("ECONNRESET") or an API error type ("invalid_request_error"). */
  code?: string;
  /** The class and code of the underlying cause, one level down. Never its message. */
  cause?: { className?: string; code?: string };
  /**
   * Redacted and capped at ERROR_MESSAGE_MAX_CHARS. Only for an Error with NO HTTP status:
   * a status error's message is the provider's response body, which can echo the request
   * (its prompt, its workspace id, its key) in a form no redactor recognises.
   */
  message?: string;
  /** For a thrown non-Error: its typeof, never its value. */
  valueType?: string;
};

function safeName(value: unknown): string | undefined {
  return typeof value === "string" && SAFE_NAME.test(value) ? value : undefined;
}

function safeCode(value: unknown): string | undefined {
  return typeof value === "string" && SAFE_CODE.test(value) ? value : undefined;
}

function classNameOf(error: object): string | undefined {
  const ctor = (error as { constructor?: { name?: unknown } }).constructor;
  return safeName(ctor?.name) ?? safeName((error as { name?: unknown }).name);
}

/** Redacted first, then collapsed and capped, so a cut can never leave half a secret. */
function safeMessage(message: string): string {
  const scanned = redact(message.slice(0, ERROR_MESSAGE_SCAN_CHARS), "error-message")
    .content.replace(/\s+/g, " ")
    .trim();
  return scanned.length <= ERROR_MESSAGE_MAX_CHARS
    ? scanned
    : `${scanned.slice(0, ERROR_MESSAGE_MAX_CHARS - 1)}…`;
}

/**
 * Sorts a thrown value into a kind and keeps only fields that are safe to log: class
 * names, a status, short codes, and, for an error without a status, a redacted, capped
 * message (a connection error's "Connection error." is written by the SDK; an HTTP error's
 * message is the provider's body and is left out). Nothing is read from
 * `headers`, `request`, `response` or `error` (the API's body), and a thrown value that is
 * not an Error contributes only its typeof. Classification is structural, as statusOf is,
 * so a test double needs no real SDK class.
 */
export function classifyError(error: unknown): ErrorClassification {
  if (typeof error !== "object" || error === null) {
    return { kind: "non_error", valueType: error === null ? "null" : typeof error };
  }
  const isErrorLike =
    error instanceof Error ||
    typeof (error as { message?: unknown }).message === "string";
  if (!isErrorLike) return { kind: "non_error", valueType: "object" };

  const className = classNameOf(error);
  const status = statusOf(error);
  const code =
    safeCode((error as { code?: unknown }).code) ??
    safeCode((error as { type?: unknown }).type);
  const rawCause = (error as { cause?: unknown }).cause;
  const cause =
    typeof rawCause === "object" && rawCause !== null
      ? {
          className: classNameOf(rawCause),
          code: safeCode((rawCause as { code?: unknown }).code),
        }
      : undefined;
  const message = (error as { message?: unknown }).message;

  let kind: ErrorKind = "error";
  if (/Timeout/i.test(className ?? "")) kind = "connection_timeout";
  else if (/Connection/i.test(className ?? "")) kind = "connection_error";
  else if (status !== undefined) kind = "http_error";

  return {
    kind,
    className,
    status,
    code,
    cause: cause && (cause.className || cause.code) ? cause : undefined,
    message:
      status === undefined && typeof message === "string" && message
        ? safeMessage(message)
        : undefined,
  };
}

const KIND_LABEL: Record<ErrorKind, string> = {
  connection_timeout: "connection timeout",
  connection_error: "connection error",
  http_error: "HTTP error",
  error: "error",
  non_error: "non-Error value",
};

/**
 * The cause of a failed call, as one line for an AiError message, e.g.
 * `connection error: APIConnectionError code=ECONNRESET cause=TypeError/ECONNRESET - Connection error.`
 * See classifyError for what it will and will not contain.
 */
function reasonOf(error: unknown): string {
  const c = classifyError(error);
  const parts: string[] = [`${KIND_LABEL[c.kind]}:`];
  if (c.valueType) parts.push(`(${c.valueType})`);
  if (c.className) parts.push(c.className);
  if (c.status !== undefined) parts.push(`HTTP ${c.status}`);
  if (c.code) parts.push(`code=${c.code}`);
  if (c.cause) {
    parts.push(
      `cause=${[c.cause.className, c.cause.code].filter(Boolean).join("/")}`,
    );
  }
  if (c.message) parts.push(`- ${c.message}`);
  return parts.join(" ");
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

type ParseOutcome<T> =
  | { ok: true; value: T }
  | { ok: false; issues: ValidationIssue[] };

export function parseAndValidate<T>(
  schema: z.ZodType<T>,
  text: string,
  truncated = false,
): ParseOutcome<T> {
  if (truncated) {
    return {
      ok: false,
      issues: [
        {
          path: "$",
          message:
            "the response was cut off at max_tokens; return the complete JSON, more briefly",
        },
      ],
    };
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (error) {
    // Never V8's own message: it quotes an excerpt of the invalid text, which can hold
    // repository-derived content and, cut mid-emoji, a lone surrogate that gets the
    // correction retry rejected. A fixed message, plus the numeric position if present.
    const position =
      error instanceof Error ? /\bposition (\d{1,9})\b/.exec(error.message)?.[1] : undefined;
    return {
      ok: false,
      issues: [
        {
          path: "$",
          message: position
            ? `response was not valid JSON (error at position ${position})`
            : "response was not valid JSON",
        },
      ],
    };
  }

  const result = schema.safeParse(json);
  if (result.success) return { ok: true, value: result.data };
  return { ok: false, issues: issuesOf(result.error) };
}

/** Paths and messages only. A Zod issue's `received` can quote repository content. */
function issuesOf(error: z.ZodError): ValidationIssue[] {
  return error.issues.map((issue) => ({
    path: issue.path.length > 0 ? issue.path.join(".") : "$",
    message: issue.message,
  }));
}

export function correctionMessage(
  issues: readonly ValidationIssue[],
): string {
  const lines = issues.map((issue) => `- ${issue.path}: ${issue.message}`);
  return [
    "Your previous response did not match the required schema:",
    ...lines,
    "",
    "Return the corrected, complete JSON object. Do not return a patch or a fragment,",
    "and do not include any text outside the JSON.",
  ].join("\n");
}

function truncate(text: string): string {
  return text.length <= ECHO_MAX_CHARS
    ? text
    : `${sliceWithoutSplitting(text, ECHO_MAX_CHARS)}\n... truncated ...`;
}

/** Stands in for an empty reply: the API rejects an assistant turn with no text. */
export const EMPTY_RESPONSE_PLACEHOLDER = "(empty response)";

/** The failed reply as the retry's assistant turn: non-empty, capped and well formed. */
export function echoOf(text: string): string {
  if (text.trim().length === 0) return EMPTY_RESPONSE_PLACEHOLDER;
  return toWellFormedText(truncate(text));
}

// ---------------------------------------------------------------------------
// Bookkeeping
// ---------------------------------------------------------------------------

function finishUsage(
  stage: AiStage,
  model: ModelId,
  tokens: TokenCounts,
  requests: number,
  stopReason?: string,
  responseModel?: string,
  callId?: string,
  attempt?: number,
): CallUsage {
  return {
    stage,
    model,
    ...tokens,
    requests,
    costUsd: estimateCostUsd(model, tokens),
    ...(stopReason === undefined ? {} : { stopReason }),
    ...(responseModel === undefined ? {} : { responseModel }),
    ...(callId === undefined ? {} : { callId }),
    ...(attempt === undefined ? {} : { attempt }),
  };
}

let callCounter = 0;

/** A process-unique id for one logical structured call. Not a secret and not random. */
function nextCallId(): string {
  callCounter += 1;
  return `call-${callCounter}`;
}

/**
 * The whole call as one CallUsage: every attempt's tokens, requests and cost summed. The
 * stop reason and reported model are the last response's. Not recorded anywhere, since the
 * ledger already holds the attempts it is made from.
 */
export function sumAttempts(attempts: readonly CallUsage[]): CallUsage {
  const last = attempts[attempts.length - 1];
  const tokens = attempts.reduce<TokenCounts>((sum, a) => addTokens(sum, a), NO_TOKENS);
  return {
    stage: last.stage,
    model: last.model,
    ...tokens,
    requests: attempts.reduce((n, a) => n + a.requests, 0),
    costUsd: attempts.reduce((n, a) => n + a.costUsd, 0),
    ...(last.stopReason === undefined ? {} : { stopReason: last.stopReason }),
    ...(last.responseModel === undefined ? {} : { responseModel: last.responseModel }),
    ...(last.callId === undefined ? {} : { callId: last.callId }),
  };
}

/**
 * Development only. The whole exchange goes to .debug/<analysisId>/, which is
 * gitignored, so a context can be read by hand when a prompt misbehaves.
 */
/** `<stage>[.<dumpKey>].attempt-<n>.txt`; an unsafe or empty key is simply left out. */
export function dumpFileName(stage: AiStage, attempt: number, dumpKey?: string): string {
  const key = dumpKey && /^[A-Za-z0-9_-]{1,32}$/.test(dumpKey) ? `.${dumpKey}` : "";
  return `${stage}${key}.attempt-${attempt}.txt`;
}

function writeDump(
  deps: ClaudeDeps,
  analysisId: string,
  stage: AiStage,
  attempt: number,
  system: string,
  messages: readonly Anthropic.MessageParam[],
  response: string,
  dumpKey?: string,
): void {
  const body = [
    `=== system ===`,
    system,
    ...messages.flatMap((message) => [
      `\n=== ${message.role} ===`,
      typeof message.content === "string"
        ? message.content
        : JSON.stringify(message.content),
    ]),
    `\n=== response ===`,
    response,
  ].join("\n");
  deps.writeDebug(analysisId, dumpFileName(stage, attempt, dumpKey), body);
}
