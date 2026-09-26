import type Anthropic from "@anthropic-ai/sdk";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  AiError,
  BACKOFF_BASE_MS,
  MAX_TRANSPORT_ATTEMPTS,
  ERROR_MESSAGE_MAX_CHARS,
  NON_STREAMING_MAX_TOKENS,
  TIMEOUT_MS,
  TRUNCATION_RETRY_TIME_MARGIN,
  callStructured,
  truncationRetryTimeoutMs,
  truncationRetryTokens,
  classifyError,
  EMPTY_RESPONSE_PLACEHOLDER,
  correctionMessage,
  dumpFileName,
  echoOf,
  parseAndValidate,
  toApiSchema,
  type ClaudeDeps,
  type MessagesApi,
} from "@/server/ai/claude";
import { UsageLedger } from "@/server/ai/usage";
import { SecretLeakError } from "@/server/security/redactor";
import { isWellFormedText, loneSurrogateOffsets } from "@/server/security/unicode";

// ---------------------------------------------------------------------------
// Harness. No network, no timers, no filesystem.
// ---------------------------------------------------------------------------

const Output = z.object({ summary: z.string(), risks: z.array(z.string()) });
type Output = z.infer<typeof Output>;

const JSON_SCHEMA = z.toJSONSchema(Output) as Record<string, unknown>;

const VALID: Output = { summary: "a small express app", risks: ["no csrf"] };

type Call = {
  body: Anthropic.MessageCreateParamsNonStreaming;
  signal?: AbortSignal;
};

/** A reply the model might send. A string is returned as a single text block. */
type Reply =
  | string
  | Error
  | ((call: Call) => string)
  | { text: string; overrides: Partial<Anthropic.Message> };

function message(
  text: string,
  overrides: Partial<Anthropic.Message> = {},
): Anthropic.Message {
  return {
    id: "msg_test",
    type: "message",
    role: "assistant",
    model: "claude-sonnet-5",
    content: [{ type: "text", text, citations: null }],
    stop_reason: "end_turn",
    stop_sequence: null,
    stop_details: null,
    usage: {
      input_tokens: 100,
      output_tokens: 20,
      cache_read_input_tokens: 0,
      cache_creation_input_tokens: 0,
    },
    ...overrides,
  } as Anthropic.Message;
}

/** An SDK-shaped failure. Structural: `status` is all the client reads. */
function httpError(status: number): Error & { status: number } {
  return Object.assign(new Error(`HTTP ${status}`), { status });
}

type Harness = {
  deps: Partial<ClaudeDeps>;
  calls: Call[];
  sleeps: number[];
  dumps: { file: string; body: string }[];
  ledger: UsageLedger;
  /** Fires the deadline that `schedule` was asked to set. */
  expire: () => void;
};

function harness(
  replies: readonly Reply[],
  options: { isDevelopment?: boolean } = {},
): Harness {
  const calls: Call[] = [];
  const sleeps: number[] = [];
  const dumps: { file: string; body: string }[] = [];
  const ledger = new UsageLedger();
  let fire: (() => void) | undefined;

  const client: MessagesApi = {
    async create(body, requestOptions) {
      const call = { body, signal: requestOptions?.signal };
      calls.push(call);
      // An aborted deadline must surface as a rejection, exactly as the SDK does.
      if (call.signal?.aborted) throw new Error("aborted");
      const reply = replies[calls.length - 1];
      if (reply === undefined) {
        throw new Error(`no reply scripted for request ${calls.length}`);
      }
      if (reply instanceof Error) throw reply;
      if (typeof reply === "object") return message(reply.text, reply.overrides);
      return message(typeof reply === "function" ? reply(call) : reply);
    },
  };

  return {
    calls,
    sleeps,
    dumps,
    ledger,
    expire: () => fire?.(),
    deps: {
      client,
      ledger,
      isDevelopment: options.isDevelopment ?? false,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
      schedule: (_ms, fn) => {
        fire = fn;
        return () => {
          fire = undefined;
        };
      },
      writeDebug: (_analysisId, file, body) => {
        dumps.push({ file, body });
      },
    },
  };
}

const run = (h: Harness, overrides: Record<string, unknown> = {}) =>
  callStructured<Output>({
    stage: "architecture",
    analysisId: "test-analysis",
    system: "You are a security reviewer.",
    user: '<repo_file path="README.md">\nA small app.\n</repo_file>',
    schema: Output,
    jsonSchema: JSON_SCHEMA,
    deps: h.deps,
    ...overrides,
  });

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

describe("callStructured, first reply valid", () => {
  it("returns the parsed value after a single request", async () => {
    const h = harness([JSON.stringify(VALID)]);
    const result = await run(h);

    expect(result.value).toEqual(VALID);
    expect(result.attempts).toBe(1);
    expect(h.calls).toHaveLength(1);
    expect(h.sleeps).toEqual([]);
  });

  it("constrains the output with the JSON schema it was given", async () => {
    const h = harness([JSON.stringify(VALID)]);
    await run(h);

    expect(h.calls[0].body.output_config).toEqual({
      format: { type: "json_schema", schema: JSON_SCHEMA },
    });
  });

  it("sends the system prompt as a cacheable block", async () => {
    const h = harness([JSON.stringify(VALID)]);
    await run(h);

    const system = h.calls[0].body.system;
    expect(Array.isArray(system)).toBe(true);
    const [block] = system as Anthropic.TextBlockParam[];
    expect(block.text).toBe("You are a security reviewer.");
    expect(block.cache_control).toEqual({ type: "ephemeral" });
  });

  it("picks the model from the active profile and defaults max_tokens to 8000", async () => {
    const h = harness([JSON.stringify(VALID)]);
    await run(h);

    expect(h.calls[0].body.model).toBe("claude-sonnet-5");
    expect(h.calls[0].body.max_tokens).toBe(8000);
  });

  it("honours an explicit max_tokens", async () => {
    const h = harness([JSON.stringify(VALID)]);
    await run(h, { maxTokens: 1234 });
    expect(h.calls[0].body.max_tokens).toBe(1234);
  });

  it("sends the user block as the only message", async () => {
    const h = harness([JSON.stringify(VALID)]);
    await run(h);

    expect(h.calls[0].body.messages).toHaveLength(1);
    expect(h.calls[0].body.messages[0].role).toBe("user");
  });
});

// ---------------------------------------------------------------------------
// The single validation retry (CLAUDE.md rule 5)
// ---------------------------------------------------------------------------

describe("callStructured, validation retry", () => {
  it("retries once and succeeds, quoting the Zod issues back", async () => {
    const h = harness([
      JSON.stringify({ summary: 42, risks: "not an array" }),
      JSON.stringify(VALID),
    ]);
    const result = await run(h);

    expect(result.value).toEqual(VALID);
    expect(result.attempts).toBe(2);
    expect(h.calls).toHaveLength(2);

    // The correction turn names the failing paths.
    const messages = h.calls[1].body.messages;
    expect(messages).toHaveLength(3);
    expect(messages[1].role).toBe("assistant");
    expect(messages[2].role).toBe("user");
    const correction = messages[2].content as string;
    expect(correction).toContain("summary");
    expect(correction).toContain("risks");
    expect(correction).toContain("did not match the required schema");
  });

  it("retries on malformed JSON", async () => {
    const h = harness(["{not json", JSON.stringify(VALID)]);
    const result = await run(h);

    expect(result.attempts).toBe(2);
    expect(h.calls[1].body.messages[2].content).toContain("not valid JSON");
  });

  it("retries JSON that looks cut off when the API did not report max_tokens", async () => {
    const truncated = '{"summary": "it was going so well';
    const h = harness([truncated, JSON.stringify(VALID)]);
    const result = await run(h);

    expect(result.attempts).toBe(2);
    expect(h.calls[1].body.messages[2].content).toContain("complete JSON");
  });

  it("throws AiError with the issues after a second failure", async () => {
    const bad = JSON.stringify({ summary: 1 });
    const h = harness([bad, bad]);

    const error = await run(h).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AiError);
    const aiError = error as AiError;
    expect(aiError.code).toBe("MODEL_OUTPUT_INVALID");
    expect(aiError.issues.length).toBeGreaterThan(0);
    expect(aiError.issues.map((i) => i.path)).toContain("summary");
    expect(h.calls).toHaveLength(2);
  });

  it("never sends a third request", async () => {
    const bad = "{}";
    const h = harness([bad, bad, JSON.stringify(VALID)]);
    await expect(run(h)).rejects.toBeInstanceOf(AiError);
    expect(h.calls).toHaveLength(2);
  });

  it("carries paths and messages only, never the offending values", async () => {
    // The value at the bad path is model output derived from repository content;
    // AiError gets logged, so it must not carry it.
    const leak = "AKIAIOSFODNN7EXAMPLE";
    const bad = JSON.stringify({ summary: { nested: leak }, risks: [] });
    const h = harness([bad, bad]);

    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    const serialised = JSON.stringify(error.issues);
    expect(serialised).not.toContain(leak);
  });
});

// ---------------------------------------------------------------------------
// Refusal
// ---------------------------------------------------------------------------

describe("callStructured, refusal", () => {
  it("fails immediately without spending the validation retry", async () => {
    const client: MessagesApi = {
      async create() {
        return message("", {
          stop_reason: "refusal",
          stop_details: { type: "refusal", category: "cyber", explanation: "no" },
        } as Partial<Anthropic.Message>);
      },
    };
    const h = harness([]);
    h.deps.client = client;

    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("MODEL_REFUSED");
    expect(error.message).toContain("declined");
  });

  it("reports a response over the size cap as MODEL_OUTPUT_INVALID, not the catch-all", async () => {
    // 4,000,000 characters is the client's own cap; one more is unusable output.
    const h = harness(["x".repeat(4_000_001)]);
    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("MODEL_OUTPUT_INVALID");
    expect(error.message).toContain("exceeds");
  });
});

// ---------------------------------------------------------------------------
// Transport backoff
// ---------------------------------------------------------------------------

describe("callStructured, backoff", () => {
  it.each([429, 529, 500, 503])("retries a %s and succeeds", async (status) => {
    const h = harness([httpError(status), JSON.stringify(VALID)]);
    const result = await run(h);

    expect(result.value).toEqual(VALID);
    expect(result.attempts).toBe(1);
    expect(h.calls).toHaveLength(2);
    expect(h.sleeps).toEqual([BACKOFF_BASE_MS]);
  });

  it("backs off exponentially across the attempt cap", async () => {
    const h = harness([httpError(529), httpError(529), JSON.stringify(VALID)]);
    await run(h);

    expect(h.sleeps).toEqual([BACKOFF_BASE_MS, BACKOFF_BASE_MS * 2]);
    expect(h.calls).toHaveLength(MAX_TRANSPORT_ATTEMPTS);
  });

  it("gives up after the attempt cap, with UPSTREAM_RATE_LIMITED for a 429", async () => {
    const h = harness([httpError(429), httpError(429), httpError(429)]);

    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error.code).toBe("UPSTREAM_RATE_LIMITED");
    expect(h.calls).toHaveLength(MAX_TRANSPORT_ATTEMPTS);
    // One sleep fewer than attempts: it never waits after the final failure.
    expect(h.sleeps).toHaveLength(MAX_TRANSPORT_ATTEMPTS - 1);
  });

  it("does not exceed the attempt cap on a persistent 529", async () => {
    const h = harness([httpError(529), httpError(529), httpError(529)]);
    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error.code).toBe("AI_FAILURE");
    expect(h.calls).toHaveLength(MAX_TRANSPORT_ATTEMPTS);
  });

  it.each([400, 401, 404, 422])("fails a %s immediately", async (status) => {
    const h = harness([httpError(status), JSON.stringify(VALID)]);

    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error.code).toBe("AI_FAILURE");
    expect(h.calls).toHaveLength(1);
    expect(h.sleeps).toEqual([]);
  });

  it("keeps a provider error's message out of the error it raises", async () => {
    // An SDK error body can echo request content, and this error gets logged.
    const leaky = Object.assign(new Error("invalid request: AKIAIOSFODNN7EXAMPLE"), {
      status: 400,
    });
    const h = harness([leaky]);

    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error.message).not.toContain("AKIA");
    expect(error.message).toContain("HTTP 400");
  });
});

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

describe("callStructured, deadline", () => {
  it("maps an expired deadline to TIMEOUT", async () => {
    const h = harness([]);
    // Abort before the first request is made: the client sees an aborted signal.
    h.deps.client = {
      async create(_body, options) {
        h.expire();
        if (options?.signal?.aborted) throw new Error("aborted");
        return message(JSON.stringify(VALID));
      },
    };

    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("TIMEOUT");
  });

  it("passes an abort signal to every request", async () => {
    const h = harness([JSON.stringify(VALID)]);
    await run(h);
    expect(h.calls[0].signal).toBeInstanceOf(AbortSignal);
    expect(h.calls[0].signal?.aborted).toBe(false);
  });

  it("does not retry a timeout as if it were a transport fault", async () => {
    const h = harness([]);
    let seen = 0;
    h.deps.client = {
      async create() {
        seen++;
        h.expire();
        throw httpError(529);
      },
    };

    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error.code).toBe("TIMEOUT");
    expect(seen).toBe(1);
    expect(h.sleeps).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Secrets (CLAUDE.md rule 3)
// ---------------------------------------------------------------------------

describe("callStructured, secret guard", () => {
  const DEPLOY_WRAPPER = '<repo_file path=".github/workflows/deploy-pages.yml">';

  it("reaches the client for a prompt with a generated .github/workflows/deploy-pages.yml wrapper", async () => {
    const h = harness([JSON.stringify(VALID)]);

    await run(h, { user: `${DEPLOY_WRAPPER}\n1| name: Deploy\n</repo_file>` });

    expect(h.calls).toHaveLength(1);
  });

  it("still refuses, before any provider request, when that wrapper's content holds a real secret", async () => {
    const h = harness([JSON.stringify(VALID)]);

    await expect(
      run(h, { user: `${DEPLOY_WRAPPER}\n1| const id = "AKIAIOSFODNN7EXAMPLE";\n</repo_file>` }),
    ).rejects.toBeInstanceOf(SecretLeakError);
    expect(h.calls).toHaveLength(0);
  });

  it("refuses, before any provider request, when a wrapper's path is secret-shaped", async () => {
    const h = harness([JSON.stringify(VALID)]);

    await expect(
      run(h, { user: '<repo_file path="keys/AKIAIOSFODNN7EXAMPLE.txt">\n1| hi\n</repo_file>' }),
    ).rejects.toBeInstanceOf(SecretLeakError);
    expect(h.calls).toHaveLength(0);
  });

  it("refuses to send a user block holding a credential", async () => {
    const h = harness([JSON.stringify(VALID)]);

    await expect(
      run(h, { user: 'const key = "AKIAIOSFODNN7EXAMPLE";' }),
    ).rejects.toBeInstanceOf(SecretLeakError);
    expect(h.calls).toHaveLength(0);
  });

  it("writes no debug dump for a call it refused to make", async () => {
    const h = harness([JSON.stringify(VALID)], { isDevelopment: true });

    await expect(
      run(h, { user: "aws_key = 'AKIAIOSFODNN7EXAMPLE'" }),
    ).rejects.toBeInstanceOf(SecretLeakError);
    expect(h.dumps).toEqual([]);
  });

  it("records nothing in the ledger for a call it refused to make", async () => {
    const h = harness([JSON.stringify(VALID)]);
    await expect(
      run(h, { user: 'token = "AKIAIOSFODNN7EXAMPLE"' }),
    ).rejects.toThrow();
    expect(h.ledger.forAnalysis("test-analysis").calls).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Debug dumps (CLAUDE.md rule 8)
// ---------------------------------------------------------------------------

describe("callStructured, debug dumps", () => {
  it("writes nothing outside development", async () => {
    const h = harness([JSON.stringify(VALID)], { isDevelopment: false });
    await run(h);
    expect(h.dumps).toEqual([]);
  });

  it("writes one dump per attempt in development", async () => {
    const h = harness(["{}", JSON.stringify(VALID)], { isDevelopment: true });
    await run(h);

    expect(h.dumps.map((d) => d.file)).toEqual([
      "architecture.attempt-1.txt",
      "architecture.attempt-2.txt",
    ]);
    expect(h.dumps[0].body).toContain("You are a security reviewer.");
    expect(h.dumps[0].body).toContain("README.md");
  });
});

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

describe("callStructured, usage", () => {
  it("records stage, model, tokens and an estimated cost", async () => {
    const h = harness([JSON.stringify(VALID)]);
    const result = await run(h);

    expect(result.usage.stage).toBe("architecture");
    expect(result.usage.model).toBe("claude-sonnet-5");
    expect(result.usage.inputTokens).toBe(100);
    expect(result.usage.outputTokens).toBe(20);
    expect(result.usage.requests).toBe(1);
    // 100 in at $2/M + 20 out at $10/M.
    expect(result.usage.costUsd).toBeCloseTo((100 * 2 + 20 * 10) / 1e6, 12);
  });

  it("counts a retried call as two provider responses, and its usage sums both", async () => {
    const h = harness(["{}", JSON.stringify(VALID)]);
    const result = await run(h);

    expect(result.usage.inputTokens).toBe(200);
    expect(result.usage.outputTokens).toBe(40);
    expect(result.usage.requests).toBe(2);
    expect(result.attemptUsage).toHaveLength(2);
    expect(h.ledger.forAnalysis("test-analysis").calls).toHaveLength(2);
    expect(h.ledger.forAnalysis("test-analysis").totals.inputTokens).toBe(200);
  });
  it("counts the backoff retries in the request tally", async () => {
    const h = harness([httpError(529), JSON.stringify(VALID)]);
    const result = await run(h);
    expect(result.usage.requests).toBe(2);
  });

  it("still records what a failed call cost: both attempts", async () => {
    const h = harness(["{}", "{}"]);
    await expect(run(h)).rejects.toBeInstanceOf(AiError);

    const total = h.ledger.forAnalysis("test-analysis");
    expect(total.calls).toHaveLength(2);
    expect(total.totalUsd).toBeGreaterThan(0);
  });
  it("accumulates across calls in the same analysis", async () => {
    const h = harness([JSON.stringify(VALID), JSON.stringify(VALID)]);
    await run(h);
    await run(h, { stage: "stride" });

    const total = h.ledger.forAnalysis("test-analysis");
    expect(total.calls).toHaveLength(2);
    expect(total.totals.inputTokens).toBe(200);
  });

  it("reads cache tokens off the response", async () => {
    const h = harness([]);
    h.deps.client = {
      async create() {
        return message(JSON.stringify(VALID), {
          usage: {
            input_tokens: 10,
            output_tokens: 5,
            cache_read_input_tokens: 4000,
            cache_creation_input_tokens: 100,
          },
        } as Partial<Anthropic.Message>);
      },
    };

    const result = await run(h);
    expect(result.usage.cacheReadTokens).toBe(4000);
    expect(result.usage.cacheWriteTokens).toBe(100);
  });

  it("treats null token counts as zero rather than NaN", async () => {
    const h = harness([]);
    h.deps.client = {
      async create() {
        return message(JSON.stringify(VALID), {
          usage: {
            input_tokens: null,
            output_tokens: 7,
            cache_read_input_tokens: null,
            cache_creation_input_tokens: null,
          },
        } as unknown as Partial<Anthropic.Message>);
      },
    };

    const result = await run(h);
    expect(result.usage.inputTokens).toBe(0);
    expect(Number.isNaN(result.usage.costUsd)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The pure pieces
// ---------------------------------------------------------------------------

describe("parseAndValidate", () => {
  it("accepts a valid payload", () => {
    const outcome = parseAndValidate(Output, JSON.stringify(VALID));
    expect(outcome).toEqual({ ok: true, value: VALID });
  });

  it("reports the truncation before it tries to parse", () => {
    const outcome = parseAndValidate(Output, "{", true);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.issues[0].message).toContain("cut off");
  });

  it("reports unparseable JSON at the root path", () => {
    const outcome = parseAndValidate(Output, "nope");
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.issues[0].path).toBe("$");
  });

  it("joins a nested Zod path with dots", () => {
    const Nested = z.object({ a: z.object({ b: z.string() }) });
    const outcome = parseAndValidate(Nested, JSON.stringify({ a: { b: 1 } }));
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.issues[0].path).toBe("a.b");
  });

  it("strips unknown keys rather than failing on them", () => {
    // Zod's default. A stray invented field must not consume the single retry.
    const outcome = parseAndValidate(
      Output,
      JSON.stringify({ ...VALID, invented: true }),
    );
    expect(outcome).toEqual({ ok: true, value: VALID });
  });
});

describe("correctionMessage", () => {
  it("lists each issue and asks for the whole object back", () => {
    const text = correctionMessage([
      { path: "summary", message: "expected string" },
      { path: "risks.0", message: "expected string" },
    ]);
    expect(text).toContain("- summary: expected string");
    expect(text).toContain("- risks.0: expected string");
    expect(text).toContain("complete JSON");
    expect(text).toContain("Do not return a patch");
  });
});

// ---------------------------------------------------------------------------
// API-compatible schema
// ---------------------------------------------------------------------------

describe("toApiSchema", () => {
  const RANGED = z.object({
    impact: z.number().int().min(1).max(5),
    name: z.string().min(1).describe("a label"),
    tags: z.array(z.number().min(0).max(9)),
    either: z.union([z.number().int().min(1), z.null()]),
    nested: z.object({ score: z.number().int().max(3) }),
  });
  const schema = z.toJSONSchema(RANGED) as Record<string, unknown>;

  it("removes minimum and maximum at every depth", () => {
    const sent = JSON.stringify(toApiSchema(schema));
    expect(sent).not.toContain('"minimum"');
    expect(sent).not.toContain('"maximum"');
    // The input really had them, so the assertion above is not vacuous.
    expect(JSON.stringify(schema)).toContain('"minimum"');
    expect(JSON.stringify(schema)).toContain('"maximum"');
  });

  it("removes every unsupported keyword, in objects, arrays, anyOf, oneOf, allOf and definitions", () => {
    const input = {
      type: "object",
      properties: {
        a: { type: "integer", minimum: 1, maximum: 5, exclusiveMinimum: 0, exclusiveMaximum: 6, multipleOf: 2 },
        b: { anyOf: [{ type: "integer", minimum: 1 }, { type: "null" }] },
        c: { oneOf: [{ type: "number", maximum: 3 }] },
        d: { allOf: [{ type: "number", exclusiveMinimum: 0 }] },
        e: { type: "array", items: { type: "integer", maximum: 9 } },
      },
      $defs: { Score: { type: "integer", minimum: 0 } },
      definitions: { Old: { type: "integer", maximum: 1 } },
    };
    expect(toApiSchema(input)).toEqual({
      type: "object",
      properties: {
        a: { type: "integer" },
        b: { anyOf: [{ type: "integer" }, { type: "null" }] },
        c: { oneOf: [{ type: "number" }] },
        d: { allOf: [{ type: "number" }] },
        e: { type: "array", items: { type: "integer" } },
      },
      $defs: { Score: { type: "integer" } },
      definitions: { Old: { type: "integer" } },
    });
  });

  it("keeps structural and descriptive fields", () => {
    const sent = toApiSchema(schema) as {
      required: string[];
      additionalProperties?: unknown;
      properties: Record<string, { type?: string; description?: string; minLength?: number; anyOf?: unknown[] }>;
    };
    expect(sent.required).toEqual(["impact", "name", "tags", "either", "nested"]);
    expect(sent.properties.impact.type).toBe("integer");
    expect(sent.properties.name.description).toBe("a label");
    expect(sent.properties.name.minLength).toBe(1);
    expect(sent.properties.either.anyOf).toHaveLength(2);
    expect(sent.additionalProperties).toBe(false);
  });

  it("drops maxItems always and minItems unless it is 0 or 1, at any depth", () => {
    const input = {
      type: "object",
      properties: {
        options: { type: "array", items: { type: "string" }, minItems: 2, maxItems: 4 },
        tags: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 9 },
        any: { type: "array", items: { type: "string" }, minItems: 0 },
        nested: {
          anyOf: [{ type: "array", items: { type: "array", minItems: 3 } }, { type: "null" }],
        },
        maxItems: { type: "array", minItems: 5 },
      },
    };
    expect(toApiSchema(input)).toEqual({
      type: "object",
      properties: {
        options: { type: "array", items: { type: "string" } },
        tags: { type: "array", items: { type: "string" }, minItems: 1 },
        any: { type: "array", items: { type: "string" }, minItems: 0 },
        nested: { anyOf: [{ type: "array", items: { type: "array" } }, { type: "null" }] },
        // A property NAMED maxItems is a field, not the keyword.
        maxItems: { type: "array" },
      },
    });
  });

  it("keeps a property that happens to be named after a keyword, and enum and default data", () => {
    const input = {
      type: "object",
      required: ["minimum"],
      properties: {
        minimum: { type: "integer", minimum: 1 },
        kind: { enum: ["a", "b"], default: { maximum: 3 } },
      },
    };
    expect(toApiSchema(input)).toEqual({
      type: "object",
      required: ["minimum"],
      properties: {
        minimum: { type: "integer" },
        kind: { enum: ["a", "b"], default: { maximum: 3 } },
      },
    });
  });

  it("treats the names under every schema map as names, not keywords", () => {
    const entry = { type: "integer", minimum: 0 };
    const input = {
      properties: { minimum: entry },
      patternProperties: { minimum: entry },
      $defs: { minimum: entry },
      definitions: { minimum: entry },
      dependentSchemas: { minimum: entry },
    };
    const clean = { type: "integer" };
    expect(toApiSchema(input)).toEqual({
      properties: { minimum: clean },
      patternProperties: { minimum: clean },
      $defs: { minimum: clean },
      definitions: { minimum: clean },
      dependentSchemas: { minimum: clean },
    });
  });

  it("keeps an array an array even under a schema-map key", () => {
    expect(toApiSchema({ properties: [{ type: "integer", minimum: 1 }] })).toEqual({
      properties: [{ type: "integer" }],
    });
  });

  it("copies enum, const, default and examples as data without rewriting them", () => {
    const input = {
      enum: [{ maximum: 1 }],
      const: { minimum: 2 },
      default: { minimum: 3 },
      examples: [{ maximum: 4 }],
    };
    expect(toApiSchema(input)).toEqual(input);
  });

  it("does not mutate the caller's schema", () => {
    const input = {
      type: "object",
      properties: { n: { type: "integer", minimum: 1, maximum: 5 }, k: { enum: [{ maximum: 1 }] } },
    };
    const before = JSON.stringify(input);
    const out = toApiSchema(input) as typeof input;
    expect(JSON.stringify(input)).toBe(before);
    expect(out).not.toBe(input);
    expect(out.properties).not.toBe(input.properties);
    // Data copied, not shared.
    (out.properties.k.enum[0] as { maximum: number }).maximum = 99;
    expect(JSON.stringify(input)).toBe(before);
  });

  it("returns non-objects unchanged", () => {
    expect(toApiSchema("x")).toBe("x");
    expect(toApiSchema(3)).toBe(3);
    expect(toApiSchema(null)).toBeNull();
  });
});

describe("callStructured, schema on the wire", () => {
  const RANGE = z.object({ impact: z.number().int().min(1).max(5) });
  const RANGE_JSON = z.toJSONSchema(RANGE) as Record<string, unknown>;

  it("sends the API-compatible schema and leaves the caller's schema untouched", async () => {
    const h = harness([JSON.stringify({ impact: 3 })]);
    const before = JSON.stringify(RANGE_JSON);
    await callStructured({
      stage: "architecture",
      analysisId: "a",
      system: "s",
      user: "u",
      schema: RANGE,
      jsonSchema: RANGE_JSON,
      deps: h.deps,
    });
    const sent = JSON.stringify(h.calls[0].body.output_config);
    expect(sent).not.toContain('"minimum"');
    expect(sent).not.toContain('"maximum"');
    expect(sent).toContain('"integer"');
    expect(JSON.stringify(RANGE_JSON)).toBe(before);
  });

  it("still enforces the range on the reply with the Zod schema", async () => {
    const h = harness([JSON.stringify({ impact: 9 }), JSON.stringify({ impact: 9 })]);
    const error = (await callStructured({
      stage: "architecture",
      analysisId: "a",
      system: "s",
      user: "u",
      schema: RANGE,
      jsonSchema: RANGE_JSON,
      deps: h.deps,
    }).catch((e: unknown) => e)) as AiError;
    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("MODEL_OUTPUT_INVALID");
    expect(error.issues.length).toBeGreaterThan(0);
    expect(h.calls).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Per-call deadline
// ---------------------------------------------------------------------------

describe("callStructured, per-call timeout", () => {
  function scheduled(h: Harness): number[] {
    const asked: number[] = [];
    const inner = h.deps.schedule!;
    h.deps.schedule = (ms, fn) => {
      asked.push(ms);
      return inner(ms, fn);
    };
    return asked;
  }

  it("keeps the 120 second default for a caller that does not ask", async () => {
    const h = harness([JSON.stringify(VALID)]);
    const asked = scheduled(h);
    await run(h);
    expect(TIMEOUT_MS).toBe(120_000);
    expect(asked).toEqual([120_000]);
  });

  it("uses the deadline a caller asks for", async () => {
    const h = harness([JSON.stringify(VALID)]);
    const asked = scheduled(h);
    await run(h, { timeoutMs: 300_000 });
    expect(asked).toEqual([300_000]);
  });

  it("reports the deadline that expired in the TIMEOUT error", async () => {
    const h = harness([]);
    h.deps.client = {
      async create(_body, options) {
        h.expire();
        if (options?.signal?.aborted) throw new Error("aborted");
        return message(JSON.stringify(VALID));
      },
    };
    const error = (await run(h, { timeoutMs: 300_000 }).catch((e: unknown) => e)) as AiError;
    expect(error.code).toBe("TIMEOUT");
    expect(error.message).toContain("300000ms");
    expect(error.message).not.toContain("120000ms");
  });

  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects a deadline of %s before any request is made",
    async (timeoutMs) => {
      const h = harness([JSON.stringify(VALID)]);
      await expect(run(h, { timeoutMs })).rejects.toThrow(/timeoutMs/);
      expect(h.calls).toHaveLength(0);
    },
  );

  it("does not retry after a timeout", async () => {
    const h = harness([]);
    h.deps.client = {
      async create(_body, options) {
        h.expire();
        if (options?.signal?.aborted) throw new Error("aborted");
        return message("unreachable");
      },
    };
    const error = (await run(h, { timeoutMs: 1000 }).catch((e: unknown) => e)) as AiError;
    expect(error.code).toBe("TIMEOUT");
    expect(h.sleeps).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Error diagnostics
// ---------------------------------------------------------------------------

/** Shaped like the SDK's classes: their `name` stays "Error", only the class differs. */
class APIConnectionError extends Error {
  constructor(message = "Connection error.", cause?: unknown) {
    super(message);
    if (cause !== undefined) (this as { cause?: unknown }).cause = cause;
  }
}
class APIConnectionTimeoutError extends APIConnectionError {
  constructor() {
    super("Request timed out.");
  }
}
class RateLimitError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly type?: string,
  ) {
    super(message);
  }
}

const SECRET = "AKIAZZTHREATZZ000001";

/** Makes every request throw exactly `thrown`, whatever it is. */
async function failure(thrown: unknown) {
  const h = harness([]);
  h.deps.client = {
    async create(body, options) {
      h.calls.push({ body, signal: options?.signal });
      throw thrown;
    },
  };
  const error = (await run(h).catch((e: unknown) => e)) as AiError;
  return { error, h };
}

describe("callStructured, safe error diagnostics", () => {
  it("names a connection error, its class, its code and its cause, without retrying", async () => {
    const cause = Object.assign(new TypeError("fetch failed: secret-detail"), {
      code: "UND_ERR_HEADERS_TIMEOUT",
    });
    const { error, h } = await failure(new APIConnectionError("Connection error.", cause));
    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("AI_FAILURE");
    expect(error.message).toContain("connection error:");
    expect(error.message).toContain("APIConnectionError");
    expect(error.message).toContain("cause=TypeError/UND_ERR_HEADERS_TIMEOUT");
    expect(error.message).toContain("Connection error.");
    // The cause's own message is never copied.
    expect(error.message).not.toContain("secret-detail");
    expect(h.calls).toHaveLength(1);
  });

  it("names a connection timeout as a different kind from a connection error", async () => {
    const { error, h } = await failure(new APIConnectionTimeoutError());
    expect(error.code).toBe("AI_FAILURE");
    expect(error.message).toContain("connection timeout:");
    expect(error.message).toContain("APIConnectionTimeoutError");
    expect(error.message).not.toContain("connection error:");
    expect(h.calls).toHaveLength(1);
  });

  it("names an HTTP status error with its status, class and API error type", async () => {
    const { error, h } = await failure(
      new RateLimitError(400, '400 {"error":{"type":"invalid_request_error"}}', "invalid_request_error"),
    );
    expect(error.code).toBe("AI_FAILURE");
    expect(error.message).toContain("HTTP error: RateLimitError HTTP 400 code=invalid_request_error");
    expect(h.calls).toHaveLength(1);
  });

  it("never includes the message of an HTTP status error, which is the provider's body", async () => {
    const echoed = `echo of ${SECRET} and wrkspc_ECHOEDWORKSPACE and a harmless sentence`;
    const c = classifyError(new RateLimitError(400, echoed, "invalid_request_error"));
    expect(c.kind).toBe("http_error");
    expect(c.message).toBeUndefined();
    const { error } = await failure(new RateLimitError(400, echoed, "invalid_request_error"));
    expect(error.message).not.toContain("wrkspc_ECHOEDWORKSPACE");
    expect(error.message).not.toContain("harmless sentence");
    expect(error.message).not.toContain(SECRET);
  });

  it("keeps the UPSTREAM_RATE_LIMITED code and the retry count for a persistent 429", async () => {
    const { error, h } = await failure(new RateLimitError(429, "429 slow down", "rate_limit_error"));
    expect(error.code).toBe("UPSTREAM_RATE_LIMITED");
    expect(h.calls).toHaveLength(MAX_TRANSPORT_ATTEMPTS);
    expect(error.message).toContain(`after ${MAX_TRANSPORT_ATTEMPTS} attempts`);
    expect(error.message).toContain("HTTP 429");
    expect(error.message).toContain("code=rate_limit_error");
  });

  it("names an ordinary Error by class and message", async () => {
    class WeirdFailure extends Error {}
    const { error, h } = await failure(new WeirdFailure("boom happened"));
    expect(error.code).toBe("AI_FAILURE");
    expect(error.message).toContain("error: WeirdFailure - boom happened");
    expect(h.calls).toHaveLength(1);
  });

  it.each([
    ["a string", "just a string " + SECRET, "string"],
    ["a number", 42, "number"],
    ["null", null, "null"],
    ["an object without a message", { detail: SECRET }, "object"],
  ])("reports only the type of a thrown %s, never its value", async (_name, value, type) => {
    const { error, h } = await failure(value);
    expect(error.code).toBe("AI_FAILURE");
    expect(error.message).toContain(`non-Error value: (${type})`);
    expect(error.message).not.toContain(SECRET);
    expect(error.message).not.toContain("just a string");
    expect(h.calls).toHaveLength(1);
  });

  it("never includes headers, request, response or the API's body", () => {
    const error = Object.assign(new APIConnectionError("Connection error."), {
      status: undefined,
      headers: { authorization: "Bearer TOPSECRETHEADER", "x-api-key": "sk-ant-KEYVALUE" },
      request: { body: "REPOCONTENTINREQUEST" },
      response: { body: "MODELOUTPUTINRESPONSE" },
      error: { error: { message: "ECHOEDPROMPTTEXT" } },
    });
    const c = classifyError(error);
    const text = JSON.stringify(c);
    for (const leak of ["TOPSECRETHEADER", "KEYVALUE", "REPOCONTENTINREQUEST", "MODELOUTPUTINRESPONSE", "ECHOEDPROMPTTEXT"]) {
      expect(text).not.toContain(leak);
    }
    expect(c.kind).toBe("connection_error");
  });

  it("drops a class name or code that is not a plain identifier", () => {
    const error = Object.assign(new Error("x"), { code: "has spaces and SECRET", type: "no good!" });
    Object.defineProperty(error, "constructor", { value: { name: "Bad Name!" } });
    Object.defineProperty(error, "name", { value: "Also bad" });
    const c = classifyError(error);
    expect(c.className).toBeUndefined();
    expect(c.code).toBeUndefined();
  });

  it("falls back to the error's own name when the class name is unusable", () => {
    const error = Object.assign(new Error("x"), { name: "CustomName" });
    Object.defineProperty(error, "constructor", { value: {} });
    expect(classifyError(error).className).toBe("CustomName");
  });

  it("caps the message at 300 characters", () => {
    const c = classifyError(new Error("word ".repeat(400)));
    expect(ERROR_MESSAGE_MAX_CHARS).toBe(300);
    expect(c.message).toHaveLength(300);
    expect(c.message!.endsWith("…")).toBe(true);
    expect(classifyError(new Error("short")).message).toBe("short");
    expect(classifyError(new Error("x".repeat(300))).message).toHaveLength(300);
    expect(classifyError(new Error("x".repeat(300))).message!.endsWith("…")).toBe(false);
  });

  it("collapses whitespace so a message cannot spread across log lines", () => {
    expect(classifyError(new Error("a\n\n  b\t c")).message).toBe("a b c");
  });

  it("redacts a secret in the message", () => {
    const c = classifyError(new Error(`upstream said key=${SECRET} is invalid`));
    expect(c.message).not.toContain(SECRET);
    expect(c.message).toContain("[REDACTED:");
  });

  it("redacts before truncating, so a cut never leaves part of a secret", () => {
    const c = classifyError(new Error(`${"a ".repeat(140)}${SECRET} and more text after it`));
    expect(c.message).not.toContain("AKIAZZ");
    expect(c.message).not.toContain("THREATZZ");
  });

  it("gives an error with no message no message field", () => {
    expect(classifyError(new Error("")).message).toBeUndefined();
  });

  it("does not change retry behaviour: a status-less error is still not retried", async () => {
    const { h } = await failure(new APIConnectionError());
    expect(h.calls).toHaveLength(1);
    expect(h.sleeps).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Usage on every received response
// ---------------------------------------------------------------------------

const usageOf = (
  input: number,
  output: number,
  extra: Partial<{ thinking: number | null; read: number; write: number }> = {},
) =>
  ({
    input_tokens: input,
    output_tokens: output,
    cache_read_input_tokens: extra.read ?? 0,
    cache_creation_input_tokens: extra.write ?? 0,
    output_tokens_details:
      extra.thinking === null || extra.thinking === undefined
        ? null
        : { thinking_tokens: extra.thinking },
  }) as Anthropic.Message["usage"];

const reply = (text: string, overrides: Partial<Anthropic.Message> = {}): Reply => ({
  text,
  overrides,
});

const entries = (h: Harness) => h.ledger.forAnalysis("test-analysis").calls;

describe("callStructured, usage is recorded when a response arrives", () => {
  it("records every field the response provides, for a call that validates", async () => {
    const h = harness([
      reply(JSON.stringify(VALID), {
        model: "claude-sonnet-5-20260901",
        stop_reason: "end_turn",
        usage: usageOf(100, 50, { thinking: 30, read: 400, write: 60 }),
      }),
    ]);
    const result = await run(h);
    const [only] = entries(h);

    expect(entries(h)).toHaveLength(1);
    expect(only).toBe(result.attemptUsage[0]);
    expect(only).toMatchObject({
      stage: "architecture",
      model: "claude-sonnet-5",
      responseModel: "claude-sonnet-5-20260901",
      stopReason: "end_turn",
      inputTokens: 100,
      outputTokens: 50,
      thinkingTokens: 30,
      cacheReadTokens: 400,
      cacheWriteTokens: 60,
      requests: 1,
      attempt: 1,
    });
    expect(only.callId).toMatch(/^call-\d+$/);
    expect(result.usage.callId).toBe(only.callId);
    // Thinking is part of the 50 output tokens, so it is not priced on top of them.
    expect(only.costUsd).toBeCloseTo((100 * 2 + 50 * 10 + 400 * 2 * 0.1 + 60 * 2 * 1.25) / 1e6, 12);
    expect(result.usage.costUsd).toBeCloseTo(only.costUsd, 12);
  });
  it("reports zero thinking tokens when the response carries no breakdown", async () => {
    const h = harness([reply(JSON.stringify(VALID), { usage: usageOf(1, 2, { thinking: null }) })]);
    await run(h);
    expect(entries(h)[0].thinkingTokens).toBe(0);
  });

  it("does not echo a model id that is not a plain identifier", async () => {
    const h = harness([reply(JSON.stringify(VALID), { model: "bad model! {}" as never })]);
    await run(h);
    expect(entries(h)[0].responseModel).toBeUndefined();
  });

  it("keeps the usage of a reply that fails schema validation: one entry per attempt", async () => {
    const bad = JSON.stringify({ summary: 1 });
    const h = harness([
      reply(bad, { usage: usageOf(100, 20, { thinking: 5 }) }),
      reply(bad, { usage: usageOf(120, 30, { thinking: 7 }), stop_reason: "end_turn" }),
    ]);
    await expect(run(h)).rejects.toBeInstanceOf(AiError);

    expect(entries(h)).toHaveLength(2);
    expect(entries(h)[0]).toMatchObject({ attempt: 1, inputTokens: 100, outputTokens: 20, thinkingTokens: 5, requests: 1 });
    expect(entries(h)[1]).toMatchObject({ attempt: 2, inputTokens: 120, outputTokens: 30, thinkingTokens: 7, requests: 1, stopReason: "end_turn" });
    expect(entries(h)[1].callId).toBe(entries(h)[0].callId);
    const total = h.ledger.forAnalysis("test-analysis").totals;
    expect(total).toMatchObject({ inputTokens: 220, outputTokens: 50, thinkingTokens: 12 });
  });
  it("counts an invalid first response plus a valid retry as two attempts: two 100-token attempts total 200, not 100", async () => {
    const h = harness([
      reply("{}", { usage: usageOf(100, 20) }),
      reply(JSON.stringify(VALID), { usage: usageOf(100, 40) }),
    ]);
    const result = await run(h);

    expect(result.attempts).toBe(2);
    expect(entries(h)).toHaveLength(2);
    expect(entries(h).map((e) => e.attempt)).toEqual([1, 2]);
    expect(result.attemptUsage).toEqual(entries(h));
    const total = h.ledger.forAnalysis("test-analysis");
    expect(total.totals.inputTokens).toBe(200);
    expect(total.totals.outputTokens).toBe(60);
    expect(result.usage.inputTokens).toBe(200);
    expect(result.usage.requests).toBe(2);
    // The cost is the sum of the two attempts' costs, in the returned usage and the ledger alike.
    const each = entries(h).map((e) => e.costUsd);
    expect(each[0]).toBeCloseTo((100 * 2 + 20 * 10) / 1e6, 12);
    expect(each[1]).toBeCloseTo((100 * 2 + 40 * 10) / 1e6, 12);
    expect(total.totalUsd).toBeCloseTo(each[0] + each[1], 12);
    expect(result.usage.costUsd).toBeCloseTo(each[0] + each[1], 12);
  });

  it("gives the whole-call usage the last attempt's stop reason and model, and the call's identity", async () => {
    const h = harness([
      reply("{}", { stop_reason: "end_turn", model: "claude-sonnet-5-first" as never, usage: usageOf(10, 1) }),
      reply(JSON.stringify(VALID), { stop_reason: "stop_sequence", model: "claude-sonnet-5-second" as never, usage: usageOf(10, 1) }),
    ]);
    const result = await run(h);
    expect(result.usage.stopReason).toBe("stop_sequence");
    expect(result.usage.responseModel).toBe("claude-sonnet-5-second");
    expect(result.usage.callId).toBe(entries(h)[0].callId);
    expect(result.usage.stage).toBe("architecture");
    expect(result.usage.model).toBe("claude-sonnet-5");
  });

  it("gives separate logical calls separate identities, each starting at attempt 1", async () => {
    const h = harness([JSON.stringify(VALID), JSON.stringify(VALID)]);
    await run(h);
    await run(h);
    const [first, second] = entries(h);
    expect(first.callId).not.toBe(second.callId);
    expect([first.attempt, second.attempt]).toEqual([1, 1]);
    expect(entries(h)).toHaveLength(2);
  });
  it("records a response before anything reads it: a refusal still shows up", async () => {
    const h = harness([
      reply("", { stop_reason: "refusal", usage: usageOf(90, 3) }),
    ]);
    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error).toBeInstanceOf(AiError);
    expect(entries(h)).toHaveLength(1);
    expect(entries(h)[0]).toMatchObject({ stopReason: "refusal", inputTokens: 90, outputTokens: 3 });
  });

  it("records nothing when the request got no response", async () => {
    const h = harness([]);
    h.deps.client = {
      async create() {
        throw new APIConnectionError();
      },
    };
    await expect(run(h)).rejects.toBeInstanceOf(AiError);
    expect(entries(h)).toEqual([]);
    expect(h.ledger.forAnalysis("test-analysis").totalUsd).toBe(0);
  });

  it("records nothing across backoff retries that never produced a response", async () => {
    const h = harness([httpError(529), httpError(529), httpError(529)]);
    await expect(run(h)).rejects.toBeInstanceOf(AiError);
    expect(entries(h)).toEqual([]);
  });

  it("keeps an earlier response's usage when a later request gets no response, and adds nothing", async () => {
    let calls = 0;
    const h = harness([]);
    h.deps.client = {
      async create() {
        calls++;
        if (calls === 1) return message("{}", { usage: usageOf(100, 20) });
        throw new APIConnectionError();
      },
    };
    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error.code).toBe("AI_FAILURE");
    expect(entries(h)).toHaveLength(1);
    expect(entries(h)[0]).toMatchObject({ inputTokens: 100, outputTokens: 20, requests: 1 });
  });

  it("counts a backoff retry in requests when the response finally arrives", async () => {
    const h = harness([httpError(529), reply(JSON.stringify(VALID), { usage: usageOf(10, 5) })]);
    const result = await run(h);
    expect(result.usage.requests).toBe(2);
    expect(entries(h)).toHaveLength(1);
    expect(entries(h)[0].inputTokens).toBe(10);
  });
});

describe("callStructured, max_tokens truncation", () => {
  const cut = (over: Partial<Anthropic.Message> = {}) =>
    reply('{"summary": "it was going so well', {
      stop_reason: "max_tokens",
      usage: usageOf(500, 8000, { thinking: 7000 }),
      ...over,
    });

  const lastUserText = (h: Harness): string => {
    const messages = h.calls.at(-1)!.body.messages;
    const last = messages.at(-1)!;
    return typeof last.content === "string" ? last.content : JSON.stringify(last.content);
  };

  it("retries once with double the output budget, and the retry can succeed", async () => {
    const h = harness([cut(), reply(JSON.stringify(VALID))]);
    const result = await run(h, { maxTokens: 8000 });

    expect(result.attempts).toBe(2);
    expect(result.value).toEqual(VALID);
    expect(h.calls.map((c) => c.body.max_tokens)).toEqual([8000, 16_000]);
    // The retry says why: cut off, so return the complete JSON, more briefly.
    expect(lastUserText(h)).toContain("cut off at max_tokens");
    expect(lastUserText(h)).toContain("more briefly");
    expect(h.sleeps).toEqual([]);
  });

  it("caps the retry budget at what a non-streaming request may ask for", async () => {
    const h = harness([cut(), reply(JSON.stringify(VALID))]);
    await run(h, { maxTokens: 12_000 });
    expect(h.calls.map((c) => c.body.max_tokens)).toEqual([12_000, NON_STREAMING_MAX_TOKENS]);
  });

  it("gives the retry strictly more than the first budget, whatever that budget was", () => {
    expect(truncationRetryTokens(4000)).toBe(8000);
    expect(truncationRetryTokens(12_000)).toBe(21_333);
    expect(truncationRetryTokens(NON_STREAMING_MAX_TOKENS - 1)).toBe(NON_STREAMING_MAX_TOKENS);
  });

  it("rejects a first budget with no room above it, before any model call", async () => {
    for (const maxTokens of [NON_STREAMING_MAX_TOKENS, 30_000, 0, 1.5]) {
      const h = harness([reply(JSON.stringify(VALID))]);
      await expect(run(h, { maxTokens })).rejects.toThrow(/maxTokens must be a positive integer below/);
      expect(h.calls).toHaveLength(0);
    }
  });

  it("gives the retry a fresh deadline sized to its budget at the first attempt's pace", async () => {
    const h = harness([cut(), reply(JSON.stringify(VALID))]);
    const inner = h.deps.client as MessagesApi;
    let clock = 0;
    const scheduled: number[] = [];
    let cancelled = 0;
    h.deps.now = () => clock;
    h.deps.schedule = (ms) => {
      scheduled.push(ms);
      return () => {
        cancelled += 1;
      };
    };
    h.deps.client = {
      async create(body, options) {
        clock += 100_000; // each reply takes 100 s
        return inner.create(body, options);
      },
    };

    const result = await run(h, { maxTokens: 12_000, timeoutMs: 120_000 });
    expect(result.attempts).toBe(2);
    // 12,000 tokens took 100 s; 21,333 at that pace, plus a quarter, is 222,219 ms. The
    // 20 s left of the original 120 s deadline could never have held it.
    expect(scheduled).toEqual([120_000, 222_219]);
    expect(cancelled).toBe(2); // the first deadline when the retry starts, the second at the end
  });

  it("never gives the retry less time than the call's own deadline", () => {
    // A fast first attempt: 1 s for 12,000 tokens would pace the retry at ~2.2 s.
    expect(truncationRetryTimeoutMs(120_000, 1000, 12_000, 21_333)).toBe(120_000);
    expect(truncationRetryTimeoutMs(300_000, 140_000, 12_000, 21_333)).toBe(
      Math.ceil((140_000 * 21_333 * TRUNCATION_RETRY_TIME_MARGIN) / 12_000),
    );
  });

  it("fails with MODEL_OUTPUT_INVALID naming the retry's limit when the retry is cut off too", async () => {
    const h = harness([cut(), cut()]);
    const error = (await run(h, { maxTokens: 1234 }).catch((e: unknown) => e)) as AiError;

    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("MODEL_OUTPUT_INVALID");
    expect(error.message).toBe(
      "architecture: structured output was truncated at the configured token limit (2468 tokens)",
    );
    expect(error.issues).toEqual([
      {
        path: "$",
        message: "the response was cut off at max_tokens; return the complete JSON, more briefly",
      },
    ]);
    expect(h.calls).toHaveLength(2);
    // None of the model's partial output is in the error.
    expect(error.message).not.toContain("going so well");
    expect(JSON.stringify(error.issues)).not.toContain("going so well");
  });

  it("records both truncated attempts, each with its usage", async () => {
    const h = harness([cut(), cut()]);
    await expect(run(h)).rejects.toBeInstanceOf(AiError);
    expect(entries(h)).toHaveLength(2);
    for (const [index, entry] of entries(h).entries()) {
      expect(entry).toMatchObject({
        attempt: index + 1,
        stopReason: "max_tokens",
        inputTokens: 500,
        outputTokens: 8000,
        thinkingTokens: 7000,
        requests: 1,
      });
      expect(entry.costUsd).toBeGreaterThan(0);
    }
  });

  it("never returns a partial value, even when the cut-off text happens to parse", async () => {
    const parsesButCut = () =>
      reply(JSON.stringify(VALID), { stop_reason: "max_tokens", usage: usageOf(1, 8000) });
    const h = harness([parsesButCut(), parsesButCut()]);
    const outcome = await run(h).then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    expect("value" in outcome).toBe(false);
    expect(h.calls).toHaveLength(2);
  });

  it("gives an ordinary invalid response its retry at the same budget", async () => {
    const h = harness([
      reply("{not json", { stop_reason: "end_turn" }),
      reply(JSON.stringify(VALID), { stop_reason: "end_turn" }),
    ]);
    const result = await run(h, { maxTokens: 8000 });
    expect(result.attempts).toBe(2);
    expect(h.calls.map((c) => c.body.max_tokens)).toEqual([8000, 8000]);
  });

  it("allows no second retry: a truncation after an ordinary failure ends the call, recording both attempts", async () => {
    const h = harness([reply("{}", { usage: usageOf(100, 20) }), cut(), reply(JSON.stringify(VALID))]);
    const error = (await run(h).catch((e: unknown) => e)) as AiError;
    expect(error.message).toContain("truncated at the configured token limit");
    expect(h.calls).toHaveLength(2);
    expect(entries(h)).toHaveLength(2);
    expect(entries(h)[0]).toMatchObject({ attempt: 1, inputTokens: 100, outputTokens: 20 });
    expect(entries(h)[1]).toMatchObject({ attempt: 2, inputTokens: 500, outputTokens: 8000, stopReason: "max_tokens" });
    expect(h.ledger.forAnalysis("test-analysis").totals).toMatchObject({ inputTokens: 600, outputTokens: 8020 });
  });

  it("still writes the development dump for a truncated reply", async () => {
    const h = harness([cut(), cut()], { isDevelopment: true });
    await expect(run(h)).rejects.toBeInstanceOf(AiError);
    expect(h.dumps.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Per-call thinking control
// ---------------------------------------------------------------------------

describe("callStructured, thinking", () => {
  it("sends no thinking field by default, so an existing caller behaves as before", async () => {
    const h = harness([JSON.stringify(VALID)]);
    await run(h);
    expect("thinking" in h.calls[0].body).toBe(false);
  });

  it("sends thinking disabled when a call asks for it, and nothing else about the request changes", async () => {
    const plain = harness([JSON.stringify(VALID)]);
    await run(plain, { maxTokens: 12_000, timeoutMs: 300_000 });
    const off = harness([JSON.stringify(VALID)]);
    await run(off, { maxTokens: 12_000, timeoutMs: 300_000, thinking: { type: "disabled" } });

    expect(off.calls[0].body.thinking).toEqual({ type: "disabled" });
    const withoutThinking = { ...off.calls[0].body } as Record<string, unknown>;
    delete withoutThinking.thinking;
    expect(withoutThinking).toEqual(plain.calls[0].body);
    expect(off.calls[0].body.max_tokens).toBe(12_000);
  });

  it("still validates the structured output when thinking is disabled", async () => {
    const bad = JSON.stringify({ summary: 1 });
    const h = harness([bad, bad]);
    const error = (await run(h, { thinking: { type: "disabled" } }).catch((e: unknown) => e)) as AiError;
    expect(error).toBeInstanceOf(AiError);
    expect(error.issues.length).toBeGreaterThan(0);
    expect(h.calls).toHaveLength(2);
    // Both attempts carry the same setting.
    expect(h.calls.every((c) => c.body.thinking?.type === "disabled")).toBe(true);
  });

  it("keeps the schema, the cache block and the deadline when thinking is disabled", async () => {
    const asked: number[] = [];
    const h = harness([JSON.stringify(VALID)]);
    const inner = h.deps.schedule!;
    h.deps.schedule = (ms, fn) => {
      asked.push(ms);
      return inner(ms, fn);
    };
    await run(h, { thinking: { type: "disabled" }, timeoutMs: 300_000 });
    expect(asked).toEqual([300_000]);
    expect(h.calls[0].body.output_config).toEqual({ format: { type: "json_schema", schema: JSON_SCHEMA } });
    expect(JSON.stringify(h.calls[0].body.system)).toContain("cache_control");
  });
});

// ---------------------------------------------------------------------------
// Retry-request hardening: every string on the wire is non-empty where required and
// well-formed UTF-16; no V8 JSON.parse excerpt is copied into the correction.
// ---------------------------------------------------------------------------

/** Every string a request carries: system blocks and each message's text. */
function wireStrings(body: Anthropic.MessageCreateParamsNonStreaming): string[] {
  const system = Array.isArray(body.system) ? body.system.map((b) => b.text) : [String(body.system ?? "")];
  const messages = body.messages.map((m) =>
    typeof m.content === "string"
      ? m.content
      : m.content.map((b) => (b.type === "text" ? b.text : "")).join(""),
  );
  return [...system, ...messages];
}

const EMOJI = "\u{1F600}";
const HIGH = EMOJI.charAt(0);

describe("callStructured, retry-request hardening", () => {
  it("builds a well-formed retry for invalid JSON containing emoji, with no V8 excerpt copied in", async () => {
    // V8 quotes an excerpt of the bad text in its message, and can cut it mid-emoji.
    const bad = `${EMOJI.repeat(3)}}`;
    const v8 = (() => {
      try {
        JSON.parse(bad);
      } catch (e) {
        return (e as Error).message;
      }
      return "";
    })();
    expect(loneSurrogateOffsets(v8).length).toBeGreaterThan(0); // the hazard is real

    const h = harness([bad, JSON.stringify(VALID)]);
    await run(h);

    expect(h.calls).toHaveLength(2);
    const retry = h.calls[1].body;
    expect(retry.messages.map((m) => m.role)).toEqual(["user", "assistant", "user"]);
    for (const text of wireStrings(retry)) {
      expect(text.trim().length).toBeGreaterThan(0);
      expect(isWellFormedText(text)).toBe(true);
    }
    const correction = retry.messages[2].content as string;
    expect(correction).toContain("response was not valid JSON");
    expect(correction).not.toContain(v8);
    expect(correction).not.toContain(EMOJI);
    expect(correction).not.toMatch(/Unexpected|Expected|"/);
  });

  it("never copies a JSON.parse excerpt, only a fixed message and a numeric position", () => {
    const outcome = parseAndValidate(Output, '{"summary": "SECRET_EXCERPT_TEXT" oops}');
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.issues).toHaveLength(1);
    expect(outcome.issues[0].path).toBe("$");
    expect(outcome.issues[0].message).toMatch(/^response was not valid JSON( \(error at position \d+\))?$/);
    expect(outcome.issues[0].message).not.toContain("SECRET_EXCERPT_TEXT");
  });

  it.each([
    ["empty", ""],
    ["whitespace-only", "  \n\t  "],
  ])("sends non-empty assistant content when the first response is %s", async (_label, first) => {
    const h = harness([first, JSON.stringify(VALID)]);
    await run(h);

    expect(h.calls).toHaveLength(2);
    expect(h.calls[1].body.messages[1]).toEqual({ role: "assistant", content: EMPTY_RESPONSE_PLACEHOLDER });
  });

  it("makes a lone surrogate in a response well formed before echoing it back", async () => {
    const h = harness([`{"summary": "x${HIGH}"`, JSON.stringify(VALID)]);
    await run(h);

    const echoed = h.calls[1].body.messages[1].content as string;
    expect(isWellFormedText(echoed)).toBe(true);
    expect(echoed).toContain("\uFFFD");
  });

  it("makes every outgoing string well formed, including a user block with a lone surrogate", async () => {
    const h = harness([JSON.stringify(VALID)]);
    await run(h, { user: `<repo_file path="a.md">\n1| broken ${HIGH} text\n</repo_file>` });

    for (const text of wireStrings(h.calls[0].body)) expect(isWellFormedText(text)).toBe(true);
  });

  it("keeps valid first attempts unchanged: one request, text sent as given", async () => {
    const user = `<repo_file path="a.md">\n1| hello ${EMOJI}\n</repo_file>`;
    const h = harness([JSON.stringify(VALID)]);
    const result = await run(h, { user });

    expect(result.attempts).toBe(1);
    expect(h.calls).toHaveLength(1);
    expect(h.calls[0].body.messages).toEqual([{ role: "user", content: user }]);
  });

  it("keeps schema-issue paths in the correction and still allows only ONE correction retry", async () => {
    const h = harness([JSON.stringify({ summary: 1 }), JSON.stringify({ summary: 2 })]);
    const error = await run(h).catch((e: unknown) => e);

    expect(h.calls).toHaveLength(2);
    expect(error).toBeInstanceOf(AiError);
    expect((error as AiError).message).toContain("failed validation twice");
    expect(h.calls[1].body.messages[2].content).toContain("- summary:");
  });

  it("echoOf caps long text without splitting an emoji at the cut", () => {
    for (const offset of [0, 1]) {
      const text = `${"a".repeat(20_000 - 1 + offset)}${EMOJI}${"b".repeat(10)}`;
      const echoed = echoOf(text);
      expect(isWellFormedText(echoed)).toBe(true);
      expect(echoed.endsWith("\n... truncated ...")).toBe(true);
    }
    expect(echoOf("short")).toBe("short");
  });
});

describe("callStructured, 4xx structural diagnostics", () => {
  function badRequest(): Error {
    return Object.assign(new Error("400 PROVIDER_MESSAGE_MUST_NOT_BE_RECORDED"), {
      status: 400,
      request_id: "req_0123456789abcdef",
      error: { type: "error", error: { type: "invalid_request_error", message: "PROVIDER_MESSAGE_MUST_NOT_BE_RECORDED" } },
    });
  }

  it("records status, type, request id, stage, attempt, roles and lengths, and no content", async () => {
    const h = harness(["not json", badRequest()]);
    const error = (await run(h).catch((e: unknown) => e)) as AiError;

    expect(error).toBeInstanceOf(AiError);
    expect(error.request).toEqual({
      status: 400,
      category: "unknown",
      errorType: "invalid_request_error",
      requestId: "req_0123456789abcdef",
      stage: "architecture",
      attempt: 2,
      messages: [
        { role: "user", chars: expect.any(Number), utf8Bytes: expect.any(Number) },
        { role: "assistant", chars: "not json".length, utf8Bytes: "not json".length },
        { role: "user", chars: expect.any(Number), utf8Bytes: expect.any(Number) },
      ],
      systemChars: expect.any(Number),
      allMessagesNonEmpty: true,
      allMessagesWellFormed: true,
    });
    const serialized = JSON.stringify(error.request);
    expect(serialized).not.toContain("PROVIDER_MESSAGE_MUST_NOT_BE_RECORDED");
    expect(serialized).not.toContain("A small app");
    expect(serialized).not.toContain("not json");
  });

  it("records the allowlisted category of the rejection, never the provider's message", async () => {
    const creditError = Object.assign(new Error("400 PROVIDER_MESSAGE_MUST_NOT_BE_RECORDED"), {
      status: 400,
      request_id: "req_0123456789abcdef",
      error: {
        type: "error",
        error: {
          type: "invalid_request_error",
          message: "Your credit balance is too low. PROVIDER_MESSAGE_MUST_NOT_BE_RECORDED",
        },
      },
    });
    const error = (await run(harness([creditError])).catch((e: unknown) => e)) as AiError;

    expect(error.request?.category).toBe("credit_balance_low");
    expect(error.request?.requestId).toBe("req_0123456789abcdef");
    expect(JSON.stringify(error.request)).not.toContain("PROVIDER_MESSAGE_MUST_NOT_BE_RECORDED");
    expect(error.message).not.toContain("PROVIDER_MESSAGE_MUST_NOT_BE_RECORDED");
  });

  it("records nothing structural for a non-4xx failure", async () => {
    const h = harness([Object.assign(new Error("HTTP 500"), { status: 500 }), Object.assign(new Error("HTTP 500"), { status: 500 }), Object.assign(new Error("HTTP 500"), { status: 500 })]);
    const error = (await run(h).catch((e: unknown) => e)) as AiError;

    expect(error.request).toBeUndefined();
  });
});

describe("callStructured, per-batch dump names", () => {
  it("names dumps by stage, dump key and attempt, so batches never overwrite each other", async () => {
    const h = harness([JSON.stringify(VALID), JSON.stringify(VALID), "not json", JSON.stringify(VALID)], {
      isDevelopment: true,
    });
    await run(h, { stage: "stride", dumpKey: "b00" });
    await run(h, { stage: "stride", dumpKey: "b01" });
    await run(h, { stage: "stride", dumpKey: "b02" });

    expect(h.dumps.map((d) => d.file)).toEqual([
      "stride.b00.attempt-1.txt",
      "stride.b01.attempt-1.txt",
      "stride.b02.attempt-1.txt",
      "stride.b02.attempt-2.txt",
    ]);
    expect(new Set(h.dumps.map((d) => d.file)).size).toBe(4);
  });

  it("keeps the old name without a key, and drops an unsafe key", () => {
    expect(dumpFileName("architecture", 1)).toBe("architecture.attempt-1.txt");
    expect(dumpFileName("stride", 2, "../evil")).toBe("stride.attempt-2.txt");
  });

  it("still refuses to dump a call whose prompt holds a secret", async () => {
    const h = harness([JSON.stringify(VALID)], { isDevelopment: true });
    await expect(
      run(h, { stage: "stride", dumpKey: "b00", user: 'token = "AKIAIOSFODNN7EXAMPLE"' }),
    ).rejects.toBeInstanceOf(SecretLeakError);
    expect(h.dumps).toEqual([]);
  });
});
