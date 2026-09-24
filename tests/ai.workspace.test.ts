import Anthropic from "@anthropic-ai/sdk";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  AiError,
  WORKSPACE_HEADER,
  callStructured,
  clientOptions,
} from "@/server/ai/claude";
import { UsageLedger } from "@/server/ai/usage";

// Made-up values for this file only. Neither is a credential.
const FAKE_WORKSPACE_ID = "wrkspc_TESTONLY0123456789";
const FAKE_API_KEY = "test-api-key-not-real-0123456789";

const Output = z.object({ summary: z.string() });
const JSON_SCHEMA = z.toJSONSchema(Output) as Record<string, unknown>;

type Sent = { url: string; headers: Headers };

/** A real SDK client whose transport is a stub: nothing reaches the network. */
function sdkClient(
  env: Record<string, string | undefined>,
  respond: () => Response,
): { client: Anthropic; sent: Sent[] } {
  const sent: Sent[] = [];
  const client = new Anthropic({
    ...clientOptions(env),
    apiKey: FAKE_API_KEY,
    fetch: async (url, init) => {
      sent.push({
        url: String(url),
        headers: new Headers(init?.headers as HeadersInit | undefined),
      });
      return respond();
    },
  });
  return { client, sent };
}

const okResponse = (): Response =>
  new Response(
    JSON.stringify({
      id: "msg_test",
      type: "message",
      role: "assistant",
      model: "claude-sonnet-5",
      content: [{ type: "text", text: JSON.stringify({ summary: "ok" }) }],
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: { input_tokens: 10, output_tokens: 5 },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );

/** A provider error that echoes the workspace id and key back, the worst case. */
const echoingBadRequest = (): Response =>
  new Response(
    JSON.stringify({
      type: "error",
      error: {
        type: "invalid_request_error",
        message: `bad request for ${FAKE_WORKSPACE_ID} using ${FAKE_API_KEY}`,
      },
    }),
    { status: 400, headers: { "content-type": "application/json" } },
  );

const call = (
  client: Anthropic,
  extra: Record<string, unknown> = {},
) =>
  callStructured({
    stage: "architecture",
    analysisId: "workspace-test",
    system: "You are a security reviewer.",
    user: "A small app.",
    schema: Output,
    jsonSchema: JSON_SCHEMA,
    deps: { client: client.messages, ledger: new UsageLedger(), ...extra },
  });

describe("clientOptions", () => {
  it("adds the workspace header when the variable is set", () => {
    expect(clientOptions({ ANTHROPIC_WORKSPACE_ID: FAKE_WORKSPACE_ID })).toEqual({
      maxRetries: 0,
      defaultHeaders: { [WORKSPACE_HEADER]: FAKE_WORKSPACE_ID },
    });
  });

  it("trims surrounding whitespace from the id", () => {
    const options = clientOptions({
      ANTHROPIC_WORKSPACE_ID: `  ${FAKE_WORKSPACE_ID}\n`,
    });
    expect(options.defaultHeaders?.[WORKSPACE_HEADER]).toBe(FAKE_WORKSPACE_ID);
  });

  it.each([undefined, "", "   ", "\n"])(
    "leaves the options exactly as before when the value is %j",
    (value) => {
      // Absent must preserve current behaviour: the same object shape, no key at all.
      const options = clientOptions({ ANTHROPIC_WORKSPACE_ID: value });
      expect(options).toEqual({ maxRetries: 0 });
      expect("defaultHeaders" in options).toBe(false);
    },
  );

  it("keeps SDK retries off, so the module's own backoff is the only one", () => {
    expect(clientOptions({}).maxRetries).toBe(0);
    expect(clientOptions({ ANTHROPIC_WORKSPACE_ID: FAKE_WORKSPACE_ID }).maxRetries).toBe(0);
  });

  it.each(["has space", "semi;colon", "new\nline", "a".repeat(129), "wrkspc/../x"])(
    "rejects a malformed id (%j) without echoing it",
    (value) => {
      let message = "";
      try {
        clientOptions({ ANTHROPIC_WORKSPACE_ID: value });
      } catch (error) {
        message = error instanceof Error ? error.message : "";
      }
      expect(message).not.toContain(value.trim() || "<blank>");
      expect(message).toMatch(/invalid format/);
    },
  );
});

describe("the header on the wire", () => {
  it("is sent on the request when the variable is present", async () => {
    const { client, sent } = sdkClient(
      { ANTHROPIC_WORKSPACE_ID: FAKE_WORKSPACE_ID },
      okResponse,
    );
    await call(client);

    expect(sent).toHaveLength(1);
    expect(sent[0].headers.get(WORKSPACE_HEADER)).toBe(FAKE_WORKSPACE_ID);
  });

  it("is omitted from the request when the variable is absent", async () => {
    const { client, sent } = sdkClient({}, okResponse);
    await call(client);

    expect(sent).toHaveLength(1);
    expect(sent[0].headers.has(WORKSPACE_HEADER)).toBe(false);
  });

  it("is omitted when the variable is blank", async () => {
    const { client, sent } = sdkClient({ ANTHROPIC_WORKSPACE_ID: "  " }, okResponse);
    await call(client);
    expect(sent[0].headers.has(WORKSPACE_HEADER)).toBe(false);
  });

  it("does not disturb the rest of the request", async () => {
    const withId = sdkClient({ ANTHROPIC_WORKSPACE_ID: FAKE_WORKSPACE_ID }, okResponse);
    const without = sdkClient({}, okResponse);
    await call(withId.client);
    await call(without.client);

    expect(withId.sent[0].url).toBe(without.sent[0].url);
    expect(withId.sent[0].headers.get("x-api-key")).toBe(
      without.sent[0].headers.get("x-api-key"),
    );
  });
});

describe("neither the workspace id nor the key surfaces", () => {
  it("stays out of the AiError a provider 400 produces", async () => {
    const { client } = sdkClient(
      { ANTHROPIC_WORKSPACE_ID: FAKE_WORKSPACE_ID },
      echoingBadRequest,
    );

    const error = (await call(client).catch((e: unknown) => e)) as AiError;
    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("AI_FAILURE");

    // Everything AiError itself exposes for logging. The provider body sits on
    // `cause`, which callers must not print (try-claude.ts never does).
    const surface = [error.message, String(error), JSON.stringify(error.issues)].join("\n");
    expect(surface).not.toContain(FAKE_WORKSPACE_ID);
    expect(surface).not.toContain(FAKE_API_KEY);
    expect(surface).toContain("HTTP 400");
  });

  it("stays out of the usage ledger", async () => {
    const ledger = new UsageLedger();
    const { client } = sdkClient({ ANTHROPIC_WORKSPACE_ID: FAKE_WORKSPACE_ID }, okResponse);
    await call(client, { ledger });

    const serialised = JSON.stringify(ledger.forAnalysis("workspace-test"));
    expect(serialised).not.toContain(FAKE_WORKSPACE_ID);
    expect(serialised).not.toContain(FAKE_API_KEY);
  });

  it("stays out of the development debug dump", async () => {
    const dumps: string[] = [];
    const { client } = sdkClient({ ANTHROPIC_WORKSPACE_ID: FAKE_WORKSPACE_ID }, okResponse);
    await call(client, {
      isDevelopment: true,
      writeDebug: (_id: string, file: string, body: string) => {
        dumps.push(`${file}\n${body}`);
      },
    });

    expect(dumps.length).toBeGreaterThan(0);
    for (const dump of dumps) {
      expect(dump).not.toContain(FAKE_WORKSPACE_ID);
      expect(dump).not.toContain(FAKE_API_KEY);
    }
  });
});
