/**
 * The local model response cache (src/server/ai/modelCache.ts) as callStructured uses it.
 * A scripted client counts requests; the cache is file-backed in a fresh temp directory.
 */

import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type Anthropic from "@anthropic-ai/sdk";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { callStructured, type ClaudeDeps, type MessagesApi } from "@/server/ai/claude";
import { cacheKey, fileModelCache, modelCacheEnabled, MODEL_CACHE_ENV } from "@/server/ai/modelCache";
import { UsageLedger } from "@/server/ai/usage";
import { assertNoSecrets } from "@/server/security/redactor";

const Output = z.object({ summary: z.string() });
const JSON_SCHEMA = z.toJSONSchema(Output) as Record<string, unknown>;
const FAKE_KEY = "sk-ant-api03-TESTKEYVALUE0123456789abcdefABCDEF";

function reply(text: string, outputTokens = 20): Anthropic.Message {
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
      output_tokens: outputTokens,
      cache_read_input_tokens: 0,
      cache_creation_input_tokens: 0,
    },
  } as Anthropic.Message;
}

function setup(replies: string[]) {
  const dir = mkdtempSync(join(tmpdir(), "model-cache-"));
  const ledger = new UsageLedger();
  let requests = 0;
  const client: MessagesApi = {
    async create() {
      const text = replies[requests];
      requests += 1;
      if (text === undefined) throw new Error("unexpected request");
      return reply(text);
    },
  };
  const deps: Partial<ClaudeDeps> = {
    client,
    ledger,
    isDevelopment: false,
    sleep: async () => {},
    schedule: () => () => {},
    modelCache: fileModelCache(dir),
  };
  const call = (user = "<repo_file path=\"a.js\">\nx\n</repo_file>") =>
    callStructured({
      stage: "architecture",
      analysisId: "cache-test",
      system: "You are a security reviewer.",
      user,
      schema: Output,
      jsonSchema: JSON_SCHEMA,
      deps,
    });
  return { dir, ledger, call, requests: () => requests };
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("model cache", () => {
  it("serves a second identical call with no HTTP request, as a zero-token cached entry", async () => {
    const t = setup([JSON.stringify({ summary: "first" })]);
    const first = await t.call();
    const second = await t.call();

    expect(t.requests()).toBe(1);
    expect(second.value).toEqual(first.value);
    expect(second.attempts).toBe(1);
    expect(second.usage).toMatchObject({ cached: true, inputTokens: 0, outputTokens: 0, costUsd: 0, requests: 0 });
    const calls = t.ledger.forAnalysis("cache-test").calls;
    expect(calls).toHaveLength(2);
    expect(calls[0].cached).toBeUndefined();
    expect(calls[1].cached).toBe(true);
  });

  it("misses when the prompt changes", async () => {
    const t = setup([JSON.stringify({ summary: "a" }), JSON.stringify({ summary: "b" })]);
    await t.call();
    const changed = await t.call('<repo_file path="b.js">\ny\n</repo_file>');
    expect(t.requests()).toBe(2);
    expect(changed.value).toEqual({ summary: "b" });
  });

  it("never saves a call that failed validation", async () => {
    const t = setup(["{}", "{}"]);
    await expect(t.call()).rejects.toMatchObject({ code: "MODEL_OUTPUT_INVALID" });
    expect(readdirSync(t.dir)).toHaveLength(0);
  });

  it("saves only after the validation retry succeeds, and serves that", async () => {
    const t = setup(["{}", JSON.stringify({ summary: "fixed" })]);
    await t.call();
    const again = await t.call();
    expect(t.requests()).toBe(2);
    expect(again.value).toEqual({ summary: "fixed" });
  });

  it("never writes the API key into the saved file", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", FAKE_KEY);
    const t = setup([JSON.stringify({ summary: "ok" })]);
    await t.call();
    const files = readdirSync(t.dir);
    expect(files).toHaveLength(1);
    const body = readFileSync(join(t.dir, files[0]), "utf8");
    expect(body).not.toContain(FAKE_KEY);
    expect(() => assertNoSecrets(body)).not.toThrow();
  });

  it("does not save a response that looks like it holds a secret", async () => {
    const t = setup([JSON.stringify({ summary: `key is ${FAKE_KEY}` })]);
    await t.call();
    expect(readdirSync(t.dir)).toHaveLength(0);
  });

  it("is on only with the variable set to 1 outside production", () => {
    expect(modelCacheEnabled({ [MODEL_CACHE_ENV]: "1", NODE_ENV: "development" })).toBe(true);
    expect(modelCacheEnabled({ [MODEL_CACHE_ENV]: "1", NODE_ENV: "production" })).toBe(false);
    expect(modelCacheEnabled({ NODE_ENV: "development" })).toBe(false);
  });

  it("keys on model, system, messages and schema", () => {
    const base = { model: "m", system: "s", messages: [{ role: "user", content: "u" }], jsonSchema: JSON_SCHEMA };
    const key = cacheKey(base);
    expect(cacheKey({ ...base })).toBe(key);
    expect(cacheKey({ ...base, model: "n" })).not.toBe(key);
    expect(cacheKey({ ...base, system: "t" })).not.toBe(key);
    expect(cacheKey({ ...base, jsonSchema: { title: "Other" } })).not.toBe(key);
  });
});
