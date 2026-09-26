/**
 * The development-only failure log in src/server/analysis/pipeline.ts (fail() ->
 * logFailure). src/server/log.ts is mocked so each test sees exactly what would be
 * written; the real log()'s secret guard is covered by tests/log.test.ts.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/server/log", () => ({ log: vi.fn() }));

import { log } from "@/server/log";
import { AiError } from "@/server/ai/claude";
import { usageLedger, type CallUsage } from "@/server/ai/usage";
import { GitHubMcpError } from "@/server/mcp/githubClient";
import type { LoadedRepo } from "@/server/ingest/loader";
import { ERROR_COPY } from "@/shared/labels";
import {
  FAILURE_MESSAGE_MAX,
  createAnalysis,
  failureDiagnostic,
  resetStore,
  runAnalysis,
  type PipelineDeps,
} from "@/server/analysis/pipeline";
import { loadCanaryRepo } from "./canaryRepo";

const SECRET_CONTENT = "const apiKey = 'REPO_FILE_BODY_MUST_NOT_BE_LOGGED';";

function loadedRepo(): LoadedRepo {
  const files = loadCanaryRepo();
  return {
    summary: {
      owner: "acme",
      name: "canary",
      ref: "main",
      languages: ["JavaScript"],
      frameworks: [],
      fileCountAnalyzed: files.length,
      analyzedAt: new Date(0).toISOString(),
    },
    files: [...files, { path: "src/secret.js", content: SECRET_CONTENT, tier: "high", reason: "source" }],
    skipped: { ignored: 0, overLimit: 0 },
    truncated: false,
  };
}

/** Reaches mapping_architecture, then fails there with `cause`. */
function failAtArchitecture(cause: unknown): Partial<PipelineDeps> {
  return {
    loadRepository: async () => loadedRepo(),
    scanFiles: async () => [],
    scanDependencies: async () => ({ evidence: [], limitations: [] }),
    inferArchitecture: async () => {
      throw cause;
    },
  };
}

/** A recorded model response: counts and a stop reason, as the real ledger holds. */
function recordedCall(overrides: Partial<CallUsage> = {}): CallUsage {
  return {
    stage: "architecture",
    model: "claude-sonnet-5",
    requests: 1,
    costUsd: 0.1,
    inputTokens: 30_000,
    outputTokens: 12_000,
    thinkingTokens: 12_000,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    stopReason: "max_tokens",
    attempt: 1,
    ...overrides,
  };
}

/** Records `calls` for the job, then fails at mapping_architecture with a truncation. */
function truncatedAfter(analysisId: string, calls: CallUsage[]): Partial<PipelineDeps> {
  return failAtArchitecture(
    (() => {
      for (const call of calls) usageLedger.record(analysisId, call);
      return new AiError(
        "AI_FAILURE",
        "architecture: structured output was truncated at the configured token limit (12000 tokens)",
        { issues: [{ path: "$", message: "the response was cut off at max_tokens" }] },
      );
    })(),
  );
}

/** Shaped like the SDK's APIError: a status plus a body that must never be logged. */
class FakeApiError extends Error {
  readonly status = 400;
  readonly error = { message: "PROMPT_TEXT_MUST_NOT_BE_LOGGED" };
  constructor() {
    super("400 invalid_request_error");
    this.name = "BadRequestError";
  }
}

function loggedFields(): Record<string, unknown> {
  expect(log).toHaveBeenCalledTimes(1);
  const [level, message, fields] = vi.mocked(log).mock.calls[0]!;
  expect(level).toBe("error");
  expect(message).toBe("analysis failed");
  return fields as Record<string, unknown>;
}

beforeEach(() => {
  resetStore();
  vi.mocked(log).mockReset();
  vi.stubEnv("NODE_ENV", "development");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("fail() development-only failure log", () => {
  it("logs the stage that failed (before it is overwritten), the error class and the API status", async () => {
    const state = createAnalysis("acme/canary");
    const cause = new AiError("AI_FAILURE", "model call failed: HTTP 400", {
      cause: new FakeApiError(),
    });

    const result = await runAnalysis(state.id, failAtArchitecture(cause));

    expect(result.stage).toBe("failed");
    const fields = loggedFields();
    expect(fields).toMatchObject({
      analysisId: state.id,
      failedStage: "mapping_architecture",
      code: "AI_FAILURE",
      causeName: "AiError",
      causeMessage: "model call failed: HTTP 400",
      causeChain: ["BadRequestError"],
      apiStatus: 400,
      issues: [],
      modelCalls: 0,
    });
  });

  it("logs a refusal as its message, without the refusal's stop_details", async () => {
    const state = createAnalysis("acme/canary");
    const cause = new AiError("AI_FAILURE", "model declined the request", {
      cause: { type: "refusal", explanation: "RESPONSE_TEXT_MUST_NOT_BE_LOGGED" },
    });

    await runAnalysis(state.id, failAtArchitecture(cause));

    const fields = loggedFields();
    expect(fields.causeMessage).toBe("model declined the request");
    expect(fields.causeChain).toEqual(["object"]);
    expect(JSON.stringify(fields)).not.toContain("RESPONSE_TEXT_MUST_NOT_BE_LOGGED");
  });

  it("never logs repository contents, prompt or response text from the cause", async () => {
    const state = createAnalysis("acme/canary");
    await runAnalysis(
      state.id,
      failAtArchitecture(new AiError("AI_FAILURE", "boom", { cause: new FakeApiError() })),
    );

    const serialized = JSON.stringify(vi.mocked(log).mock.calls);
    expect(serialized).not.toContain("REPO_FILE_BODY_MUST_NOT_BE_LOGGED");
    expect(serialized).not.toContain("PROMPT_TEXT_MUST_NOT_BE_LOGGED");
  });

  it("logs validation issues' paths and messages for an AiError that carries them", async () => {
    const state = createAnalysis("acme/canary");
    const cause = new AiError("AI_FAILURE", "architecture: schema validation failed", {
      issues: [{ path: "components.0.id", message: "Required" }],
    });

    await runAnalysis(state.id, failAtArchitecture(cause));

    expect(loggedFields().issues).toEqual([{ path: "components.0.id", message: "Required" }]);
  });

  it("logs a loading failure at loading_repo with its own error class and code", async () => {
    const state = createAnalysis("acme/canary");
    await runAnalysis(state.id, {
      loadRepository: async () => {
        throw new GitHubMcpError("REPO_NOT_FOUND", "GET /repos/acme/canary returned 404");
      },
    });

    expect(loggedFields()).toMatchObject({
      failedStage: "loading_repo",
      code: "REPO_NOT_FOUND",
      causeName: "GitHubMcpError",
    });
  });

  it("caps a long upstream message", async () => {
    const state = createAnalysis("acme/canary");
    await runAnalysis(state.id, failAtArchitecture(new Error("x".repeat(5000))));

    expect(String(loggedFields().causeMessage)).toHaveLength(FAILURE_MESSAGE_MAX);
  });

  it.each(["test", "production"])("logs nothing when NODE_ENV=%s", async (env) => {
    vi.stubEnv("NODE_ENV", env);
    const state = createAnalysis("acme/canary");

    const result = await runAnalysis(state.id, failAtArchitecture(new Error("boom")));

    expect(result.stage).toBe("failed");
    expect(log).not.toHaveBeenCalled();
  });

  it("leaves the public error unchanged: only the code and the ERROR_COPY message", async () => {
    const state = createAnalysis("acme/canary");
    const result = await runAnalysis(
      state.id,
      failAtArchitecture(new AiError("AI_FAILURE", "model declined the request")),
    );

    expect(result.error).toEqual({ code: "AI_FAILURE", message: ERROR_COPY.AI_FAILURE.message });
  });

  it("still fails the job normally when log() throws (secret-shaped line), falling back to a minimal line", async () => {
    vi.mocked(log).mockImplementationOnce(() => {
      throw new Error("SecretLeakError");
    });
    const state = createAnalysis("acme/canary");

    const result = await runAnalysis(state.id, failAtArchitecture(new Error("boom")));

    expect(result.stage).toBe("failed");
    expect(result.error?.code).toBe("AI_FAILURE");
    expect(log).toHaveBeenCalledTimes(2);
    expect(vi.mocked(log).mock.calls[1]![2]).toEqual({
      analysisId: state.id,
      failedStage: "mapping_architecture",
      code: "AI_FAILURE",
      causeName: "Error",
    });
  });

  it("does not reject even when both log attempts throw", async () => {
    vi.mocked(log).mockImplementation(() => {
      throw new Error("SecretLeakError");
    });
    const state = createAnalysis("acme/canary");

    await expect(runAnalysis(state.id, failAtArchitecture(new Error("boom")))).resolves.toMatchObject({
      stage: "failed",
    });
  });
});

describe("fail() failure log: last model response metadata", () => {
  it("includes the last recorded response's stopReason and thinkingTokens", async () => {
    const state = createAnalysis("acme/canary");
    await runAnalysis(state.id, truncatedAfter(state.id, [recordedCall()]));

    expect(loggedFields()).toMatchObject({
      failedStage: "mapping_architecture",
      modelCalls: 1,
      stopReason: "max_tokens",
      thinkingTokens: 12_000,
    });
  });

  it("uses the LAST recorded response when there are several", async () => {
    const state = createAnalysis("acme/canary");
    await runAnalysis(
      state.id,
      truncatedAfter(state.id, [
        recordedCall({ stopReason: "end_turn", thinkingTokens: 500 }),
        recordedCall({ stopReason: "max_tokens", thinkingTokens: 0, attempt: 2 }),
      ]),
    );

    expect(loggedFields()).toMatchObject({ modelCalls: 2, stopReason: "max_tokens", thinkingTokens: 0 });
  });

  it("omits both fields when no model response was recorded", async () => {
    const state = createAnalysis("acme/canary");
    await runAnalysis(state.id, failAtArchitecture(new Error("boom")));

    const fields = loggedFields();
    expect(fields).not.toHaveProperty("stopReason");
    expect(fields).not.toHaveProperty("thinkingTokens");
  });

  it("omits stopReason when the recorded response has none, but keeps thinkingTokens", async () => {
    const state = createAnalysis("acme/canary");
    await runAnalysis(state.id, truncatedAfter(state.id, [recordedCall({ stopReason: undefined })]));

    const fields = loggedFields();
    expect(fields).not.toHaveProperty("stopReason");
    expect(fields.thinkingTokens).toBe(12_000);
  });

  it("logs nothing in production even with recorded response metadata", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const state = createAnalysis("acme/canary");

    const result = await runAnalysis(state.id, truncatedAfter(state.id, [recordedCall()]));

    expect(result.stage).toBe("failed");
    expect(log).not.toHaveBeenCalled();
  });

  it("keeps the public error to the code and ERROR_COPY message: no stopReason or thinkingTokens", async () => {
    const state = createAnalysis("acme/canary");
    const result = await runAnalysis(state.id, truncatedAfter(state.id, [recordedCall()]));

    expect(result.error).toEqual({ code: "AI_FAILURE", message: ERROR_COPY.AI_FAILURE.message });
    expect(JSON.stringify(result.error)).not.toMatch(/stopReason|thinkingTokens|max_tokens/);
  });
});

describe("fail() failure log: ledger usage totals", () => {
  it("contains the exact ledger totals: calls, token counts, USD and the last stop reason", async () => {
    const state = createAnalysis("acme/canary");
    const calls = [
      recordedCall({
        inputTokens: 18_000, outputTokens: 3_700, thinkingTokens: 0,
        cacheReadTokens: 0, cacheWriteTokens: 5_000, costUsd: 0.08, stopReason: "end_turn",
      }),
      recordedCall({
        stage: "stride", inputTokens: 4_500, outputTokens: 2_800, thinkingTokens: 0,
        cacheReadTokens: 5_000, cacheWriteTokens: 0, costUsd: 0.047, stopReason: "end_turn",
      }),
      recordedCall({
        stage: "stride", inputTokens: 4_400, outputTokens: 2_900, thinkingTokens: 12,
        cacheReadTokens: 5_000, cacheWriteTokens: 0, costUsd: 0.046, stopReason: "max_tokens",
      }),
    ];
    await runAnalysis(state.id, truncatedAfter(state.id, calls));

    const fields = loggedFields();
    expect(fields.modelCalls).toBe(3);
    expect(fields.stopReason).toBe("max_tokens");
    expect(fields.usage).toEqual({
      inputTokens: 26_900,
      outputTokens: 9_400,
      cacheReadTokens: 10_000,
      cacheWriteTokens: 5_000,
      thinkingTokens: 12,
      totalUsd: usageLedger.forAnalysis(state.id).totalUsd,
    });
    expect(fields.usage).toMatchObject({ totalUsd: expect.closeTo(0.173, 10) });
  });

  it("reports zero totals when no model call was recorded", async () => {
    const state = createAnalysis("acme/canary");
    await runAnalysis(state.id, failAtArchitecture(new Error("boom")));

    expect(loggedFields().usage).toEqual({
      inputTokens: 0, outputTokens: 0, cacheReadTokens: 0,
      cacheWriteTokens: 0, thinkingTokens: 0, totalUsd: 0,
    });
  });

  it("logs no totals in production, and the public error still carries only code and message", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const state = createAnalysis("acme/canary");

    const result = await runAnalysis(state.id, truncatedAfter(state.id, [recordedCall()]));

    expect(log).not.toHaveBeenCalled();
    expect(result.error).toEqual({ code: "AI_FAILURE", message: ERROR_COPY.AI_FAILURE.message });
    expect(Object.keys(result.error!)).toEqual(["code", "message"]);
  });
});

describe("fail() failure log: 4xx request structure", () => {
  it("includes the rejected request's structure and nothing from its content", async () => {
    const state = createAnalysis("acme/canary");
    const request = {
      status: 400,
      category: "unknown" as const,
      errorType: "invalid_request_error",
      requestId: "req_0123456789abcdef",
      stage: "stride" as const,
      attempt: 2,
      messages: [
        { role: "user", chars: 9000, utf8Bytes: 9100 },
        { role: "assistant", chars: 16, utf8Bytes: 16 },
        { role: "user", chars: 247, utf8Bytes: 247 },
      ],
      systemChars: 12000,
      allMessagesNonEmpty: true,
      allMessagesWellFormed: true,
    };
    await runAnalysis(
      state.id,
      failAtArchitecture(new AiError("AI_FAILURE", "model call failed: HTTP 400", { request })),
    );

    expect(loggedFields().providerRequest).toEqual(request);
  });

  it("omits providerRequest when the failure had none", async () => {
    const state = createAnalysis("acme/canary");
    await runAnalysis(state.id, failAtArchitecture(new Error("boom")));

    expect(loggedFields()).not.toHaveProperty("providerRequest");
  });
});

describe("failureDiagnostic", () => {
  it("handles a non-Error thrown value", () => {
    const state = createAnalysis("acme/canary");
    const diagnostic = failureDiagnostic(state, "AI_FAILURE", "a string");

    expect(diagnostic).toMatchObject({ causeName: "string", causeMessage: "", causeChain: [] });
    expect(diagnostic.apiStatus).toBeUndefined();
  });
});
