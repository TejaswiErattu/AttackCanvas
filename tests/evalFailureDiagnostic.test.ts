/**
 * The eval runner's failure diagnostic: a provider failure inside a threat batch, run
 * through the real threat engine and model client (faked provider only), must log one
 * metadata line -- phase, batch, attempts, status, error type, a short sanitized message
 * -- when ATTACKCANVAS_FAILURE_DIAGNOSTICS=1, even outside development, and nothing that
 * came from the prompt, the provider's response body, headers or the repository.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/server/log", () => ({ log: vi.fn() }));

import { log } from "@/server/log";
import { MAX_TRANSPORT_ATTEMPTS, type MessagesApi } from "@/server/ai/claude";
import type { LoadedRepo } from "@/server/ingest/loader";
import { failedBatchOf, generateThreats } from "@/server/analysis/threats";
import {
  FAILURE_DIAGNOSTICS_ENV,
  createAnalysis,
  resetStore,
  runAnalysis,
  type PipelineDeps,
} from "@/server/analysis/pipeline";
import type { ArchitectureDraft } from "@/shared/schema";
import { CANARY_INJECTION_PHRASES, loadCanaryRepo } from "./canaryRepo";

const REPO_SECRET = "REPO_FILE_BODY_MUST_NOT_BE_LOGGED";
const PROVIDER_BODY_TEXT = "PROVIDER_BODY_MUST_NOT_BE_LOGGED";
const HEADER_VALUE = "HEADER_VALUE_MUST_NOT_BE_LOGGED";

function loadedRepo(): LoadedRepo {
  const files = loadCanaryRepo();
  return {
    summary: {
      owner: "acme",
      name: "canary",
      ref: "main",
      languages: ["JavaScript"],
      frameworks: [],
      fileCountAnalyzed: files.length + 1,
      analyzedAt: new Date(0).toISOString(),
    },
    files: [
      ...files,
      { path: "src/notes.js", content: `// ${REPO_SECRET}\n`, tier: "high", reason: "source" },
    ],
    skipped: { ignored: 0, overLimit: 0 },
    truncated: false,
  };
}

/** Three components: with batches of two, the threat phase runs two batches. */
const DRAFT: ArchitectureDraft = {
  components: ["comp-app", "comp-db", "comp-worker"].map((id) => ({
    id,
    name: id,
    type: "backend" as const,
    description: `${id} description`,
    technologies: [],
    files: ["src/app.js"],
    assets: ["user data"],
    evidenceRefs: ["src/app.js"],
  })),
  dataFlows: [],
  trustBoundaries: [],
  unknowns: [],
};

/** Shaped like the SDK's APIError for a 529: status, provider body and headers. */
class FakeOverloadedError extends Error {
  readonly status = 529;
  readonly error = {
    type: "error",
    error: { type: "overloaded_error", message: PROVIDER_BODY_TEXT },
  };
  readonly headers = { authorization: `Bearer ${HEADER_VALUE}`, "x-trace": HEADER_VALUE };
  readonly request_id = "req_test123";
  constructor() {
    super(`529 ${PROVIDER_BODY_TEXT}`);
    this.name = "InternalServerError";
  }
}

/** Every request fails with a 529; records how many were sent. */
function overloadedClient(): MessagesApi & { sent: number } {
  const client = {
    sent: 0,
    async create() {
      client.sent++;
      throw new FakeOverloadedError();
    },
  };
  return client as MessagesApi & { sent: number };
}

function pipelineDeps(client: MessagesApi, writeDebug: () => void): Partial<PipelineDeps> {
  return {
    loadRepository: async () => loadedRepo(),
    scanFiles: async () => [],
    scanDependencies: async () => ({ evidence: [], limitations: [] }),
    inferArchitecture: async () => ({
      draft: DRAFT,
      usage: {
        inputTokens: 1,
        outputTokens: 1,
        thinkingTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        stage: "architecture",
        model: "claude-sonnet-5",
        requests: 1,
        costUsd: 0,
      },
      attempts: 1,
      promptId: "architecture.v1",
    }),
    // The REAL threat engine and model client; only the provider is faked.
    generateThreats: (input) =>
      generateThreats({
        ...input,
        concurrency: 1,
        deps: { ...input.deps, client, sleep: async () => {}, writeDebug },
      }),
  };
}

beforeEach(() => {
  resetStore();
  vi.mocked(log).mockReset();
  vi.stubEnv("NODE_ENV", "production");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("eval failure diagnostic for a failed threat-batch provider call", () => {
  it("logs phase, batch, attempts, status, error type and a short message outside development", async () => {
    vi.stubEnv(FAILURE_DIAGNOSTICS_ENV, "1");
    const client = overloadedClient();
    const writeDebug = vi.fn();
    const state = createAnalysis("acme/canary");

    const result = await runAnalysis(state.id, pipelineDeps(client, writeDebug));

    expect(result.stage).toBe("failed");
    expect(result.error?.code).toBe("AI_FAILURE");
    // Every transport attempt was made for the first batch, then the pool stopped.
    expect(client.sent).toBe(MAX_TRANSPORT_ATTEMPTS);

    expect(log).toHaveBeenCalledTimes(1);
    const [level, message, fields] = vi.mocked(log).mock.calls[0]!;
    expect(level).toBe("error");
    expect(message).toBe("analysis failed");
    expect(fields).toMatchObject({
      failedStage: "generating_threats",
      code: "AI_FAILURE",
      apiStatus: 529,
      providerCall: {
        stage: "stride",
        validationAttempt: 1,
        transportAttempts: MAX_TRANSPORT_ATTEMPTS,
        status: 529,
        errorType: "overloaded_error",
      },
      batch: { number: 1, of: 2 },
    });
    const causeMessage = (fields as { causeMessage: string }).causeMessage;
    expect(causeMessage).toBe(
      `model call failed after ${MAX_TRANSPORT_ATTEMPTS} attempts: HTTP error: FakeOverloadedError HTTP 529`,
    );

    // Nothing sensitive: provider body, headers, repository content, prompt text.
    const serialized = JSON.stringify(fields);
    for (const forbidden of [
      PROVIDER_BODY_TEXT,
      HEADER_VALUE,
      "authorization",
      "Bearer",
      REPO_SECRET,
      "<repo_file",
      "comp-app",
      ...CANARY_INJECTION_PHRASES,
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    // .debug/ dumps stay off: NODE_ENV is not development.
    expect(writeDebug).not.toHaveBeenCalled();
  });

  it("tags the thrown error with its batch only, without element ids", async () => {
    const client = overloadedClient();
    const state = createAnalysis("acme/canary");
    let thrown: unknown;
    await runAnalysis(state.id, {
      ...pipelineDeps(client, () => {}),
      generateThreats: (input) =>
        generateThreats({
          ...input,
          concurrency: 1,
          deps: { ...input.deps, client, sleep: async () => {} },
        }).catch((error: unknown) => {
          thrown = error;
          throw error;
        }),
    });

    expect(failedBatchOf(thrown)).toEqual({ number: 1, of: 2 });
    expect(failedBatchOf(new Error("unrelated"))).toBeUndefined();
    expect(failedBatchOf(undefined)).toBeUndefined();
  });

  it("logs nothing in production when the flag is not set", async () => {
    const state = createAnalysis("acme/canary");

    const result = await runAnalysis(state.id, pipelineDeps(overloadedClient(), () => {}));

    expect(result.stage).toBe("failed");
    expect(log).not.toHaveBeenCalled();
  });

  it("does not treat any value other than '1' as enabling the log", async () => {
    vi.stubEnv(FAILURE_DIAGNOSTICS_ENV, "true");
    const state = createAnalysis("acme/canary");

    await runAnalysis(state.id, pipelineDeps(overloadedClient(), () => {}));

    expect(log).not.toHaveBeenCalled();
  });

  it("keeps the public error to the code and the fixed copy", async () => {
    vi.stubEnv(FAILURE_DIAGNOSTICS_ENV, "1");
    const state = createAnalysis("acme/canary");

    const result = await runAnalysis(state.id, pipelineDeps(overloadedClient(), () => {}));

    expect(Object.keys(result.error ?? {}).sort()).toEqual(["code", "message"]);
    expect(JSON.stringify(result.error)).not.toContain(PROVIDER_BODY_TEXT);
  });
});
