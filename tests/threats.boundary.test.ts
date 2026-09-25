import { describe, expect, it, vi } from "vitest";
import type Anthropic from "@anthropic-ai/sdk";
import type { ClaudeDeps, MessagesApi } from "@/server/ai/claude";
import { UsageLedger } from "@/server/ai/usage";
import type { MergedArchitecture } from "@/server/analysis/architecture";
import { generateThreats } from "@/server/analysis/threats";
import * as threatPrompt from "@/server/analysis/threatPrompt";

/**
 * The engine's own guard, tested apart from the builder's. buildThreatBatch is replaced by a
 * stub that returns whatever text a test wants, so the only thing standing between that text
 * and the model is the engine's assertBatchClean call.
 */
vi.mock("@/server/analysis/threatPrompt", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/server/analysis/threatPrompt")>();
  return { ...actual, buildThreatBatch: vi.fn() };
});

const architecture: MergedArchitecture = {
  components: [
    {
      id: "svc-01",
      name: "svc-01",
      type: "backend",
      description: "d",
      technologies: [],
      files: [],
      assets: [],
    },
  ],
  dataFlows: [],
  trustBoundaries: [],
  unknowns: [],
  evidence: [],
  limitations: [],
  gapBindings: new Map(),
  componentEvidence: new Map(),
  flowEvidence: new Map(),
  issues: [],
};

function stubBatch(text: string, files: string[] = []) {
  return {
    text,
    elements: [
      {
        kind: "component" as const,
        id: "svc-01",
        type: "backend" as const,
        name: "svc-01",
        description: "d",
        assets: [],
        stride: ["S" as const],
        evidenceIds: [],
        gaps: [],
        unknownIds: [],
        files,
      },
    ],
    includedFiles: [],
    droppedFiles: [],
    unresolvedIds: [],
    extraWindows: [],
    estimatedTokens: 1,
  };
}

function clientWith(calls: unknown[]): Partial<ClaudeDeps> {
  const client: MessagesApi = {
    async create(body) {
      calls.push(body);
      return {
        id: "m",
        type: "message",
        role: "assistant",
        model: "claude-sonnet-5",
        content: [{ type: "text", text: JSON.stringify({ threats: [] }), citations: null }],
        stop_reason: "end_turn",
        stop_sequence: null,
        stop_details: null,
        usage: { input_tokens: 1, output_tokens: 1, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 },
      } as Anthropic.Message;
    },
  };
  return {
    client,
    ledger: new UsageLedger(),
    sleep: async () => {},
    schedule: () => () => {},
    isDevelopment: false,
    writeDebug: () => {},
  };
}

const run = (deps: Partial<ClaudeDeps>) =>
  generateThreats({ architecture, gaps: [], files: [], analysisId: "boundary", deps });

describe("the engine's own guard before a request", () => {
  it("refuses a batch whose text still holds a credential, and makes no request", async () => {
    vi.mocked(threatPrompt.buildThreatBatch).mockReturnValueOnce(
      stubBatch("### ELEMENT svc-01\nleaked AKIAZZTHREATZZ000001 here\n"),
    );
    const calls: unknown[] = [];
    const error = (await run(clientWith(calls)).catch((e: unknown) => e)) as Error;

    expect(error.name).toBe("SecretLeakError");
    expect(error.message).toBe("refusing to continue: unredacted secret (aws_access_key at line 2)");
    expect(error.message).not.toContain("AKIAZZ");
    expect(calls).toHaveLength(0);
  });

  it("refuses a batch with a credential-shaped path in an element, and makes no request", async () => {
    vi.mocked(threatPrompt.buildThreatBatch).mockReturnValueOnce(
      stubBatch("### ELEMENT svc-01\nclean text\n", ["src/AKIAZZTHREATZZ000001.ts"]),
    );
    const calls: unknown[] = [];
    await expect(run(clientWith(calls))).rejects.toMatchObject({ name: "SecretLeakError" });
    expect(calls).toHaveLength(0);
  });

  it("does not stop a clean batch: the guard is not a blanket refusal", async () => {
    vi.mocked(threatPrompt.buildThreatBatch).mockReturnValueOnce(stubBatch("### ELEMENT svc-01\nclean text\n"));
    const calls: unknown[] = [];
    const result = await run(clientWith(calls));
    expect(calls).toHaveLength(1);
    expect(result.threats).toEqual([]);
  });

  it("never sends a request after a guard failure, even when the next batch is clean", async () => {
    const two: MergedArchitecture = {
      ...architecture,
      components: [...architecture.components, { ...architecture.components[0], id: "svc-02", name: "svc-02" }],
    };
    vi.mocked(threatPrompt.buildThreatBatch)
      .mockReturnValueOnce(stubBatch("AKIAZZTHREATZZ000001"))
      .mockReturnValueOnce(stubBatch("clean"));
    const calls: unknown[] = [];
    await expect(
      generateThreats({ architecture: two, gaps: [], files: [], analysisId: "b", deps: clientWith(calls), concurrency: 1 }),
    ).rejects.toMatchObject({ name: "SecretLeakError" });
    expect(calls).toHaveLength(0);
  });
});
