/**
 * Replay mode (src/server/analysis/replay.ts) through the real POST /api/analyze route
 * and the real pipeline store. The GitHub client and callStructured are spies: a replayed
 * job must reach neither, and a run that falls through must reach GitHub as usual.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/server/mcp/githubClient", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/server/mcp/githubClient")>()),
  getClient: vi.fn(() => Promise.reject(new Error("github client called"))),
  callTool: vi.fn(() => Promise.reject(new Error("github client called"))),
  getRepoMetadata: vi.fn(() => Promise.reject(new Error("github client called"))),
  listTree: vi.fn(() => Promise.reject(new Error("github client called"))),
  getFileContent: vi.fn(() => Promise.reject(new Error("github client called"))),
}));
vi.mock("@/server/ai/claude", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/server/ai/claude")>()),
  callStructured: vi.fn(() => Promise.reject(new Error("model called"))),
}));
vi.mock("@/server/log", () => ({ log: vi.fn() }));

import { POST } from "@/app/api/analyze/route";
import { GET } from "@/app/api/analyze/[id]/route";
import { getAnalysis, resetStore } from "@/server/analysis/pipeline";
import {
  REPLAYED_DIAGNOSTIC,
  REPLAY_DIR_ENV,
  loadReplay,
  replayDir,
  replayFileName,
  resetReplayWarning,
} from "@/server/analysis/replay";
import { resetRateLimiter } from "@/server/http/rateLimit";
import { callStructured } from "@/server/ai/claude";
import * as github from "@/server/mcp/githubClient";
import { log } from "@/server/log";

const NODEGOAT = "https://github.com/OWASP/NodeGoat";
const REPLAY_FIXTURES = join(process.cwd(), "fixtures", "replay");

function postRequest(repoUrl: string): NextRequest {
  return new NextRequest("http://localhost/api/analyze", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": "7.7.7.7" },
    body: JSON.stringify({ repoUrl, analysisLevel: 1 }),
  });
}

function githubCalls(): number {
  return [github.getClient, github.callTool, github.getRepoMetadata, github.listTree, github.getFileContent]
    .map((fn) => vi.mocked(fn).mock.calls.length)
    .reduce((a, b) => a + b, 0);
}

/** Lets a fire-and-forget runAnalysis reach its first GitHub call and fail. */
async function settle(id: string): Promise<void> {
  for (let i = 0; i < 50 && getAnalysis(id)?.stage !== "failed"; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

beforeEach(() => {
  resetStore();
  resetRateLimiter();
  resetReplayWarning();
  vi.clearAllMocks();
  vi.stubEnv("NODE_ENV", "test");
  vi.stubEnv(REPLAY_DIR_ENV, REPLAY_FIXTURES);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("replay mode", () => {
  it("completes from the saved file without calling GitHub or the model", async () => {
    const response = await POST(postRequest(NODEGOAT));
    expect(response.status).toBe(202);
    const { analysisId, status } = (await response.json()) as { analysisId: string; status: string };
    expect(status).toBe("complete");

    const state = getAnalysis(analysisId)!;
    expect(state.replayed).toBe(true);
    expect(state.diagnostics).toContain(REPLAYED_DIAGNOSTIC);
    expect(state.threatModel?.repo.name).toBe("NodeGoat");
    expect(githubCalls()).toBe(0);
    expect(callStructured).not.toHaveBeenCalled();

    const polled = await GET(new NextRequest(`http://localhost/api/analyze/${analysisId}`), {
      params: Promise.resolve({ id: analysisId }),
    });
    const body = (await polled.json()) as { replayed?: boolean; stage: string };
    expect(body).toMatchObject({ stage: "complete", replayed: true });
  });

  it("matches the file name case-insensitively", async () => {
    const response = await POST(postRequest("https://github.com/owasp/nodegoat"));
    expect(((await response.json()) as { status: string }).status).toBe("complete");
    expect(githubCalls()).toBe(0);
  });

  it("is ignored in production, with one warning, and the run goes to GitHub", async () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(replayDir()).toBeUndefined();
    expect(replayDir()).toBeUndefined();
    expect(vi.mocked(log).mock.calls.filter(([level]) => level === "warn")).toHaveLength(1);

    const response = await POST(postRequest(NODEGOAT));
    const { analysisId } = (await response.json()) as { analysisId: string };
    await settle(analysisId);
    const state = getAnalysis(analysisId)!;
    expect(state.replayed).toBe(false);
    expect(githubCalls()).toBeGreaterThan(0);
  });

  it("falls through to a normal run when the file does not validate", async () => {
    const dir = mkdtempSync(join(tmpdir(), "replay-"));
    writeFileSync(join(dir, "OWASP__NodeGoat.json"), JSON.stringify({ threats: "nope" }));
    vi.stubEnv(REPLAY_DIR_ENV, dir);
    expect(loadReplay(dir, "OWASP", "NodeGoat")).toBeUndefined();

    const response = await POST(postRequest(NODEGOAT));
    const { analysisId, status } = (await response.json()) as { analysisId: string; status: string };
    expect(status).not.toBe("complete");
    await settle(analysisId);
    expect(getAnalysis(analysisId)!.replayed).toBe(false);
    expect(githubCalls()).toBeGreaterThan(0);
  });

  it("falls through when the file is not JSON or is missing", () => {
    const dir = mkdtempSync(join(tmpdir(), "replay-"));
    writeFileSync(join(dir, "OWASP__NodeGoat.json"), "{not json");
    expect(loadReplay(dir, "OWASP", "NodeGoat")).toBeUndefined();
    expect(loadReplay(dir, "acme", "other")).toBeUndefined();
    expect(loadReplay(join(dir, "absent"), "OWASP", "NodeGoat")).toBeUndefined();
  });

  it("is off when the variable is unset or blank", () => {
    expect(replayDir({ NODE_ENV: "development" })).toBeUndefined();
    expect(replayDir({ NODE_ENV: "development", [REPLAY_DIR_ENV]: "  " })).toBeUndefined();
    expect(replayDir({ NODE_ENV: "development", [REPLAY_DIR_ENV]: "x" })).toBe("x");
  });

  it("refuses names that could leave the directory", () => {
    expect(replayFileName("OWASP", "NodeGoat")).toBe("OWASP__NodeGoat.json");
    expect(replayFileName("..", "x/y")).toBeUndefined();
  });
});
