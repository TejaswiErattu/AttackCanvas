import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  README_BODY,
  README_STATUS_MESSAGE,
  REAL_GET_FILE_CONTENTS_RESULT,
  REST_README_RESPONSE,
  STATUS_ONLY_RESULT,
} from "./githubResponses";

/**
 * getFileContent end to end: the SDK is mocked so nothing spawns Docker, and fetch is
 * stubbed for the REST fallback. Uses the response shape captured from the live server.
 */

const mcpCalls: { name: string; arguments: Record<string, unknown> }[] = [];
let mcpBehavior: () => Promise<unknown> = async () => REAL_GET_FILE_CONTENTS_RESULT;

vi.mock("@modelcontextprotocol/sdk/client/stdio.js", () => ({
  StdioClientTransport: class {},
  getDefaultEnvironment: () => ({ PATH: "/usr/bin" }),
}));

vi.mock("@modelcontextprotocol/sdk/client/index.js", () => ({
  Client: class {
    async connect() {}
    async close() {}
    async callTool(params: { name: string; arguments: Record<string, unknown> }) {
      mcpCalls.push(params);
      return mcpBehavior();
    }
  },
}));

const FAKE_TOKEN = "github_pat_fake_value_for_tests";
const fetchMock = vi.fn();

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), { status: 200, ...init });
}

function mcpReturns(result: unknown) {
  mcpBehavior = async () => result;
}

async function freshModule() {
  vi.resetModules();
  return import("@/server/mcp/githubClient");
}

beforeEach(() => {
  mcpCalls.length = 0;
  mcpReturns(REAL_GET_FILE_CONTENTS_RESULT);
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  process.env.GITHUB_PERSONAL_ACCESS_TOKEN = FAKE_TOKEN;
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
});

describe("getFileContent with the real MCP response", () => {
  it("returns the file body, not the status message", async () => {
    const { getFileContent } = await freshModule();
    const content = await getFileContent("octocat", "Hello-World", "master", "README");

    expect(content).toBe(README_BODY);
    expect(content).not.toBe(README_STATUS_MESSAGE);
    expect(content).not.toContain("successfully downloaded");
  });

  it("uses MCP alone, with no REST call", async () => {
    const { getFileContentWithSource } = await freshModule();
    const file = await getFileContentWithSource("octocat", "Hello-World", "master", "README");

    expect(file).toEqual({ content: README_BODY, source: "mcp" });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(mcpCalls).toEqual([
      {
        name: "get_file_contents",
        arguments: { owner: "octocat", repo: "Hello-World", ref: "master", path: "README" },
      },
    ]);
  });

  it("returns an empty file as an empty string, without falling back", async () => {
    mcpReturns({
      content: [
        { type: "text", text: "successfully downloaded text file (SHA: abc1234)" },
        { type: "resource", resource: { uri: "repo://x", mimeType: "text/plain", text: "" } },
      ],
    });
    const { getFileContentWithSource } = await freshModule();

    await expect(getFileContentWithSource("o", "r", "main", "empty.txt")).resolves.toEqual({
      content: "",
      source: "mcp",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("decodes a base64 blob resource", async () => {
    mcpReturns({
      content: [
        { type: "text", text: "successfully downloaded binary file (SHA: abc1234)" },
        { type: "resource", resource: { blob: Buffer.from("héllo").toString("base64") } },
      ],
    });
    const { getFileContent } = await freshModule();

    await expect(getFileContent("o", "r", "main", "a.txt")).resolves.toBe("héllo");
  });

  it("refuses a binary blob rather than returning garbage", async () => {
    mcpReturns({
      content: [
        { type: "resource", resource: { blob: Buffer.from([0x89, 0x00, 0x01]).toString("base64") } },
      ],
    });
    const { getFileContent } = await freshModule();

    await expect(getFileContent("o", "r", "main", "logo.png")).rejects.toThrow(/looks binary/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("still accepts a text-only server that returns the body as text", async () => {
    mcpReturns({ content: [{ type: "text", text: "const x = 1;\n" }] });
    const { getFileContentWithSource } = await freshModule();

    await expect(getFileContentWithSource("o", "r", "main", "x.ts")).resolves.toEqual({
      content: "const x = 1;\n",
      source: "mcp",
    });
  });

  it("rejects an oversized resource without falling back", async () => {
    mcpReturns({
      content: [{ type: "resource", resource: { text: "a".repeat(1024 * 1024 + 1) } }],
    });
    const { getFileContent } = await freshModule();

    await expect(getFileContent("o", "r", "main", "big.txt")).rejects.toMatchObject({
      code: "REPO_TOO_LARGE",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("REST Contents fallback", () => {
  beforeEach(() => {
    mcpReturns(STATUS_ONLY_RESULT);
    fetchMock.mockResolvedValue(jsonResponse(REST_README_RESPONSE));
  });

  it("falls back when the MCP result has only a status message", async () => {
    const { getFileContentWithSource } = await freshModule();
    const file = await getFileContentWithSource("octocat", "Hello-World", "master", "README");

    expect(file).toEqual({ content: README_BODY, source: "rest" });
    expect(file.content).not.toBe(README_STATUS_MESSAGE);
  });

  it("never returns the status message, even if that is all MCP has", async () => {
    mcpReturns({ content: [{ type: "text", text: README_STATUS_MESSAGE }] });
    const { getFileContent } = await freshModule();

    const content = await getFileContent("octocat", "Hello-World", "master", "README");
    expect(content).toBe(README_BODY);
  });

  it("calls the Contents API for the file at the ref, with the token in a header only", async () => {
    const { getFileContent } = await freshModule();
    await getFileContent("octocat", "Hello-World", "master", "docs/read me.md");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];

    expect(url).toBe(
      "https://api.github.com/repos/octocat/Hello-World/contents/docs/read%20me.md?ref=master",
    );
    expect(url).not.toContain(FAKE_TOKEN);
    expect((init.headers as Record<string, string>).Authorization).toBe(`Bearer ${FAKE_TOKEN}`);
    expect(init.method ?? "GET").toBe("GET");
  });

  it("sends a ref parsed from a URL to GitHub encoded exactly once, on both paths", async () => {
    // parseGitHubUrl decodes the ref ("caf%C3%A9" -> "café"); this client encodes it.
    const { parseGitHubUrl } = await import("@/server/ingest/urlParser");
    const parsed = parseGitHubUrl("https://github.com/o/r/tree/caf%C3%A9");
    if (!parsed.ok || parsed.ref === undefined) throw new Error("expected a ref");
    expect(parsed.ref).toBe("café");

    const { getFileContent, listTree } = await freshModule();
    await getFileContent("o", "r", parsed.ref, "README");
    expect(mcpCalls[0].arguments.ref).toBe("café"); // MCP gets the value, unencoded
    const [contentsUrl] = fetchMock.mock.calls[0] as [string];
    expect(contentsUrl).toBe("https://api.github.com/repos/o/r/contents/README?ref=caf%C3%A9");

    mcpReturns({ content: [{ type: "text", text: "boom" }], isError: true });
    fetchMock.mockResolvedValue(jsonResponse({ tree: [], truncated: false }));
    await listTree("o", "r", parsed.ref);
    const [treeUrl] = fetchMock.mock.calls[1] as [string];
    expect(treeUrl).toBe("https://api.github.com/repos/o/r/git/trees/caf%C3%A9?recursive=1");
    expect(treeUrl).not.toContain("%25");
  });

  it("applies the 60 second timeout to the request", async () => {
    const { getFileContent } = await freshModule();
    await getFileContent("o", "r", "main", "README");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it("falls back when MCP fails in a way that is not a repository error", async () => {
    mcpReturns({ content: [{ type: "text", text: "boom" }], isError: true });
    const { getFileContentWithSource } = await freshModule();

    await expect(getFileContentWithSource("o", "r", "main", "README")).resolves.toEqual({
      content: README_BODY,
      source: "rest",
    });
  });

  it("does not fall back when MCP reports the repository is missing", async () => {
    mcpReturns({ content: [{ type: "text", text: "404 Not Found" }], isError: true });
    const { getFileContent } = await freshModule();

    await expect(getFileContent("o", "r", "main", "README")).rejects.toMatchObject({
      code: "REPO_NOT_FOUND",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not fall back when MCP is rate limited", async () => {
    mcpReturns({ content: [{ type: "text", text: "API rate limit exceeded" }], isError: true });
    const { getFileContent } = await freshModule();

    await expect(getFileContent("o", "r", "main", "README")).rejects.toMatchObject({
      code: "UPSTREAM_RATE_LIMITED",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not fall back on a missing token", async () => {
    delete process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
    const { getFileContent, GitHubClientConfigError } = await freshModule();

    await expect(getFileContent("o", "r", "main", "README")).rejects.toThrow(
      GitHubClientConfigError,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports a directory from MCP as an error, without retrying over REST", async () => {
    mcpReturns({ content: [{ type: "text", text: JSON.stringify([{ name: "a.ts", type: "file" }]) }] });
    const { getFileContent } = await freshModule();

    await expect(getFileContent("o", "r", "main", "src")).rejects.toThrow(/directory/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports a directory from the REST fallback as an error", async () => {
    fetchMock.mockResolvedValue(jsonResponse([{ name: "a.ts", type: "file" }]));
    const { getFileContent } = await freshModule();

    await expect(getFileContent("o", "r", "main", "src")).rejects.toThrow(/directory/);
  });

  describe("size cap", () => {
    it("accepts a file of exactly 1 MiB, despite base64 inflating the body", async () => {
      const size = 1024 * 1024;
      fetchMock.mockResolvedValue(
        jsonResponse({
          type: "file",
          encoding: "base64",
          size,
          content: Buffer.alloc(size, 0x61).toString("base64"),
        }),
      );
      const { getFileContent } = await freshModule();

      await expect(getFileContent("o", "r", "main", "big.txt")).resolves.toHaveLength(size);
    });

    it("rejects a file one byte over 1 MiB", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ type: "file", encoding: "base64", size: 1024 * 1024 + 1, content: "YQ==" }),
      );
      const { getFileContent } = await freshModule();

      await expect(getFileContent("o", "r", "main", "big.txt")).rejects.toMatchObject({
        code: "REPO_TOO_LARGE",
      });
    });

    it("rejects a file too large for the API to inline", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ type: "file", encoding: "none", size: 3_000_000, content: "" }),
      );
      const { getFileContent } = await freshModule();

      await expect(getFileContent("o", "r", "main", "huge.bin")).rejects.toMatchObject({
        code: "REPO_TOO_LARGE",
      });
    });

    it("rejects a response body far beyond any legitimate file", async () => {
      fetchMock.mockResolvedValue(
        jsonResponse({ type: "file", encoding: "base64", content: "a".repeat(2_000_000) }),
      );
      const { getFileContent } = await freshModule();

      await expect(getFileContent("o", "r", "main", "x")).rejects.toMatchObject({
        code: "REPO_TOO_LARGE",
      });
    });
  });

  describe("error mapping", () => {
    it.each([
      [404, undefined, "REPO_NOT_FOUND"],
      [403, "0", "UPSTREAM_RATE_LIMITED"],
      [429, undefined, "UPSTREAM_RATE_LIMITED"],
      [403, "4999", "REPO_NOT_FOUND"],
      [500, undefined, "GITHUB_UNAVAILABLE"],
    ])("maps HTTP %i (remaining %s) to %s", async (status, remaining, code) => {
      const headers: Record<string, string> = remaining ? { "x-ratelimit-remaining": remaining } : {};
      fetchMock.mockResolvedValue(new Response("nope", { status, headers }));
      const { getFileContent } = await freshModule();

      await expect(getFileContent("o", "r", "main", "README")).rejects.toMatchObject({ code });
    });

    it("maps a request timeout to TIMEOUT", async () => {
      fetchMock.mockRejectedValue(
        new DOMException("The operation was aborted due to timeout", "TimeoutError"),
      );
      const { getFileContent } = await freshModule();

      await expect(getFileContent("o", "r", "main", "README")).rejects.toMatchObject({
        code: "TIMEOUT",
      });
    });

    it("treats a rejected token as a setup problem", async () => {
      fetchMock.mockResolvedValue(new Response("Bad credentials", { status: 401 }));
      const { getFileContent, GitHubClientConfigError } = await freshModule();

      await expect(getFileContent("o", "r", "main", "README")).rejects.toThrow(
        GitHubClientConfigError,
      );
    });

    it("never puts the token in an error message", async () => {
      fetchMock.mockResolvedValue(new Response("nope", { status: 500 }));
      const { getFileContent } = await freshModule();

      const error = await getFileContent("o", "r", "main", "README").catch((e: unknown) => e);
      expect((error as Error).message).not.toContain(FAKE_TOKEN);
    });
  });
});
