import { describe, expect, it } from "vitest";
import {
  ALLOWED_TOOLS,
  GitHubClientConfigError,
  GitHubMcpError,
  MAX_RESPONSE_BYTES,
  bodyFromResources,
  callToolResultWith,
  callToolWith,
  extractResources,
  extractText,
  isDownloadStatusMessage,
  mapErrorCode,
  parseContentsResponse,
  parseFileContent,
  parseTree,
  restErrorFor,
  type ToolCaller,
} from "@/server/mcp/githubClient";
import {
  README_BODY,
  README_STATUS_MESSAGE,
  REAL_GET_FILE_CONTENTS_RESULT,
  REST_README_RESPONSE,
  STATUS_ONLY_RESULT,
} from "./githubResponses";

/** A stub MCP client that returns a fixed result, or throws. */
function stubClient(result: unknown, throws?: unknown): ToolCaller & { calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    calls,
    async callTool(params, _schema, options) {
      calls.push({ params, options });
      if (throws !== undefined) throw throws;
      return result;
    },
  };
}

function textResult(text: string, isError = false) {
  return { content: [{ type: "text", text }], isError };
}

describe("allowlist", () => {
  it("calls a tool that is on the list", async () => {
    const client = stubClient(textResult("ok"));
    await expect(callToolWith(client, "get_file_contents", { owner: "a" })).resolves.toBe("ok");
    expect(client.calls).toHaveLength(1);
  });

  it.each(ALLOWED_TOOLS)("allows %s", async (name) => {
    const client = stubClient(textResult("ok"));
    await expect(callToolWith(client, name)).resolves.toBe("ok");
  });

  it.each([
    "create_or_update_file",
    "delete_file",
    "create_pull_request",
    "merge_pull_request",
    "search_code",
    "list_repository_collaborators",
  ])("refuses %s", async (name) => {
    const client = stubClient(textResult("ok"));
    await expect(callToolWith(client, name)).rejects.toThrow(GitHubClientConfigError);
  });

  it("refuses before calling the client at all", async () => {
    const client = stubClient(textResult("ok"));
    await expect(callToolWith(client, "delete_repository")).rejects.toThrow(
      /not in ALLOWED_TOOLS/,
    );
    expect(client.calls).toEqual([]);
  });

  it("contains only read tools", () => {
    for (const name of ALLOWED_TOOLS) {
      expect(name, name).toMatch(/^(get|list)_/);
      expect(name, name).not.toMatch(/create|update|delete|merge|push|write|add/);
    }
  });
});

describe("timeout wiring", () => {
  it("passes the timeout to the client", async () => {
    const client = stubClient(textResult("ok"));
    await callToolWith(client, "list_tags", {}, 1234);
    expect(client.calls[0]).toMatchObject({ options: { timeout: 1234 } });
  });

  it("defaults to 60 seconds", async () => {
    const client = stubClient(textResult("ok"));
    await callToolWith(client, "list_tags");
    expect(client.calls[0]).toMatchObject({ options: { timeout: 60_000 } });
  });
});

describe("size cap", () => {
  it("accepts a response exactly at the cap", () => {
    const text = "a".repeat(MAX_RESPONSE_BYTES);
    expect(extractText([{ type: "text", text }])).toHaveLength(MAX_RESPONSE_BYTES);
  });

  it("rejects one byte over the cap", () => {
    const text = "a".repeat(MAX_RESPONSE_BYTES + 1);
    expect(() => extractText([{ type: "text", text }])).toThrow(GitHubMcpError);
  });

  it("counts bytes across items, not characters", () => {
    // Four-byte characters: half the cap in characters is twice the cap in bytes.
    const text = "😀".repeat(MAX_RESPONSE_BYTES / 4);
    expect(() => extractText([{ type: "text", text }, { type: "text", text }])).toThrow(
      /exceeds/,
    );
  });

  it("reports an oversized response as REPO_TOO_LARGE", async () => {
    const client = stubClient(textResult("a".repeat(MAX_RESPONSE_BYTES + 1)));
    await expect(callToolWith(client, "get_file_contents")).rejects.toMatchObject({
      code: "REPO_TOO_LARGE",
    });
  });
});

describe("text extraction", () => {
  it("joins text items and ignores other types", () => {
    const content = [
      { type: "text", text: "one" },
      { type: "image", data: "ignored" },
      { type: "text", text: "two" },
      { type: "resource", resource: {} },
    ];
    expect(extractText(content)).toBe("one\ntwo");
  });

  it("ignores text items whose text is not a string", () => {
    expect(extractText([{ type: "text", text: 42 }, { type: "text", text: "ok" }])).toBe("ok");
  });

  it("returns an empty string for missing or malformed content", () => {
    expect(extractText(undefined)).toBe("");
    expect(extractText(null)).toBe("");
    expect(extractText("not an array")).toBe("");
    expect(extractText([])).toBe("");
  });
});

describe("error mapping", () => {
  it.each([
    ["404 Not Found", "REPO_NOT_FOUND"],
    ["Repository not found", "REPO_NOT_FOUND"],
    ["403 Forbidden", "REPO_NOT_FOUND"],
    ["API rate limit exceeded", "UPSTREAM_RATE_LIMITED"],
    ["403 rate limit exceeded for user", "UPSTREAM_RATE_LIMITED"],
    ["You have exceeded a secondary rate limit", "UPSTREAM_RATE_LIMITED"],
    ["429 Too Many Requests", "UPSTREAM_RATE_LIMITED"],
    ["Request timed out", "TIMEOUT"],
    ["The operation was aborted", "TIMEOUT"],
    ["ETIMEDOUT", "TIMEOUT"],
    ["response is too large", "REPO_TOO_LARGE"],
    ["something else broke", "AI_FAILURE"],
  ])("maps %j to %s", (message, code) => {
    expect(mapErrorCode(message)).toBe(code);
  });

  it("prefers rate limit over the 403 that carries it", () => {
    expect(mapErrorCode("403 Forbidden: API rate limit exceeded")).toBe("UPSTREAM_RATE_LIMITED");
  });

  it("returns the caller's unclassified code when nothing matches", () => {
    expect(mapErrorCode("something else broke", "GITHUB_UNAVAILABLE")).toBe("GITHUB_UNAVAILABLE");
    // A classified message keeps its own code whatever the fallback.
    expect(mapErrorCode("404 Not Found", "GITHUB_UNAVAILABLE")).toBe("REPO_NOT_FOUND");
  });

  it("types an unclassified GitHub failure as GITHUB_UNAVAILABLE, not the catch-all", async () => {
    const thrown = stubClient(null, new Error("socket hang up"));
    await expect(callToolWith(thrown, "list_commits")).rejects.toMatchObject({
      code: "GITHUB_UNAVAILABLE",
      name: "GitHubMcpError",
    });
    const reported = stubClient(textResult("internal server error", true));
    await expect(callToolWith(reported, "get_file_contents")).rejects.toMatchObject({
      code: "GITHUB_UNAVAILABLE",
      name: "GitHubMcpError",
    });
  });

  it("prefers timeout over other hints", () => {
    expect(mapErrorCode("404 after request timed out")).toBe("TIMEOUT");
  });

  it("maps an isError result by its text", async () => {
    const client = stubClient(textResult("404 Not Found", true));
    await expect(callToolWith(client, "get_file_contents")).rejects.toMatchObject({
      code: "REPO_NOT_FOUND",
      name: "GitHubMcpError",
    });
  });

  it("maps a thrown transport error", async () => {
    const client = stubClient(null, new Error("Request timed out after 60000ms"));
    await expect(callToolWith(client, "list_commits")).rejects.toMatchObject({
      code: "TIMEOUT",
    });
  });

  it("maps a non-Error rejection", async () => {
    const client = stubClient(null, "rate limit exceeded");
    await expect(callToolWith(client, "list_commits")).rejects.toMatchObject({
      code: "UPSTREAM_RATE_LIMITED",
    });
  });

  it("names the tool in the message but never the arguments", async () => {
    const client = stubClient(textResult("404", true));
    const error = await callToolWith(client, "get_file_contents", {
      token: "should-not-appear",
    }).catch((cause: unknown) => cause);

    expect(error).toBeInstanceOf(GitHubMcpError);
    const { message } = error as GitHubMcpError;
    expect(message).toContain("get_file_contents");
    expect(message).not.toContain("should-not-appear");
  });
});

describe("real get_file_contents shape", () => {
  it("explains the original bug: the text block holds only the status line", () => {
    expect(extractText(REAL_GET_FILE_CONTENTS_RESULT.content)).toBe(README_STATUS_MESSAGE);
  });

  it("finds the file body in the resource block", () => {
    expect(extractResources(REAL_GET_FILE_CONTENTS_RESULT.content)).toEqual([
      {
        uri: "repo://octocat/Hello-World/sha/7fd1a60b01f91b314f59955a4e4d4e80d8edf11d/contents/README",
        mimeType: "text/plain; charset=utf-8",
        text: README_BODY,
      },
    ]);
  });

  it("returns text and resources together from the wrapper", async () => {
    const client = stubClient(REAL_GET_FILE_CONTENTS_RESULT);
    await expect(callToolResultWith(client, "get_file_contents")).resolves.toEqual({
      text: README_STATUS_MESSAGE,
      resources: extractResources(REAL_GET_FILE_CONTENTS_RESULT.content),
    });
  });

  it("keeps callToolWith returning text only", async () => {
    const client = stubClient(REAL_GET_FILE_CONTENTS_RESULT);
    await expect(callToolWith(client, "get_file_contents")).resolves.toBe(README_STATUS_MESSAGE);
  });
});

describe("extractResources", () => {
  it("returns nothing for text-only, missing or malformed content", () => {
    expect(extractResources(STATUS_ONLY_RESULT.content)).toEqual([]);
    expect(extractResources(undefined)).toEqual([]);
    expect(extractResources("nope")).toEqual([]);
    expect(extractResources([null, { type: "resource" }, { type: "resource", resource: 5 }])).toEqual(
      [],
    );
  });

  it("keeps only the string fields it recognises", () => {
    const [resource] = extractResources([
      { type: "resource", resource: { uri: "repo://x", text: "hi", mimeType: 7, extra: "no" } },
    ]);
    expect(resource).toEqual({ uri: "repo://x", text: "hi" });
  });

  it("carries a base64 blob", () => {
    const blob = Buffer.from("bytes").toString("base64");
    expect(extractResources([{ type: "resource", resource: { blob } }])).toEqual([{ blob }]);
  });

  it("accepts a resource text exactly at the cap and rejects one byte over", () => {
    const at = "a".repeat(MAX_RESPONSE_BYTES);
    expect(extractResources([{ type: "resource", resource: { text: at } }])).toHaveLength(1);
    expect(() =>
      extractResources([{ type: "resource", resource: { text: `${at}a` } }]),
    ).toThrow(GitHubMcpError);
  });

  it("caps a blob by its decoded size, not its base64 length", () => {
    const at = Buffer.alloc(MAX_RESPONSE_BYTES, 0x61).toString("base64");
    const over = Buffer.alloc(MAX_RESPONSE_BYTES + 1, 0x61).toString("base64");
    expect(extractResources([{ type: "resource", resource: { blob: at } }])).toHaveLength(1);
    expect(() => extractResources([{ type: "resource", resource: { blob: over } }])).toThrow(
      /exceeds/,
    );
  });

  it("does not let the status text count against a file of exactly the cap", async () => {
    const body = "a".repeat(MAX_RESPONSE_BYTES);
    const client = stubClient({
      content: [
        { type: "text", text: README_STATUS_MESSAGE },
        { type: "resource", resource: { text: body } },
      ],
    });
    const output = await callToolResultWith(client, "get_file_contents");
    expect(output.resources[0].text).toHaveLength(MAX_RESPONSE_BYTES);
  });
});

describe("isDownloadStatusMessage", () => {
  it("recognises the real status line", () => {
    expect(isDownloadStatusMessage(README_STATUS_MESSAGE)).toBe(true);
    expect(isDownloadStatusMessage(`  ${README_STATUS_MESSAGE}\n`)).toBe(true);
  });

  it("recognises a binary variant", () => {
    expect(isDownloadStatusMessage("successfully downloaded binary file (SHA: abc1234)")).toBe(true);
  });

  it("does not mistake file content for a status line", () => {
    expect(isDownloadStatusMessage(README_BODY)).toBe(false);
    expect(isDownloadStatusMessage("")).toBe(false);
    expect(isDownloadStatusMessage("# Notes\nsuccessfully downloaded text file (SHA: abc123)")).toBe(
      false,
    );
    expect(
      isDownloadStatusMessage(`${README_STATUS_MESSAGE}\nand then the real README text`),
    ).toBe(false);
  });
});

describe("bodyFromResources", () => {
  it("returns resource text, including an empty file", () => {
    expect(bodyFromResources([{ text: "hello" }], "f")).toBe("hello");
    expect(bodyFromResources([{ text: "" }], "f")).toBe("");
  });

  it("decodes a text blob", () => {
    const blob = Buffer.from("héllo").toString("base64");
    expect(bodyFromResources([{ blob }], "f")).toBe("héllo");
  });

  it("refuses a binary blob", () => {
    const blob = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]).toString("base64");
    expect(() => bodyFromResources([{ blob }], "logo.png")).toThrow(/looks binary/);
  });

  it("returns undefined when there is no body", () => {
    expect(bodyFromResources([], "f")).toBeUndefined();
    expect(bodyFromResources([{ uri: "repo://x" }], "f")).toBeUndefined();
  });
});

describe("parseContentsResponse", () => {
  it("decodes the real Contents API shape, including newlines in the base64", () => {
    expect(parseContentsResponse(REST_README_RESPONSE, "README")).toBe(README_BODY);
  });

  it("returns an empty file as an empty string", () => {
    expect(
      parseContentsResponse({ type: "file", encoding: "base64", content: "", size: 0 }, "x"),
    ).toBe("");
  });

  it("rejects a file over the cap by its reported size", () => {
    const file = { ...REST_README_RESPONSE, size: MAX_RESPONSE_BYTES + 1 };
    expect(() => parseContentsResponse(file, "big")).toThrow(/exceeds/);
  });

  it("rejects a file over the cap by its decoded size", () => {
    const content = Buffer.alloc(MAX_RESPONSE_BYTES + 1, 0x61).toString("base64");
    expect(() =>
      parseContentsResponse({ type: "file", encoding: "base64", content }, "big"),
    ).toThrow(/exceeds/);
  });

  it("reports a file too large for inline content as REPO_TOO_LARGE", () => {
    const file = { type: "file", encoding: "none", content: "", size: 5_000_000 };
    expect(() => parseContentsResponse(file, "huge")).toThrow(GitHubMcpError);
    expect(() => parseContentsResponse({ ...file, size: 1 }, "huge")).toThrow(/too large/);
  });

  it("rejects directories, symlinks and unsupported encodings", () => {
    expect(() => parseContentsResponse([{ name: "a" }], "src")).toThrow(/directory/);
    expect(() => parseContentsResponse({ type: "symlink" }, "link")).toThrow(/not a regular file/);
    expect(() => parseContentsResponse(null, "x")).toThrow(/not a regular file/);
    expect(() =>
      parseContentsResponse({ type: "file", encoding: "utf-16", content: "x" }, "x"),
    ).toThrow(/unsupported encoding/);
  });

  it("refuses binary content", () => {
    const content = Buffer.from([0x00, 0x01, 0x02]).toString("base64");
    expect(() =>
      parseContentsResponse({ type: "file", encoding: "base64", content }, "a.bin"),
    ).toThrow(/looks binary/);
  });
});

describe("REST status mapping", () => {
  it("treats a rejected credential as a setup problem, not an analysis failure", () => {
    const error = restErrorFor(401, null, "/repos/a/b");
    expect(error).toBeInstanceOf(GitHubClientConfigError);
    expect(error.message).toMatch(/missing, expired or revoked/);
  });

  it("maps an exhausted quota to UPSTREAM_RATE_LIMITED", () => {
    expect(restErrorFor(403, "0", "/repos/a/b")).toMatchObject({ code: "UPSTREAM_RATE_LIMITED" });
    expect(restErrorFor(429, null, "/repos/a/b")).toMatchObject({ code: "UPSTREAM_RATE_LIMITED" });
  });

  it("maps a 403 with quota left to REPO_NOT_FOUND", () => {
    expect(restErrorFor(403, "4999", "/repos/a/b")).toMatchObject({
      code: "REPO_NOT_FOUND",
    });
  });

  it.each([
    [404, "REPO_NOT_FOUND"],
    [500, "GITHUB_UNAVAILABLE"],
    [502, "GITHUB_UNAVAILABLE"],
  ])("maps %i to %s", (status, code) => {
    expect(restErrorFor(status, null, "/repos/a/b")).toMatchObject({ code });
  });

  it("names the path but never a credential", () => {
    expect(restErrorFor(404, null, "/repos/acme/notes").message).toContain(
      "/repos/acme/notes",
    );
  });
});

describe("parseTree", () => {
  it("reads GitHub's { tree } shape and normalises blob/tree", () => {
    const text = JSON.stringify({
      tree: [
        { path: "src", type: "tree" },
        { path: "src/index.ts", type: "blob", size: 120 },
      ],
      truncated: false,
    });

    expect(parseTree(text)).toEqual({
      entries: [
        { path: "src", type: "dir" },
        { path: "src/index.ts", type: "file", size: 120 },
      ],
      truncated: false,
    });
  });

  it("reads a bare array and an { entries } wrapper", () => {
    const expected = { entries: [{ path: "a.ts", type: "file" }], truncated: false };
    expect(parseTree(JSON.stringify([{ path: "a.ts", type: "blob" }]))).toEqual(expected);
    expect(parseTree(JSON.stringify({ entries: [{ path: "a.ts", type: "file" }] }))).toEqual(
      expected,
    );
  });

  it("accepts file/dir type names and a name field", () => {
    const text = JSON.stringify([
      { name: "docs", type: "dir" },
      { path: "r.md", type: "file" },
    ]);
    expect(parseTree(text).entries).toEqual([
      { path: "docs", type: "dir" },
      { path: "r.md", type: "file" },
    ]);
  });

  it("carries the truncated flag", () => {
    expect(parseTree(JSON.stringify({ tree: [], truncated: true })).truncated).toBe(true);
  });

  it("skips entries with no usable path", () => {
    const text = JSON.stringify([{ type: "blob" }, null, { path: "", type: "blob" }, { path: "ok" }]);
    expect(parseTree(text).entries).toEqual([{ path: "ok", type: "file" }]);
  });

  it("rejects non-JSON and a missing array", () => {
    expect(() => parseTree("<html>error</html>")).toThrow(/not JSON/);
    expect(() => parseTree(JSON.stringify({ message: "Not Found" }))).toThrow(
      /no entries array/,
    );
  });
});

describe("parseFileContent", () => {
  it("decodes base64 content", () => {
    const text = JSON.stringify({
      content: Buffer.from("hello world").toString("base64"),
      encoding: "base64",
    });
    expect(parseFileContent(text)).toBe("hello world");
  });

  it("returns plain content and a text wrapper", () => {
    expect(parseFileContent(JSON.stringify({ content: "plain" }))).toBe("plain");
    expect(parseFileContent(JSON.stringify({ text: "wrapped" }))).toBe("wrapped");
  });

  it("returns raw text unchanged", () => {
    expect(parseFileContent("const x = 1;\n")).toBe("const x = 1;\n");
  });

  it("returns text that only looks like JSON", () => {
    expect(parseFileContent("{ this is not json")).toBe("{ this is not json");
  });

  it("rejects a directory listing", () => {
    const text = JSON.stringify([{ name: "a.ts", type: "file" }]);
    expect(() => parseFileContent(text)).toThrow(/directory/);
  });

  it("rejects base64 content that decodes past the cap", () => {
    const big = Buffer.alloc(MAX_RESPONSE_BYTES + 1, 0x61).toString("base64");
    expect(() => parseFileContent(JSON.stringify({ content: big, encoding: "base64" })))
      .toThrow(/size cap/);
  });
});
