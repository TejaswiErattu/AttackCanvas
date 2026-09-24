import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Connection wiring, with the SDK mocked so nothing spawns Docker. Kept in its own
 * file because vi.mock applies to the whole module graph of the file it runs in.
 */

const transportCalls: { command: string; args: string[]; env: Record<string, string> }[] = [];
const connectCalls: unknown[] = [];
const closeCalls: { count: number } = { count: 0 };

vi.mock("@modelcontextprotocol/sdk/client/stdio.js", () => ({
  StdioClientTransport: class {
    constructor(options: { command: string; args: string[]; env: Record<string, string> }) {
      transportCalls.push(options);
    }
  },
  getDefaultEnvironment: () => ({ PATH: "/usr/bin" }),
}));

vi.mock("@modelcontextprotocol/sdk/client/index.js", () => ({
  Client: class {
    async connect(transport: unknown) {
      connectCalls.push(transport);
    }
    async close() {
      closeCalls.count += 1;
    }
  },
}));

const FAKE_TOKEN = "github_pat_fake_value_for_tests";

async function freshModule() {
  vi.resetModules();
  return import("@/server/mcp/githubClient");
}

beforeEach(() => {
  transportCalls.length = 0;
  connectCalls.length = 0;
  closeCalls.count = 0;
  process.env.GITHUB_PERSONAL_ACCESS_TOKEN = FAKE_TOKEN;
});

afterEach(() => {
  delete process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
});

describe("connection", () => {
  it("runs the documented docker command", async () => {
    const { getClient, IMAGE } = await freshModule();
    await getClient();

    // The image itself must carry an explicit tag, not float on `:latest` (Prompt U
    // Part 2: MCP hardening) -- asserted directly, not just matched, so a future edit
    // that drops the tag fails loudly here rather than only in docs/setup.md going stale.
    expect(IMAGE).toMatch(/^ghcr\.io\/github\/github-mcp-server:.+$/);

    expect(transportCalls).toHaveLength(1);
    expect(transportCalls[0].command).toBe("docker");
    expect(transportCalls[0].args).toEqual([
      "run",
      "-i",
      "--rm",
      "-e",
      "GITHUB_PERSONAL_ACCESS_TOKEN",
      "-e",
      "GITHUB_TOOLSETS",
      "-e",
      "GITHUB_READ_ONLY",
      IMAGE,
    ]);
  });

  it("passes the token through the environment, never through argv", async () => {
    const { getClient } = await freshModule();
    await getClient();

    const { args, env } = transportCalls[0];
    expect(args.join(" ")).not.toContain(FAKE_TOKEN);
    expect(args).toContain("GITHUB_PERSONAL_ACCESS_TOKEN"); // the name, not the value
    expect(env.GITHUB_PERSONAL_ACCESS_TOKEN).toBe(FAKE_TOKEN);
  });

  it("pins read-only mode and the toolsets that expose the tree tool", async () => {
    const { getClient } = await freshModule();
    await getClient();

    expect(transportCalls[0].env).toMatchObject({
      GITHUB_READ_ONLY: "1",
      GITHUB_TOOLSETS: "repos,git",
      PATH: "/usr/bin", // inherited so "docker" resolves
    });
  });

  it("connects once and reuses the client", async () => {
    const { getClient } = await freshModule();
    const [a, b, c] = await Promise.all([getClient(), getClient(), getClient()]);

    expect(transportCalls).toHaveLength(1);
    expect(connectCalls).toHaveLength(1);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it("closes the client and reconnects on the next use", async () => {
    const { getClient, closeClient } = await freshModule();
    await getClient();
    await closeClient();

    expect(closeCalls.count).toBe(1);

    await getClient();
    expect(transportCalls).toHaveLength(2);
  });

  it("forgets a connection whose server died, and reconnects on the next use", async () => {
    // When the child process exits, the SDK fires Client.onclose and drops its
    // transport; a cached client would then fail every call with "Not connected".
    const { getClient } = await freshModule();
    const first = (await getClient()) as unknown as { onclose?: () => void };
    expect(typeof first.onclose).toBe("function");

    first.onclose!(); // the transport closed underneath us

    const second = await getClient();
    expect(second).not.toBe(first);
    expect(transportCalls).toHaveLength(2);
    expect(await getClient()).toBe(second); // and the new one is cached as usual
  });

  it("does not let a stale close event evict a newer connection", async () => {
    const { getClient, closeClient } = await freshModule();
    const first = (await getClient()) as unknown as { onclose?: () => void };
    await closeClient();
    const second = await getClient();

    first.onclose!(); // late close event from the old connection

    expect(await getClient()).toBe(second);
    expect(transportCalls).toHaveLength(2);
  });

  it("closing without a connection is a no-op", async () => {
    const { closeClient } = await freshModule();
    await expect(closeClient()).resolves.toBeUndefined();
    expect(closeCalls.count).toBe(0);
  });

  it("fails with a config error when the token is missing", async () => {
    delete process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
    const { getClient, GitHubClientConfigError } = await freshModule();

    await expect(getClient()).rejects.toThrow(GitHubClientConfigError);
    expect(transportCalls).toEqual([]);
  });

  it("does not cache a failed connection", async () => {
    delete process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
    const { getClient } = await freshModule();

    await expect(getClient()).rejects.toThrow();

    process.env.GITHUB_PERSONAL_ACCESS_TOKEN = FAKE_TOKEN;
    await expect(getClient()).resolves.toBeDefined();
    expect(transportCalls).toHaveLength(1);
  });

  it("registers exactly one shutdown hook across many calls", async () => {
    const before = process.listenerCount("exit");
    const { getClient } = await freshModule();

    await getClient();
    await getClient();

    expect(process.listenerCount("exit")).toBe(before + 1);
  });
});

// ---------------------------------------------------------------------------
// Prompt U, Part 2: the pinned image has exactly one authoritative definition
// ---------------------------------------------------------------------------

describe("pinned image, single source of truth", () => {
  const SCRIPT = "scripts/list-github-tools.ts";

  it("is pinned to an explicit tag, not :latest and not bare", async () => {
    const { IMAGE } = await freshModule();
    expect(IMAGE).toMatch(/^ghcr\.io\/github\/github-mcp-server:.+$/);
    expect(IMAGE).not.toMatch(/:latest(@|$)/);
  });

  it("is also pinned to an immutable digest, since a tag can be re-pointed", async () => {
    const { IMAGE } = await freshModule();
    expect(IMAGE).toMatch(/:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/);
  });

  it("is not duplicated as a literal in the discovery script", () => {
    // Asserted against the script's SOURCE, because the property being protected is
    // "there is only one copy of this string" -- a second literal could hold a
    // different tag and nothing at runtime would notice the drift.
    const source = readFileSync(SCRIPT, "utf8");
    expect(source).not.toMatch(/["'`]ghcr\.io\/github\/github-mcp-server/);
  });

  it("makes the discovery script import the client's exported constant instead", () => {
    const source = readFileSync(SCRIPT, "utf8");
    expect(source).toMatch(/import\s*\{\s*IMAGE\s*\}\s*from\s*["']@\/server\/mcp\/githubClient["']/);
  });

  it("uses that one value for the container the script actually runs", async () => {
    const { IMAGE } = await freshModule();
    const source = readFileSync(SCRIPT, "utf8");
    // The script passes the imported IMAGE straight into its docker args; with no
    // literal anywhere in the file (asserted above), this is the only value it can use.
    expect(source).toMatch(/\bIMAGE\b/);
    expect(IMAGE).toBe(
      "ghcr.io/github/github-mcp-server:v1.12.2@sha256:508a0857ec762b1ab1cece29193345b501fab1dd9d1228a7b617062954cecac6",
    ); // matches docs/setup.md
  });
});
