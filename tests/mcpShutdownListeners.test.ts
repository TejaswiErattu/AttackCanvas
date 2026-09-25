import { describe, expect, it, vi } from "vitest";

vi.mock("@modelcontextprotocol/sdk/client/stdio.js", () => ({
  StdioClientTransport: class {},
  getDefaultEnvironment: () => ({ PATH: "/usr/bin" }),
}));

vi.mock("@modelcontextprotocol/sdk/client/index.js", () => ({
  Client: class {
    async connect() {}
    async close() {}
  },
}));

const EVENTS = ["exit", "SIGINT", "SIGTERM"] as const;

async function freshConnection() {
  vi.resetModules();
  const { createStdioConnection } = await import("@/server/mcp/base");
  return createStdioConnection({
    command: "x",
    args: [],
    clientName: "t",
    clientVersion: "0",
    errors: {} as never,
    isTyped: () => false,
    isConfigError: () => false,
    startFailureContext: "t",
  });
}

describe("createStdioConnection shutdown handlers", () => {
  it("does not add process listeners per connection", async () => {
    const first = await freshConnection();
    await first.getClient();
    const before = EVENTS.map((e) => process.listenerCount(e));

    for (let i = 0; i < 15; i++) {
      const c = await freshConnection();
      await c.getClient();
      await c.closeClient();
      await c.getClient(); // reconnect after close
    }

    expect(EVENTS.map((e) => process.listenerCount(e))).toEqual(before);
  });
});
