import { describe, expect, it } from "vitest";
import { IMAGE, launchCommand } from "@/server/mcp/githubClient";

describe("launchCommand", () => {
  it("uses docker with the pinned image when GITHUB_MCP_BINARY is unset", () => {
    const { command, args } = launchCommand({});
    expect(command).toBe("docker");
    expect(args[args.length - 1]).toBe(IMAGE);
    expect(args).toContain("GITHUB_READ_ONLY");
  });

  it("treats a blank GITHUB_MCP_BINARY as unset", () => {
    expect(launchCommand({ GITHUB_MCP_BINARY: "  " }).command).toBe("docker");
  });

  it("runs the binary in stdio mode when GITHUB_MCP_BINARY is set", () => {
    expect(launchCommand({ GITHUB_MCP_BINARY: "/usr/local/bin/github-mcp-server" })).toEqual({
      command: "/usr/local/bin/github-mcp-server",
      args: ["stdio"],
    });
  });
});
