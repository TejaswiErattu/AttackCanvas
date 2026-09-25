// A minimal MCP server over stdio. Records when its stdin closes, which is what the
// client's close() does, so the parent test can tell the connection was closed.
import { writeFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const marker = process.argv[2];
const server = new McpServer({ name: "fake", version: "0" });
await server.connect(new StdioServerTransport());
process.stdin.on("close", () => {
  writeFileSync(marker, "closed");
  process.exit(0);
});
