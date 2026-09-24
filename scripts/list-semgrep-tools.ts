/**
 * Discovery: connect to the Semgrep MCP server and print every tool it exposes.
 *
 *   pnpm try scripts/list-semgrep-tools.ts            # summary
 *   pnpm try scripts/list-semgrep-tools.ts --json     # full schemas as JSON
 *
 * Run this before touching src/server/mcp/semgrepClient.ts: the allowlist there must
 * name tools this server actually has, and the scan arguments must match the schema it
 * actually accepts, not the ones we assume.
 *
 * Needs the semgrep CLI on PATH ("brew install semgrep"). No token and no account: the
 * server runs locally, and metrics and the version check are turned off below.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from "@modelcontextprotocol/sdk/client/stdio.js";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

type ToolSchema = {
  type?: string;
  properties?: Record<string, { type?: string; description?: string }>;
  required?: string[];
};

type Tool = {
  name: string;
  description?: string;
  inputSchema?: ToolSchema;
};

const asJson = process.argv.includes("--json");

function summarise(tool: Tool): string {
  const properties = tool.inputSchema?.properties ?? {};
  const required = new Set(tool.inputSchema?.required ?? []);

  const args = Object.entries(properties).map(([name, spec]) => {
    const type = spec?.type ?? "unknown";
    return required.has(name) ? `${name}: ${type}` : `${name}?: ${type}`;
  });

  const signature = args.length > 0 ? args.join(", ") : "";
  const firstLine = (tool.description ?? "").trim().split("\n")[0] ?? "";

  return `  ${tool.name}(${signature})${firstLine ? `\n      ${firstLine}` : ""}`;
}

async function main(): Promise<void> {
  const transport = new StdioClientTransport({
    env: {
      ...getDefaultEnvironment(),
      SEMGREP_SEND_METRICS: "off",
      SEMGREP_ENABLE_VERSION_CHECK: "0",
    },
    command: "semgrep",
    args: ["mcp"],
    stderr: "ignore",
  });

  const client = new Client({ name: "attackcanvas-discovery", version: "0.1.0" });
  await client.connect(transport);

  try {
    const { tools } = (await client.listTools()) as { tools: Tool[] };

    if (asJson) {
      console.log(JSON.stringify(tools, null, 2));
      return;
    }

    console.log(`${tools.length} tools\n`);
    for (const tool of tools) {
      console.log(summarise(tool));
      console.log();
    }
  } finally {
    await client.close();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
