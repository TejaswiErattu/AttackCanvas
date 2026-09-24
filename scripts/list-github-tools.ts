/**
 * Discovery: connect to the GitHub MCP server and print every tool it exposes.
 *
 *   pnpm try scripts/list-github-tools.ts            # summary
 *   pnpm try scripts/list-github-tools.ts --json     # full schemas as JSON
 *
 * GITHUB_TOOLSETS overrides the toolset (default "repos") so you can check what other
 * toolsets expose. The client itself always pins "repos".
 *
 * Run this before touching src/server/mcp/githubClient.ts: the allowlist there must
 * name tools this server actually has, not ones we assume it has.
 *
 * Needs GITHUB_PERSONAL_ACCESS_TOKEN (from the environment or .env.local) and a
 * running Docker daemon. The token is passed to the child process through its
 * environment only, never through argv, and is never printed.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from "@modelcontextprotocol/sdk/client/stdio.js";
// The ONE authoritative pinned image, imported rather than re-typed: discovery must run
// against the exact version the production allowlist was verified against, and a second
// copy of the string here could drift from the client's without anything failing.
// Importing is side-effect-free -- githubClient's connection is a lazy closure, so this
// reads no token and spawns no container at import time.
import { IMAGE } from "@/server/mcp/githubClient";

const toolsets = process.env.GITHUB_TOOLSETS ?? "repos";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

const token = process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
if (!token) {
  console.error(
    [
      "GITHUB_PERSONAL_ACCESS_TOKEN is not set.",
      "",
      "Create a fine-grained token with public read access only (no write scopes),",
      "then put it in .env.local, which is gitignored:",
      "",
      "  GITHUB_PERSONAL_ACCESS_TOKEN=<your token>",
      "",
      "Do not paste the token into a chat or commit it.",
    ].join("\n"),
  );
  process.exit(1);
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

function describeParams(schema: ToolSchema | undefined): string {
  const properties = schema?.properties;
  if (!properties || Object.keys(properties).length === 0) return "    (no parameters)";
  const required = new Set(schema?.required ?? []);
  return Object.entries(properties)
    .map(([name, spec]) => {
      const flag = required.has(name) ? "*" : " ";
      const type = spec.type ?? "any";
      const help = spec.description ? ` — ${spec.description.split("\n")[0]}` : "";
      return `    ${flag} ${name}: ${type}${help}`;
    })
    .join("\n");
}

async function main(): Promise<void> {
  const transport = new StdioClientTransport({
    command: "docker",
    args: [
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
    ],
    // getDefaultEnvironment() supplies PATH so "docker" resolves; without it the
    // child would start with an empty environment.
    env: {
      ...getDefaultEnvironment(),
      GITHUB_PERSONAL_ACCESS_TOKEN: token!,
      GITHUB_TOOLSETS: toolsets,
      GITHUB_READ_ONLY: "1",
    },
    stderr: "pipe",
  });

  const client = new Client({ name: "attackcanvas-discovery", version: "0.1.0" });

  transport.stderr?.on("data", (chunk: Buffer) => {
    const line = chunk.toString().trim();
    if (line) console.error(`[server] ${line}`);
  });

  await client.connect(transport);

  try {
    const { tools } = (await client.listTools()) as { tools: Tool[] };
    const sorted = [...tools].sort((a, b) => a.name.localeCompare(b.name));

    if (process.argv.includes("--json")) {
      console.log(JSON.stringify(sorted, null, 2));
      return;
    }

    console.log(`server: ${IMAGE}`);
    console.log(`toolsets: ${toolsets}   read-only: 1`);
    console.log(`tools: ${sorted.length}\n`);

    for (const tool of sorted) {
      const summary = (tool.description ?? "").split("\n")[0].trim();
      console.log(`- ${tool.name}`);
      if (summary) console.log(`    ${summary}`);
      console.log(describeParams(tool.inputSchema));
      console.log();
    }

    console.log("(* marks a required parameter)");
    console.log(`\nall names:\n${sorted.map((t) => t.name).join("\n")}`);
  } finally {
    await client.close();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
