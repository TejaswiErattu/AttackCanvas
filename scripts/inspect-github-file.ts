/**
 * Discovery: show the raw shape of a get_file_contents result.
 *
 *   pnpm try scripts/inspect-github-file.ts octocat/Hello-World README
 *   pnpm try scripts/inspect-github-file.ts octocat/Hello-World README master
 *
 * Prints structure (block types, keys, lengths) and a short preview of each text or
 * resource payload. It never prints the environment or the token.
 */
import { closeClient, getClient } from "@/server/mcp/githubClient";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

const PREVIEW = 160;

function preview(value: string): string {
  const flat = value.length > PREVIEW ? `${value.slice(0, PREVIEW)}…` : value;
  return JSON.stringify(flat);
}

function describeBlock(block: unknown, index: number): string[] {
  const lines: string[] = [];
  const item = block as Record<string, unknown>;
  lines.push(`  [${index}] type=${String(item?.type)}  keys=${Object.keys(item ?? {}).join(",")}`);

  if (typeof item?.text === "string") {
    lines.push(`      text: ${item.text.length} chars  ${preview(item.text)}`);
  }

  const resource = item?.resource as Record<string, unknown> | undefined;
  if (resource && typeof resource === "object") {
    lines.push(`      resource.keys=${Object.keys(resource).join(",")}`);
    if (typeof resource.uri === "string") lines.push(`      resource.uri: ${resource.uri}`);
    if (typeof resource.mimeType === "string") {
      lines.push(`      resource.mimeType: ${resource.mimeType}`);
    }
    if (typeof resource.text === "string") {
      lines.push(`      resource.text: ${resource.text.length} chars  ${preview(resource.text)}`);
    }
    if (typeof resource.blob === "string") {
      lines.push(`      resource.blob: ${resource.blob.length} base64 chars (not printed)`);
    }
  }

  if (typeof item?.data === "string") {
    lines.push(`      data: ${item.data.length} chars (not printed), mimeType=${String(item.mimeType)}`);
  }
  if (typeof item?.uri === "string") lines.push(`      uri: ${item.uri}`);
  return lines;
}

async function main(): Promise<void> {
  const [target, path = "README", ref] = process.argv.slice(2);
  const [owner, repo] = (target ?? "").split("/");
  if (!owner || !repo) {
    console.error("usage: pnpm try scripts/inspect-github-file.ts <owner/repo> [path] [ref]");
    process.exit(1);
  }

  const client = await getClient();
  const args: Record<string, unknown> = { owner, repo, path };
  if (ref) args.ref = ref;

  const result = (await client.callTool({ name: "get_file_contents", arguments: args })) as Record<
    string,
    unknown
  >;

  console.log(`get_file_contents ${JSON.stringify(args)}`);
  console.log(`result keys: ${Object.keys(result).join(", ")}`);
  console.log(`isError: ${String(result.isError)}`);
  if (result.structuredContent !== undefined) {
    console.log(`structuredContent: ${preview(JSON.stringify(result.structuredContent))}`);
  }

  const content = Array.isArray(result.content) ? result.content : [];
  console.log(`content blocks: ${content.length}`);
  content.forEach((block, index) => {
    for (const line of describeBlock(block, index)) console.log(line);
  });
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  })
  .finally(() => closeClient());
