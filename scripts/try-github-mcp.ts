/**
 * Smoke test against a real public repository.
 *
 *   pnpm try scripts/try-github-mcp.ts vercel/next.js
 *   pnpm try scripts/try-github-mcp.ts https://github.com/vercel/next.js
 *
 * Prints the default branch, the first 40 tree entries and the first 20 lines of the
 * README, and says whether each result came from MCP or the REST fallback.
 *
 * Needs GITHUB_PERSONAL_ACCESS_TOKEN (environment or .env.local) and Docker.
 */
import {
  GitHubClientConfigError,
  GitHubMcpError,
  closeClient,
  getFileContentWithSource,
  getRepoMetadata,
  isDownloadStatusMessage,
  listTree,
} from "@/server/mcp/githubClient";

const TREE_LIMIT = 40;
const README_LINES = 20;

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

/** Accepts "owner/repo", a github.com URL, or a .git clone URL. */
function parseTarget(input: string): { owner: string; repo: string } {
  const cleaned = input.trim().replace(/\.git$/, "");
  const match =
    /^https?:\/\/github\.com\/([^/]+)\/([^/?#]+)/.exec(cleaned) ??
    /^([^/\s]+)\/([^/\s]+)$/.exec(cleaned);

  if (!match) {
    throw new Error(`could not read "${input}" as owner/repo or a github.com URL`);
  }
  return { owner: match[1], repo: match[2] };
}

function findReadme(paths: string[]): string | undefined {
  return (
    paths.find((path) => /^readme\.md$/i.test(path)) ??
    paths.find((path) => /^readme(\.[a-z]+)?$/i.test(path)) ??
    paths.find((path) => /^readme/i.test(path))
  );
}

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error("usage: pnpm try scripts/try-github-mcp.ts <owner/repo | github URL>");
    process.exit(1);
  }

  const { owner, repo } = parseTarget(target);
  console.log(`repository: ${owner}/${repo}\n`);

  const metadata = await getRepoMetadata(owner, repo);
  console.log(`default branch: ${metadata.defaultBranch}   [via ${metadata.source}]`);
  console.log(`languages:      ${metadata.languages?.join(", ") ?? "(none reported)"}`);
  console.log(`size:           ${metadata.sizeKb ?? "?"} KB\n`);

  const tree = await listTree(owner, repo, metadata.defaultBranch);
  const shown = tree.entries.slice(0, TREE_LIMIT);
  console.log(
    `tree: ${tree.entries.length} entries` +
      `${tree.truncated ? " (truncated by GitHub)" : ""}, showing ${shown.length}` +
      `   [via ${tree.source}]`,
  );
  for (const entry of shown) {
    const size = entry.type === "file" && entry.size !== undefined ? ` (${entry.size} B)` : "";
    console.log(`  ${entry.type === "dir" ? "d" : "-"} ${entry.path}${size}`);
  }

  const readme = findReadme(tree.entries.filter((e) => e.type === "file").map((e) => e.path));
  console.log();

  if (!readme) {
    console.log("README: none found in the tree");
    return;
  }

  const file = await getFileContentWithSource(owner, repo, metadata.defaultBranch, readme);
  const { content } = file;

  // Regression guard: get_file_contents also emits a status line ("successfully
  // downloaded text file (SHA: …)"). Receiving only that means the body was lost.
  if (isDownloadStatusMessage(content)) {
    throw new Error(
      `${readme}: received only a download-status message, not the file contents: "${content.trim()}"`,
    );
  }

  const lines = content.split("\n");
  console.log(
    `${readme}: ${content.length} chars, first ${Math.min(README_LINES, lines.length)} of ` +
      `${lines.length} lines   [via ${file.source}]`,
  );
  for (const line of lines.slice(0, README_LINES)) console.log(`  ${line}`);
}

main()
  .catch((error: unknown) => {
    if (error instanceof GitHubMcpError) {
      console.error(`\n[${error.code}] ${error.message}`);
    } else if (error instanceof GitHubClientConfigError) {
      console.error(`\n${error.message}`);
    } else {
      console.error(`\n${error instanceof Error ? error.message : String(error)}`);
    }
    process.exitCode = 1;
  })
  .finally(() => closeClient());
