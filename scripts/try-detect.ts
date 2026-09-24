/**
 * Smoke test: load a real repository and run the deterministic detectors over it.
 *
 *   pnpm try scripts/try-detect.ts expressjs/express
 *   pnpm try scripts/try-detect.ts https://github.com/vercel/next.js
 *
 * Prints a count per fact type and a sample of each, so a regression in the parsing
 * shows up as an empty or absurd count against a repository you know.
 *
 * Needs GITHUB_PERSONAL_ACCESS_TOKEN (environment or .env.local) and Docker, because
 * it loads through the GitHub MCP client.
 */
import { closeClient } from "@/server/mcp/githubClient";
import { loadRepository } from "@/server/ingest/loader";
import { IngestError } from "@/server/ingest/loader";
import { frameworkNames, runDetectors } from "@/server/detect";
import { assertNoSecrets } from "@/server/security/redactor";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

const SAMPLE = 8;

/** Accepts "owner/repo" or a github.com URL. */
function parseTarget(input: string): { owner: string; repo: string } {
  const cleaned = input.trim().replace(/\.git$/, "");
  const match =
    /^https?:\/\/github\.com\/([^/]+)\/([^/?#]+)/.exec(cleaned) ??
    /^([^/\s]+)\/([^/\s]+)$/.exec(cleaned);

  if (!match) {
    throw new Error(
      `could not read "${input}" as owner/repo or a github.com URL`,
    );
  }
  return { owner: match[1], repo: match[2] };
}

function section(title: string, rows: string[]): void {
  console.log(`\n${title} (${rows.length})`);
  for (const row of rows.slice(0, SAMPLE)) console.log(`  ${row}`);
  if (rows.length > SAMPLE) console.log(`  … and ${rows.length - SAMPLE} more`);
}

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error("usage: pnpm try scripts/try-detect.ts <owner/repo>");
    process.exitCode = 1;
    return;
  }

  const { owner, repo } = parseTarget(target);
  console.log(`loading ${owner}/${repo} …`);

  const loaded = await loadRepository(owner, repo);
  console.log(
    `${loaded.files.length} files, ref ${loaded.summary.ref}, truncated=${loaded.truncated}`,
  );

  const started = Date.now();
  const result = runDetectors(loaded.files);
  const seconds = ((Date.now() - started) / 1000).toFixed(2);

  console.log(`\ndetectors ran in ${seconds}s`);

  section(
    "frameworks",
    result.frameworks.map(
      (f) => `${f.category.padEnd(20)} ${f.name}@${f.version}`,
    ),
  );
  section(
    "routes",
    result.routes.map(
      (r) =>
        `${r.id.padEnd(9)} ${r.method.padEnd(7)} ${r.normalizedPath}  (${r.file}:${r.line})`,
    ),
  );

  const byStatus = new Map<string, number>();
  for (const fact of result.auth) {
    byStatus.set(fact.status, (byStatus.get(fact.status) ?? 0) + 1);
  }
  section(
    "auth",
    [...byStatus].map(([status, count]) => `${status.padEnd(16)} ${count}`),
  );

  const admin = result.auth.filter(
    (a) => a.adminPath && a.status !== "authenticated",
  );
  if (admin.length > 0) {
    section(
      "unauthenticated admin paths",
      admin.map((a) => a.routeId),
    );
  }

  section(
    "datastores",
    result.datastores.map(
      (d) => `${d.kind.padEnd(10)} ${d.name} (${d.origin})`,
    ),
  );
  section(
    "env names",
    result.envNames.map((e) => `${e.name} (${e.origin})`),
  );
  section(
    "deployment",
    result.deployment.map(
      (d) =>
        `${d.kind.padEnd(12)} ${d.name}${d.ports.length ? ` ports ${d.ports}` : ""}`,
    ),
  );

  section(
    "token checks",
    result.tokens.map(
      (t) =>
        `${t.kind.padEnd(20)} ${t.via}${t.algorithmPinned ? " (alg pinned)" : ""}  (${t.file}:${t.line})`,
    ),
  );

  console.log(`\nevidence: ${result.evidence.length} items`);
  for (const evidence of result.evidence.slice(0, 4)) {
    console.log(`  ${evidence.id}  ${evidence.summary}`);
  }

  console.log(
    `\nframeworkNames: ${frameworkNames(result).join(", ") || "(none)"}`,
  );

  // The whole point of the "never emit values" rule: this must hold on a real
  // repository, not only on the samples.
  const leaves: string[] = [];
  const walk = (value: unknown): void => {
    if (typeof value === "string") leaves.push(value);
    else if (Array.isArray(value)) value.forEach(walk);
    else if (value && typeof value === "object")
      Object.values(value).forEach(walk);
  };
  walk(result);

  try {
    assertNoSecrets(leaves.join("\n"));
    console.log("\nassertNoSecrets: clean");
  } catch (error) {
    console.error(`\nassertNoSecrets FAILED: ${(error as Error).message}`);
    process.exitCode = 1;
  }
}

main()
  .catch((error: unknown) => {
    if (error instanceof IngestError) {
      console.error(`[${error.code}] ${error.message}`);
    } else {
      console.error(error instanceof Error ? error.message : String(error));
    }
    process.exitCode = 1;
  })
  .finally(() => closeClient());
