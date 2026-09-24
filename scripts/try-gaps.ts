/**
 * Smoke test: run the control gap detector and print what it found.
 *
 *   pnpm try scripts/try-gaps.ts                      the in-memory sample repo
 *   pnpm try scripts/try-gaps.ts expressjs/express    a real repository
 *
 * Prints one row per gap: kind, file:line, certainty and the missing control. With no
 * argument it needs neither Docker nor a token. With one, it loads through the GitHub
 * MCP client, so it needs GITHUB_PERSONAL_ACCESS_TOKEN (environment or .env.local) and
 * Docker, exactly like try-detect.ts.
 *
 * Exits non-zero if any gap summary would fail the secret sweep, which is the rule-3
 * check: a gap states an absence and must never quote repository content.
 */
import { runDetectors } from "@/server/detect";
import type { DetectorInput } from "@/server/detect";
import { assertNoSecrets } from "@/server/security/redactor";
import { SAMPLE_REPO } from "../tests/detectSamples";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

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

async function loadFiles(
  target: string | undefined,
): Promise<{ label: string; files: DetectorInput[] }> {
  if (!target) return { label: "sample repo", files: SAMPLE_REPO };

  const { owner, repo } = parseTarget(target);
  console.log(`loading ${owner}/${repo} …`);

  // Imported here so the no-argument path never touches the MCP client.
  const { loadRepository } = await import("@/server/ingest/loader");
  const loaded = await loadRepository(owner, repo);
  return { label: `${owner}/${repo}`, files: loaded.files };
}

function row(cells: string[], widths: number[]): string {
  return cells.map((cell, index) => cell.padEnd(widths[index])).join("  ");
}

async function main(): Promise<void> {
  const { label, files } = await loadFiles(process.argv[2]);

  const started = Date.now();
  const { gaps, evidence } = runDetectors(files);
  const seconds = ((Date.now() - started) / 1000).toFixed(2);

  console.log(
    `${label}: ${files.length} files, ${gaps.length} gaps in ${seconds}s\n`,
  );

  const header = ["kind", "file:line", "certainty", "control"];
  const rows = gaps.map((gap) => [
    gap.kind,
    `${gap.file}:${gap.line}`,
    gap.certainty.toFixed(2),
    gap.control,
  ]);
  const widths = header.map((title, index) =>
    Math.max(title.length, ...rows.map((cells) => cells[index].length)),
  );

  console.log(row(header, widths));
  console.log(
    row(
      widths.map((width) => "-".repeat(width)),
      widths,
    ),
  );
  for (const cells of rows) console.log(row(cells, widths));

  const byKind = new Map<string, number>();
  for (const gap of gaps) byKind.set(gap.kind, (byKind.get(gap.kind) ?? 0) + 1);
  console.log(
    `\nby kind: ${[...byKind].map(([kind, count]) => `${kind} ${count}`).join(", ") || "none"}`,
  );

  for (const item of evidence.filter((e) => e.ruleId?.startsWith("gap:"))) {
    try {
      assertNoSecrets(item.summary);
    } catch {
      console.error(`SECRET-SHAPED SUMMARY in ${item.id}`);
      process.exitCode = 1;
    }
  }
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  })
  .finally(async () => {
    // Only a live load opens the MCP client; the sample path never imports it.
    if (process.argv[2]) {
      const { closeClient } = await import("@/server/mcp/githubClient");
      await closeClient();
    }
  });
