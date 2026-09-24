/**
 * Smoke test for the Claude client against the real API.
 *
 *   pnpm try scripts/try-claude.ts
 *
 * Needs ANTHROPIC_API_KEY. Costs a fraction of a cent. The README below is fake so
 * nothing about a real repository leaves the machine.
 *
 * Note on the cost line: the system prompt here is far below the model's minimum
 * cacheable prefix, so cache read tokens will read 0. That is expected at this size,
 * not a sign that caching is misconfigured.
 */

import { z } from "zod";
import { AiError, callStructured } from "@/server/ai/claude";
import { activeProfile, modelFor } from "@/server/ai/models";
import { formatUsd, usageLedger } from "@/server/ai/usage";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

if (!process.env.ANTHROPIC_API_KEY?.trim()) {
  console.error(
    "ANTHROPIC_API_KEY is not set.\n" +
      "Add it to .env.local (which is gitignored) as ANTHROPIC_API_KEY=... , " +
      "or export it in this shell, then run this script again.",
  );
  process.exit(1);
}

const OutputSchema = z.object({
  summary: z.string(),
  risks: z.array(z.string()),
});

const FAKE_README = `
# Paper Trail

A small Express service that stores expense receipts.

- POST /api/receipts uploads a receipt image to S3.
- GET /api/receipts/:id returns one receipt as JSON.
- Sessions are cookies signed with a secret from the environment.
- Receipts are stored in Postgres; the connection string comes from DATABASE_URL.
`;

const analysisId = "try-claude";

async function main(): Promise<void> {
  const profile = activeProfile();
  console.log(`profile: ${profile}`);
  console.log(`model:   ${modelFor("architecture", profile)}\n`);

  const { value, usage, attempts } = await callStructured({
    stage: "architecture",
    analysisId,
    system:
      "You summarise software projects for a security review. " +
      "Return only the JSON described by the schema.",
    user: `<repo_file path="README.md">\n${FAKE_README}\n</repo_file>`,
    schema: OutputSchema,
    jsonSchema: z.toJSONSchema(OutputSchema) as Record<string, unknown>,
    maxTokens: 1000,
  });

  console.log("summary:", value.summary);
  console.log("risks:");
  for (const risk of value.risks) console.log(`  - ${risk}`);

  const total = usageLedger.forAnalysis(analysisId);
  console.log(
    `\nattempts ${attempts} | requests ${usage.requests} | ` +
      `in ${usage.inputTokens} out ${usage.outputTokens} ` +
      `cache-read ${usage.cacheReadTokens} cache-write ${usage.cacheWriteTokens}`,
  );
  console.log(`cost: ${formatUsd(usage.costUsd)} (analysis total ${formatUsd(total.totalUsd)})`);
}

main().catch((error: unknown) => {
  // Never print the error object: its `cause` chain carries the API's response body
  // and headers, which can echo request content.
  if (error instanceof AiError) {
    console.error(`${error.name} [${error.code}]: ${error.message}`);
    for (const issue of error.issues) {
      console.error(`  - ${issue.path}: ${issue.message}`);
    }
  } else {
    console.error(error instanceof Error ? `${error.name}: ${error.message}` : "unknown error");
  }
  process.exitCode = 1;
});
