import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    // `.tsx` is matched as well so the dashboard component tests actually run; without it
    // they would be collected by nothing and `pnpm test` would pass on files it never
    // executed. The environment stays per-file (`// @vitest-environment jsdom`), so the
    // pure Node tests keep running in Node.
    include: ["tests/**/*.test.{ts,tsx}"],
    // Read only by `pnpm test:coverage` (vitest run --coverage); plain `pnpm test` skips it.
    // The text report prints one row per directory, which docs/testing.md quotes.
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      // skipFull off: a directory at 100% (src/server/scoring) must still print its row.
      reporter: [["text", { skipFull: false }], "text-summary", "json-summary"],
      reportsDirectory: "coverage",
    },
  },
});
