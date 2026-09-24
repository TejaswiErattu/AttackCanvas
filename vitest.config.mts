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
  },
});
