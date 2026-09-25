import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Fixture repositories are sample code from an imaginary third party, not our source.
    // The canary repo is deliberately written the way the repositories we analyse are
    // written -- CommonJS requires, no auth, planted prompt injection -- and linting it to
    // this project's standards would mean changing the thing under test.
    "tests/fixtures/**",
    // Claude Code session worktrees: separate, possibly stale checkouts of this repo.
    ".claude/worktrees/**",
  ]),
]);

export default eslintConfig;
