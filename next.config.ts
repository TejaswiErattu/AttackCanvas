import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /**
   * Stop Next from appending its `<!-- BEGIN:nextjs-agent-rules -->` block to
   * CLAUDE.md on every dev/typegen run.
   *
   * CLAUDE.md is this project's own instruction file (CLAUDE.md rule set, and the
   * contract every prompt is written against). Tooling rewriting it means content
   * nobody here authored lands in the file that governs how this repo is built, and
   * reappears as an uncommitted change after every `pnpm typecheck`.
   *
   * `agentRules` is a documented top-level option in the installed Next (16.3.5):
   * `config-shared.d.ts` types it `agentRules?: boolean` with `@default true` and
   * "Set to `false` to disable this behavior", and `server/lib/start-server.ts` gates
   * generation on `agentRules !== false` -- its own log line tells you to set exactly
   * this. It is the only thing the flag gates: dev, typegen, API routes, rendering and
   * the dashboard are all untouched by it (verified by enumerating every call site).
   */
  agentRules: false,
};

export default nextConfig;
