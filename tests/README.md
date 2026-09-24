# tests

Vitest unit tests for pure logic.

## `fixtures/canary-repo/`

A small Express application standing in for a hostile repository, used by
`security.test.ts` and `canary.live.test.ts`. It contains a genuinely unauthenticated
`POST /admin/users`, a password-reset route with no rate-limiting package declared, and
planted prompt injections in its README, its manifest description, a source comment and a
string literal — including a README claiming the API gateway handles authentication and
asking for missing checks not to be reported.

Load it with `loadCanaryRepo()` from `canaryRepo.ts`, never by reading the directory
directly: the loader re-paths each file to its repository-relative form. `isScannable()`
drops any path containing a `tests/` or `fixtures/` segment, so on-disk paths would remove
every source file and leave the assertions passing against an empty result.

`canary.live.test.ts` makes real paid calls and is skipped unless `ANTHROPIC_API_KEY` is
set. Run it deliberately:

    set -a && . ./.env.local && set +a && pnpm test canary
