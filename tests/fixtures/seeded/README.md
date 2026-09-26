# Seeded repositories

Three small, deliberately vulnerable apps for the seeded bench (`pnpm bench`,
`scripts/eval/bench.ts`, gated by `tests/bench.test.ts`). **Do not deploy or run them.** Every
credential in them is fake (`seeded-demo-…-not-a-secret`), and the external host names do not
belong to anyone.

| Repo | Stack | Files |
|---|---|---|
| `seeded-express` | Express 5, express-session in MongoDB (connect-mongo), helmet, cors, zod | 15 |
| `seeded-next` | Next.js 15 App Router API routes, JWT (jsonwebtoken), pg, bcryptjs, pino, @upstash/ratelimit, zod | 19 |
| `seeded-monorepo` | pnpm workspace: `packages/api` (Express 4, cookie-session, pg) and `packages/auth`, imported through its `src/index.ts` barrel | 22 |

The file counts include `expected.yaml`. They are read through `loadFixtureRepo(…, root:
"tests/fixtures/seeded")`, the same classification and size policy as a GitHub repository.
The bench drops `expected.yaml` before any detector runs, because its words (for example
"rate limit") would otherwise count as configuration.

They are excluded from `tsconfig.json`, since their imports resolve in their own projects, not
this one. ESLint already ignores `tests/fixtures/**`.

## Labels

Each repository has an `expected.yaml`:

```yaml
repo: seeded-express
issues:      # planted vulnerabilities, which should be found
  - id: x-authz-invoice
    class: Invoice read by id with no ownership check (IDOR)
    owasp: A01:2025
    file: src/routes/invoices.js
    line: 30
    gapKind: authz_missing                  # and/or
    ruleId: attackcanvas-command-injection  # a Semgrep rule id from src/server/mcp/semgrepRules.ts
controls:    # present-but-tricky controls, which must NOT produce a gap
  - id: x-ctl-admin-prefix
    gapKind: authz_missing
    file: src/routes/admin.js   # where a false gap of this kind would be reported
    how: …                      # where the control is and why it counts
    type: app-level middleware  # | framework default | barrel-imported guard | cross-package guard
    review: "1b"                # the entry in docs/gap-adversarial-review.md, when there is one
```

- Every planted item has a one-line `SEEDED:<id>` comment. In `package.json`, which has no
  comments, it is an npm-style `"//": "SEEDED:<id>"` key. For an issue, the marker sits on
  `line` or at most 5 lines above it. For a control, it sits where the control is
  implemented, sometimes in more than one file. The bench fails if an issue's marker is out
  of place, a control has no marker, or a marker names no label, so
  `grep -rn "SEEDED:" tests/fixtures/seeded` is a checkable listing.
- An issue's `file` and `line` are where the finding is reported. For a repository-wide absence
  (missing headers, rate limiting, CSRF, password hashing, logging), that is the detector's
  anchor: the web framework's line in `package.json` for headers, the first authentication
  route for rate limiting, the first state-changing route outside `/api` for CSRF, and the
  weak-hash line for password hashing.
- An issue with both `gapKind` and `ruleId` is one vulnerability that both sources can see.
  Either one matches it, and a second matching finding counts as a duplicate, not a false
  positive. An issue with only a `ruleId` is skipped, not missed, when Semgrep is not
  installed.
- A control is contradicted by a gap of its kind in its `file`, or by a repository-scoped gap
  of its kind anywhere.

## Planted issues

Every repository covers A01, A02, A04, A05 and A07. None is copied from NodeGoat.

| Repo | Id | OWASP | Found by |
|---|---|---|---|
| express | `x-authz-invoice` | A01 | authz_missing |
| express | `x-cors-reflect` | A02 | cors_permissive |
| express | `x-md5-password` | A04 | password_storage_weak, attackcanvas-weak-hash |
| express | `x-plain-webhook` | A04 | transport_insecure |
| express | `x-export-cmd` | A05 | input_validation_missing, attackcanvas-command-injection |
| express | `x-login-ratelimit` | A07 | rate_limit_missing |
| next | `n-export-unauth` | A01 | authn_missing |
| next | `n-cors-wildcard` | A02 | cors_permissive |
| next | `n-jwt-none` | A04 | attackcanvas-jwt-verify-none |
| next | `n-sql-concat` | A05 | input_validation_missing, attackcanvas-sql-string-concat |
| next | `n-token-storage` | A07 | client_secret_storage |
| next | `n-jwt-literal` | A07 | attackcanvas-hardcoded-jwt-secret |
| monorepo | `m-authz-project` | A01 | authz_missing |
| monorepo | `m-csrf-form` | A01 | csrf_missing |
| monorepo | `m-no-headers` | A02 | security_headers_missing |
| monorepo | `m-tls-off` | A04 | transport_insecure |
| monorepo | `m-eval-filter` | A05 | input_validation_missing, attackcanvas-eval-user-input |
| monorepo | `m-hardcoded-apikey` | A07 | attackcanvas-hardcoded-credentials |

## Controls

There are 17 controls. `seeded-express` and `seeded-monorepo` cover all four types.
`seeded-next` has no cross-package guard: it is one package, and its guards come from its own
`lib/` through barrels.

| Repo | Id | Kind | Type | Review |
|---|---|---|---|---|
| express | `x-ctl-admin-prefix` | authz_missing | app-level middleware | 1b |
| express | `x-ctl-express5-async` | error_handling_gap | framework default | |
| express | `x-ctl-barrel-login` | authn_missing | barrel-imported guard | 2b |
| express | `x-ctl-helmet-app` | security_headers_missing | app-level middleware | |
| express | `x-ctl-cross-pkg-authz` | authz_missing | cross-package guard | 1d |
| next | `n-ctl-with-auth-barrel` | authn_missing | barrel-imported guard | |
| next | `n-ctl-with-role` | authz_missing | barrel-imported guard | 1c |
| next | `n-ctl-middleware-headers` | security_headers_missing | app-level middleware | 5a |
| next | `n-ctl-next-errors` | error_handling_gap | framework default | |
| next | `n-ctl-zod-barrel` | input_validation_missing | barrel-imported guard | 6a |
| next | `n-ctl-login-limiter` | rate_limit_missing | barrel-imported guard | |
| monorepo | `m-ctl-barrel-guard` | authn_missing | cross-package guard | 2b |
| monorepo | `m-ctl-cross-pkg-owner` | authz_missing | cross-package guard | 1d |
| monorepo | `m-ctl-cross-pkg-kdf` | password_storage_weak | cross-package guard | 8d |
| monorepo | `m-ctl-error-mw` | error_handling_gap | app-level middleware | 10a |
| monorepo | `m-ctl-limiter-pkg` | rate_limit_missing | cross-package guard | 3e |
| monorepo | `m-ctl-request-logger` | logging_missing | app-level middleware | 9b |

## Caveat

The apps and labels were written by someone who had read the detector source. The planted
issues are therefore shapes the detectors are known to handle, so recall here is an upper
bound for code written this way, not an estimate for arbitrary code. The controls are the
more informative half: they follow the review's sketches inside realistic apps, and were not
adjusted after the first run.
