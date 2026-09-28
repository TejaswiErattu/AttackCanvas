# Known limitations

Limits that are understood, deliberate, and not scheduled for a code change. Each entry
says what is missed and why the detector accepts it. Source: the 2026-09-25 adversarial
review (`docs/gap-adversarial-review.md`) and security review (`docs/bug-bash.md`).

## Gap detector

The detectors are regex over comment- and string-masked source. They cannot follow an
identifier to its definition, so a control that lives behind a name that does not describe
it, or in a file the loader did not fetch, is invisible. The route-scoped kinds carry low
certainty for exactly this reason.

- **authz_missing (1d).** An authorization decision made inside imported middleware whose
  name does not say so (`guard`, `check`) is invisible. Certainty stays 0.7 outside admin
  paths for that reason.
- **authn_missing (2e).** The app-level `.use(guard)` scan is order-insensitive and
  repo-wide, so a guard registered after some routes is over-credited (a missed gap, not a
  false one). When the file that registers the guard was not loaded (300-file cap), every
  mutating route is reported at 0.9.
- **rate_limit_missing (3e).** Dependencies are the union of every loaded `package.json`.
  A limiter declared in a workspace manifest that fell past the loader's caps is not seen.
  `LoadedRepo.truncated` exists in the loader and could be threaded into the detector later.
- **input_validation_missing (6e).** Firestore rules that allow writes without reading
  `request.resource` are reported at 0.8; validation may live in a Cloud Function trigger
  the repository does not show.
- **password_storage_weak (8d).** A KDF wrapped in a module that was not loaded (or a
  workspace package whose manifest was not loaded) is not seen.
- **logging_missing (9d).** Platform request logs (Vercel, Render, CloudWatch) leave no
  trace in the repository and are not security logging of the authentication event itself.
- **error_handling_gap (10d).** An error handler registered in a file the loader did not
  fetch is not seen; the kind is already at 0.5 for that reason.
- **cors_permissive (11d).** The wildcard-header scan keeps string literals on purpose, so
  `res.setHeader("Access-Control-Allow-Origin", "*")` is caught. A string that merely
  mentions the header (an error message, a fixture list, a `.d.ts`) is reported too.
- **supply_chain_integrity (12b).** A lockfile can be in the repository and absent from the
  analysis: `yarn.lock` and `pnpm-lock.yaml` over 200 KB are ignored at load (only
  `package-lock.json` has the 1 MiB exemption), and any file can fall past the 300-file
  cap. The missing-lockfile gap is held at 0.35 for that reason.
- **client_secret_storage (13b, 13c).** Only `localStorage` and `sessionStorage` writes
  count. React Native `AsyncStorage` and encrypted wrappers (`secure-ls`, `secureStorage`)
  are out of scope. Writes in test, mock and storybook files are filtered by the
  source-file rule (`isScannable`), which is what keeps fixtures from reporting.
- **Seeded bench (2026-09-25).** Two results from `pnpm bench` (`eval/bench/report.md`):
  - *authz_missing, cross-package guard, package loaded.* `requireAuth, guard` from a loaded
    workspace package (`@acme/auth`) is still reported at 0.7. Role and ownership checks
    are read only from the route's own text and middleware names, never from an imported
    definition. So 1d applies whether or not the package was loaded.
  - *authz_missing, fragile pass.* A route whose last middleware is named `can…`
    (`requireLogin, canReadReport`) is credited with a "permission call". This only happens
    because the joined middleware names and the handler text put `canReadReport` next to
    the handler's `(`. Reorder the middleware, or name it `ownsReport`, and the same route
    is reported.
- **General.** Every "absent" finding is bounded by what was loaded. A repository over the
  300-file or 2 MiB caps can have its control in a file that was never fetched.

## Findings across runs

The dashboard compares runs in the browser (`src/client/drift.ts`); nothing checks the code.

- **"Not found this run" is not "fixed".** A model run can miss a threat an earlier run
  reported. The drift panel counts those as "not found this run", never "resolved", and
  says how many are not marked Fixed or False positive.
- **Run-to-run variation.** The threats themselves come from a model, so two runs of an
  unchanged repository can differ. Listing and counting every scored threat, including those
  below 25% confidence, keeps the dashboard from swinging between "nothing" and "many"
  because of the cutoff, but it does not remove the model's own variation.
- **Only one run back.** The comparison is with the previous run alone.
- **Identity is by name.** A threat is matched across runs by normalised title, component
  names and OWASP codes. A reworded title or a renamed component reads as a different
  threat, so its status does not follow and it shows as new.
- **Status migration guesses the run.** Statuses saved by per-run number before they were
  keyed by threat identity are converted once, against the last run stored in this
  browser. If that is not the run they were set on, some are dropped or land on another
  threat.
- **Not-closed count covers confident threats only.** A threat that was already below 25% in
  the last run and is gone now counts as "not found" but not in "not marked Fixed".

## Security review

Findings rated Medium or Low in the 2026-09-25 review that were not fixed, with the reason.

- **X-Forwarded-For trust** (`src/server/http/rateLimit.ts`). The rightmost hop is used,
  which is correct behind a proxy that appends (Render does). A `next start` exposed
  directly lets a client choose its own rate-limit bucket. Deploy behind a proxy.
- **Full-body JSON parse before validation** (`POST /api/analyze`, `POST .../answers`).
  App Router handlers have no default body limit. Mitigated by the per-IP rate limit; a
  content-length check is a five-minute follow-up.
- **Per-resource MCP size cap** (`src/server/mcp/base.ts` `extractResources`). Each
  resource block is capped at 1 MiB; the total across blocks is not. The GitHub server
  returns one resource per file, so this needs a hostile server to matter.
- **Tree paths not validated** (`src/server/mcp/githubClient.ts` `normalizeEntry`). Git
  forbids `..` and absolute components, so a traversal path needs a compromised server
  response. Paths are forwarded to the Semgrep MCP server as `code_files[].path`.
- **Opaque bearer tokens** (`src/server/security/redactor.ts`). A token in a header
  literal with no credential keyword in the key and no vendor shape is not redacted unless
  it is high-entropy and assigned with `=`.
- **Committed credentials are redacted but not reported.** `toEvidence` in the redactor
  has no caller, so a hardcoded key produces no evidence or threat. Rule 3 holds (it never
  reaches a model); surfacing it is a product follow-up.
- **`escapeAttribute` leaves `>` unescaped** in `<repo_file path>`. A path containing `>`
  renders a malformed-looking tag; it cannot open or close a block.
- **`.git` suffix stripping** in `urlParser` applies to the whole path, so a `/tree/` ref
  ending in `.git` loses that suffix. Cosmetic.
