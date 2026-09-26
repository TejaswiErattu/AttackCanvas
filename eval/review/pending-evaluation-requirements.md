# Pending evaluation requirements (NodeGoat)

Status: **R1 implemented (2026-09-25, branch `eval-gap-sheet`); R2 still pending.** Recorded
2026-09-24 from the human labeler's decisions. `recalledIds` in `scripts/eval/lib.ts` builds
recall from supported rows only, and the per-class table reads the same set. `score.ts` still
reports a single all-result recall, so do not use it for the final NodeGoat report's visible
recall until R2 is done.

R1 reproduces every reviewed all-result recall from the saved label sheets: after-fix 12/19,
7f7211d 16/19, 7a0fb27 13/19, f64cfa8 14/19 and a3118b6 17/19. The previous any-row rule gave
15, 19, 14, 17 and 18. For a3118b6, the difference is exactly `NG-VULNERABLE-DEPS`, matched
only by threat-70 (`supported = n`). `tests/evalGaps.test.ts` pins that case.

## Metric decisions

### R1. Recall requires a supported match
An expected item counts as recalled only when **at least one** label row lists it in
`matchesExpected` **and** has `supported = y`.

- A row with `matchesExpected` filled and `supported = n` (e.g. after-fix threat-63,
  `NG-VULNERABLE-DEPS`, `n`) does **not** make that item recalled on its own. It still counts
  toward the unsupported rate.
- Implemented: `computeRepoMetrics` now builds `matchedSet` with `recalledIds`, which keeps
  only rows with `supported = y`.

### R2. Two recall figures
Report both, per repo and pooled:

- **All-result recall**: R1 applied to every labelled row.
- **Dashboard-visible recall**: R1 applied only to rows with `confidence >= 0.25` (the
  dashboard cutoff, `HIDE_BELOW` in `src/server/scoring`).
- Current code differs: nothing in `parseLabels`, `computeRepoMetrics` or `score.ts` reads
  the `confidence` column; there is a single recall over all rows.

### R3. Keep recorded labels as given
Threat-63's recorded labels stay as they are (`NG-VULNERABLE-DEPS`, `n`, `3/3`, with its note).
The metric change, not a relabel, determines how it affects recall.

## Implementation notes for later (not done)

- Parse `confidence` in `parseLabels` (already a column of every sheet) and carry it on
  `LabeledThreat`.
- `computeRepoMetrics`: build the matched set from rows with `supported === true`; compute it a
  second time over rows with `confidence >= 0.25`.
- `renderEvaluationReport`: show both recalls; update the Recall definition text, which today
  says "matched by at least one generated threat" without requiring support.
- Tests: a supported=n-only match is not recalled; a hidden-only supported match counts for
  all-result recall but not visible recall; the 0.25 boundary is inclusive.
- `parseLabels` still requires every row to be labelled, so scoring waits until all rows are
  done.

## Settled labelling rules (for consistency across the remaining rows)

- **Answer key:** all 19 draft items kept; `NG-INSECURE-SESSION-COOKIE` kept bundled;
  `NG-VULNERABLE-DEPS` requires marked 0.3.5 with GHSA-vfvf-mqq8-rwqc or GHSA-7px7-7xjx-hxm8;
  `NG-PLAINTEXT-HTTP` counts only when the finding acknowledges that exploitability depends on
  deployment. The key itself remains a draft, not human-verified.
- **Hidden threats** (confidence < 0.25) are included in the label review.
- **evidenceCorrect:** an accurate route citation that locates the relevant route counts as
  correct. A gap that only shows "no validation library imported" does not count as proof of a
  specific missing control (e.g. an allow-list). A dependency advisory counts only if its
  prerequisites hold in NodeGoat and it supports the threat's specific scenario.

## Progress at the time of writing

- After-fix sheet: 11 of 109 rows labelled (all dashboard-visible threats). threat-34's
  `evidenceCorrect` was revised by the labeler from 1/2 to 2/2 under the route rule.
- Before-fix sheet: not yet labelled (scored columns blank; `notes` hold Claude-drafted
  `SUGGESTED:` text, not human labels).

## Review note: session cookie HttpOnly (for assessing cookie-theft claims)
The answer key's NG-INSECURE-SESSION-COOKIE description says the session cookie has "no
httpOnly". In the pinned code (server.js:77-100) no `cookie` option is passed, but
express-session defaults to `httpOnly: true`, so the cookie IS HttpOnly. Only `secure`
and `maxAge` are missing. Script-based cookie theft (`document.cookie`) is therefore not
possible; an XSS finding is supported only for same-origin actions as the victim. Apply this
when labelling cookie-theft claims (after-fix t84, t88, t98; t60 is already labelled n).
The answer key is left unchanged.

## Proposed fix for later (not implemented): suppressed header and CSRF detectors
Recorded 2026-09-25 during labelling of the nodegoat-7f7211d run. Do not change code during
labelling.

- `security_headers_missing` (src/server/detect/gaps.ts, check 5) returns early when `helmet`
  is merely declared in package.json (`hasAny(ctx.deps, HEADER_DEPS)`). NodeGoat declares
  helmet but calls it only in commented-out code, so the detector never fires.
  MISSING-SECURITY-HEADERS was then covered only when the architecture model happened to
  write a headers unknown: it did in the after-fix run (t13) and did not in the 7f7211d run,
  which has no headers threat.
- `csrf_missing` (check 4) has the same pattern with `csurf` (`hasAny(ctx.deps, CSRF_DEPS)`).
- Proposed: require an uncommented call (`helmet(`, `csrf(`/`csurf(`) rather than a declared
  dependency. Check that `anySource(/csrf/i)` does not match commented code or template
  `_csrf` fields. Add positive and negative tests, including declared-but-unused.

### Update: active-protection fix implemented in 7a0fb27
`security_headers_missing` and `csrf_missing` now require live use, not a declared
dependency (`usesPackage`, `usesPackageFeature` for lusca, `checksCsrfToken` in
src/server/detect/gaps.ts). Token producers (`req.csrfToken()`, template `_csrf` fields)
never count as validation. Known limitations, accepted for now:

- **Route coverage is not checked.** Any live use of a protection package (for example one
  `csrf()` on one route, or a reference inside a function that never runs) suppresses the
  gap for every route.
- **Hand-rolled CSRF checks are pattern-matched.** A loaded CSRF-named function counts if its
  body reads a request field and contains any comparison or verify call. Whether that is
  the token check, and whether failure rejects the request, is not verified.
- **Unloaded definitions count as protection (deliberately conservative).** A CSRF-named
  middleware whose definition is not in loaded source (imported from an unloaded module, or
  a method such as `tokens.verifyCsrf()`) suppresses the gap, because its behaviour cannot
  be established. A silent `csrf_missing` therefore does not prove a check exists.
- **Regex parsing, not an AST.** Definitions are found by name (first match wins; class
  methods and re-exports are not followed). Unusual import syntax can be missed. Template
  literals are masked whole, so a `${helmet()}` inside one is missed; that errs toward
  reporting a gap.
- **No source loaded:** a declared header package with no loaded source stays silent
  (unknown, not missing).

## Erratum (2026-09-25): after-fix threat-13 clickjacking label
- **Original label:** threat-13 (Missing security response headers ... allow clickjacking),
  `NG-MISSING-SECURITY-HEADERS`, supported **y**, evidence 0/0. It was the after-fix run's
  only supported match for NG-MISSING-SECURITY-HEADERS.
- **Corrected label:** supported **n** (match and evidence unchanged).
- **Reason:** NodeGoat's session cookie (express-session 1.15.6) is `connect.sid=...;
  Path=/; HttpOnly` with no SameSite attribute. Chrome treats it as Lax, Firefox Total Cookie
  Protection partitions third-party cookies, and Safari blocks them, so a cross-site iframe
  of NodeGoat is logged out and no authenticated form can be clickjacked. The row's
  script-src half assumes an injection it never establishes. The same rule was applied to
  t2, t12, t75 and t78 of the 7a0fb27 run.
- **Where it is applied:** the working copy `eval/labels/nodegoat-after-fix.csv` only
  (sha256 22654311b17163600f91f8e27b4d0d676fe4544da679b0073a9d9034fd79af6f), with an ERRATUM note on the row. The read-only baseline
  `eval/baselines/nodegoat-after-fix/labels.csv` and its MANIFEST are untouched and still
  hold the original label (sha256 3fd29781bf9f7bd4bcd3bbc2546ee8009294b1cd99ea27b13241065df5ec87c9).

| after-fix metric | original (baseline file) | corrected (erratum, working copy) |
|---|---|---|
| All-result recall | 13/19 | **12/19** (loses NG-MISSING-SECURITY-HEADERS) |
| Visible recall | 4/19 | 4/19 |
| Unsupported | 22/109 | 23/109 |
| Evidence accuracy | 87/111 | 87/111 |

Reports that quote the after-fix run should say which figure they use. The originally
reported 13/19 was computed from the baseline labels before this correction.
