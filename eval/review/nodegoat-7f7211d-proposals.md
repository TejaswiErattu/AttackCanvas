# NodeGoat at c8dd73f: proposed mappings to the 19 expected items

> **AI PROPOSALS, NOT LABELS.** Drafted by Claude from `eval/results/nodegoat-7f7211d.json`
> (snapshot: `eval/baselines/nodegoat-7f7211d/`). No label sheet exists yet for this run, and
> no old labels were copied: every proposal below was checked against the new threat's own
> scenario and citations and the NodeGoat source at c5cb68a. Rules applied are the settled
> ones in `pending-evaluation-requirements.md`, including the HttpOnly review note.

- Run: AttackCanvas `c8dd73f`, demo profile, level 2, questions skipped, 2,400 s phase
  timeout. 118 threats, 16 visible (confidence >= 0.25), 39 evidence items.
- All five new Semgrep rules fired: `semgrep-1` allocations-dao.js:77 ($where),
  `semgrep-2` user-dao.js:61 (plaintext compare), `semgrep-6` index.js:72 (open redirect),
  `semgrep-7` profile.js:59 (ReDoS), `semgrep-8` research.js:16 (SSRF).

## Per expected item

"sup" and "evid" are proposals. Old = best supported row in the labelled after-fix run.

| expected item | best proposed row | conf | vis | match / sup / evid | old best | note |
|---|---|---|---|---|---|---|
| SSJS-EVAL | t30 (also t36) | 0.70 | yes | match / y / 4/4 | 0.70 visible | eval() on preTax/afterTax/roth; route + 3 Semgrep hits. |
| NOSQL-WHERE | t1 (also t8, t4, t5) | 0.70 | yes | match / y / 2/2 | 0.20 hidden | threshold interpolated into $where (allocations-dao.js:77-78). **Newly visible** via semgrep-1. |
| LOG-INJECTION | t100 | 0.05 | no | match / y / 3/3 | none | Scenario names session.js:64 logging the raw userName and "newline-laden usernames to forge surrounding log lines". Main title is audit; **review** whether the secondary claim is enough to match. |
| PLAINTEXT-PASSWORDS | t97 (also t117, t68) | 0.70 | yes | match / y / 3/3 | 0.35 visible | semgrep-2 at user-dao.js:61 plus login/signup routes. |
| USER-ENUMERATION | t96 (also t115) | 0.20 | no | match / y / 1/1 | none | "Invalid username" vs "Invalid password" (session.js:60-61, 82-98); identical-error fix commented out. **New.** |
| WEAK-PASSWORD-POLICY | t99 (also t116) | 0.20 | no | match / y / 2/2 | none | `PASS_RE = /^.{1,20}$/` (session.js:144); stronger regex commented out. t116 is 1/1. **New.** |
| SESSION-FIXATION | t101 (also t98) | 0.20 | no | match / y / 1/1 | only n (t90) | No `req.session.regenerate` at login (session.js:116). Neither row repeats the old "reused indefinitely" overclaim. **New supported.** |
| INSECURE-SESSION-COOKIE | t109 (also t113) | 0.20 | no | match (with PLAINTEXT-HTTP) / y / 1/1 | 0.00 hidden | Missing `secure` flag with plain HTTP, deployment dependence stated; same bundling as old t9. t72 (hard-coded secret, forged admin cookie) proposed **n**, as old t92. |
| XSS-AUTOESCAPE-OFF | t16, t111 | 0.05 / 0.20 | no | match / **n** / 1/1 | none | **Decision needed**, see below. The mechanism is right in both; the only stated impact is `document.cookie` theft, which fails under HttpOnly. t53 (`<script>` inside `value="..."`, inert) and t75/t63 (memo `<script>`/`<img>`, escaped by marked sanitize) are **n**. |
| IDOR-ALLOCATIONS | t3 (also t6, t77, t102, t112, t26) | 0.51 | yes | match / y / 2/2 | 0.66 visible | userId from the URL, no ownership check. |
| MISSING-SECURITY-HEADERS | t75 only | 0.00 | no | match / **n** / 0/0 | 0.00 hidden (t13, y) | **Regression:** no threat is about missing headers. t75 mentions the commented-out helmet CSP, but its memo `<script>` payload is escaped by marked sanitize. |
| PLAINTEXT-HTTP | t49, t113, t109 (and others) | 0.20 | no | match / y / 2/2 (t49) | 0.05 hidden | Assumptions state no TLS terminator. |
| UNENCRYPTED-PII | t81 (also t69) | 0.00 | no | match / y / 0/0 | 0.20 hidden | profile-dao.js encryption helpers commented out; fields stored raw. No citations, so lower confidence than before. |
| MISSING-FUNCTION-AUTHZ | t19 (also t20, t17) | 0.20 | no | match / y / 1/1 | 0.20 hidden | /benefits GET/POST behind isLoggedIn only (index.js:55-56). |
| CSRF | t71, t83, t61, t29, t21, t35 | 0.05 | no | match / y / 0/0 to 1/1 | 0.05 hidden | csurf and the token commented out (server.js:104-113). Relies on the no-SameSite assumption, as before. |
| OPEN-REDIRECT | t55 (also t57) | 0.70 | yes | match / y / 2/2 | 0.61 visible | semgrep-6 at index.js:72. t56/t58 (`javascript:` or CRLF in Location) proposed **n**: browsers do not follow `javascript:` Location and Node rejects CR/LF in headers. |
| SSRF-RESEARCH | t88 (also t104, t92) | 0.70 | yes | match / y / 2/2 | 0.20 hidden | semgrep-8 at research.js:16. **Newly visible.** t93 (steals the session cookie) proposed **n** under HttpOnly. |
| REDOS-ROUTING | t82 (also t85) | 0.70 | yes | match / y / 2/2 | 0.20 hidden | semgrep-7 at profile.js:59. **Newly visible.** |
| VULNERABLE-DEPS | t65 | 0.75 | yes | match / **n** / 4/4 | only n (t63) | Names marked 0.3.5 with both GHSAs, but says the script runs automatically for "every user who later loads GET /memos" and takes a "non-httpOnly session cookie". Both bypasses need a click on a crafted link, and the cookie is HttpOnly. Same overclaims as old t63. |

## Recall if these proposals were approved

| | all results | visible |
|---|---|---|
| old after-fix run (final labels) | 13/19 | 4/19 |
| new run, as proposed | **16/19** | **7/19** |

- Newly visible: NOSQL-WHERE, SSRF-RESEARCH, REDOS-ROUTING (all via the new Semgrep rules).
- Newly recalled (hidden): LOG-INJECTION, USER-ENUMERATION, WEAK-PASSWORD-POLICY,
  SESSION-FIXATION.
- Lost: MISSING-SECURITY-HEADERS (no headers threat this run).
- Not recalled: XSS-AUTOESCAPE-OFF, MISSING-SECURITY-HEADERS, VULNERABLE-DEPS.

## Decisions for the labeler

1. **XSS impact under HttpOnly (t16, t111).**
   - t16: `benefits.html:51` prints `{{user.firstName}}` in a `<td>` with autoescape off, and
     firstName is saved raw, so a script tag runs for anyone who opens /benefits.
   - t111: uses a quote-breaking `"><script>` payload in lastName, but overclaims "every
     authenticated page".
   - Under the t88/t98 rule both are **n**, because the only impact stated is reading
     `document.cookie`. Keeping that rule leaves recall at 16/19; relaxing it for t16 alone
     would make it 17/19.
2. **t100 match to LOG-INJECTION.** Log forging is a secondary claim in an audit-titled
   threat. If it does not count, LOG-INJECTION is not recalled (15/19).
3. **t73 and t78 (express, body-parser and marked advisories).** Proposed without a match.
   - t73: the express open-redirect CVE concerns allow-list bypass, and NodeGoat has no
     allow-list.
   - t78: the body-parser CVE needs `extended: true`, and NodeGoat uses `false`.
   - Whether these rows are supported needs a per-advisory decision.

Rows not named above are not yet proposed. A full label sheet for all 118 threats needs your go-ahead.

## Disputed rows: source-checked proposals (not applied)

Blank sheet: `eval/labels/nodegoat-7f7211d.csv` (118 rows, same columns as the after-fix
sheet, 16 rows at confidence >= 0.25). Nothing filled.

| row | proposed match | sup | evid | reason |
|---|---|---|---|---|
| t100 | NG-LOG-INJECTION | y | 3/3 | session.js:64 `console.log("... invalid user: ", userName)` logs the raw body value; the CR/LF-encoding fix is commented out at 66-79. The scenario states the forging ("newline-laden usernames to forge surrounding log lines"). Successful login, signup and logout are also unlogged. POST /login, POST /signup and GET /logout are each named in the claim. |
| t16 | NG-XSS-AUTOESCAPE-OFF | n | 1/1 | Mechanism real: benefits.html:51 prints `{{user.firstName}}` in a `<td>` with autoescape off (server.js:135-142), and profile-dao stores firstName raw. The only stated impact, `fetch(...+document.cookie)`, fails: the session cookie is HttpOnly by express-session default. No other impact is claimed, so none is credited. GET /benefits locates the rendering route. |
| t111 | NG-XSS-AUTOESCAPE-OFF | n | 0/1 | The `"><script>` breakout in `value="{{lastName}}"` does work, but the claim is cookie exfiltration from a cookie it says "carries no HttpOnly flag" (false), on "every authenticated page" (lastName renders on profile.html and benefits.html only). ev-route-1 (GET /, index.js:30) is not a route that renders lastName. |
| t73 | NG-OPEN-REDIRECT | n | 0/2 | CVE-2024-29041 is an allow-list bypass via malformed URLs; NodeGoat has no allow-list, and `/learn` redirects to any URL without the CVE (tested: `Location: https://evil.example`). CVE-2024-43796: untrusted input does reach `res.redirect`, and express 4.16.4 echoes it into the body (tested: `<a href="javascript:alert(1)">`), but that needs a click, and the claimed impact is stealing the HttpOnly cookie. Neither advisory supports the stated scenario. |
| t78 | (blank) | n | 1/5 | None of the three claimed DoS paths occur. (1) body-parser CVE-2024-45590: the 1.20.3 fix changes only the `extended` (qs) parser's depth; NodeGoat uses `extended: false` (server.js:72-75); a 5,000-parameter body gets a 413 in 9 ms. (2) marked CVE-2022-21681: 0.3.5 lacks the vulnerable reflink/nolink patterns; the payload that takes 1.8-6 s on 4.0.9 takes <=5 ms on 0.3.5 even at 2,000 repeats. (3) The two express advisories are not DoS. The advisories are accurate as version facts but their preconditions fail, so they are not counted; GET /dashboard is where the claimed outage shows. |

Recall effect: only t100 adds an item (LOG-INJECTION, hidden). XSS-AUTOESCAPE-OFF stays
unrecalled under the HttpOnly rule. Totals as proposed: **16/19 all-result, 7/19 visible**.

## Why MISSING-SECURITY-HEADERS disappeared

| layer | old run (after-fix) | new run (7f7211d) |
|---|---|---|
| Detector evidence | none: `security_headers_missing` returns early because `helmet` is declared in package.json | none, same reason |
| Architecture unknowns (model-written) | include `unknown-security-headers-csp` | no headers unknown; new ones are `unknown-output-encoding`, `unknown-security-logging` and others |
| Generation coverage | t13, dedicated headers threat (no component, no evidence), plus tutorial-page rows t101/t104 | no dedicated threat; t75 mentions the commented-out CSP only inside a memo-XSS claim |
| Source support | t13 labelled y | t75: memo `<script>` is escaped by marked `sanitize: true`, so n |
| Visibility | t13 0.00, hidden | nothing to show |

- The item was never backed by evidence. The old run covered it only because the architecture
  call happened to write a headers unknown, which the threat batches then picked up.
- The architecture prompt did not change in 7f7211d or c8dd73f, so the loss comes from run-to-run
  model variance, not a code change.
- The detector suppression (helmet is declared but only used in commented-out code) is why
  nothing deterministic keeps the item covered.

## Plan for the remaining 113 rows

1. **Visible rows first (16).** Check each Semgrep, OSV or route citation at its line; these
   drive visible recall.
2. **New kinds of claim.** Rows with no counterpart in the old labels, each checked against source:
   - enumeration (t96, t115), weak password (t99, t116), fixation (t98, t101, t110);
   - XSS (t53, t63, t75, t65, t93, t87, t91, t94);
   - error pages (t54, t76), build context and secrets (t46), forgeable cookie (t50, t72);
   - CI (t23, t24, t27, t28, t47, t48).
3. **Clusters seen in the old run.** Re-read each row's own scenario and citations; do not
   copy old labels:
   - unauthenticated or unencrypted MongoDB;
   - plaintext HTTP (the deployment-dependence clause is required);
   - CSRF (the SameSite assumption is required);
   - IDOR, open redirect, audit gaps, unbounded or resource exhaustion;
   - seed/reset, Docker and compose.
4. **Settled rules applied throughout:**
   - HttpOnly: cookie theft fails, and no unclaimed impact is credited.
   - Route citations count when relevant to the claim.
   - A generic "no validation library imported" gap is not counted.
   - An advisory counts only if its preconditions hold.
   - `javascript:` Location and CR/LF headers do not work (t56, t58).
5. Deliver proposals in groups, as before, with straightforward and uncertain rows separated,
   and the recall effect of each supported match.

## Remaining 113 rows: grouped proposals (not applied)

Applied so far: t16, t73, t78, t100, t111. Everything below is a proposal. Rows marked **?** are uncertain.
Provisional totals if all were approved: **16/19 all-result, 7/19 visible**; 91 supported, 27 not (of 118).

### Visible: straightforward

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t1 | 0.70 | NG-NOSQL-WHERE | y | 2/2 | threshold interpolated into $where (allocations-dao.js:77); the always-true payload is the one in the commented fix. |
| t3, t6 | 0.51, 0.51 | NG-IDOR-ALLOCATIONS | y | 2/2 | userId from req.params (allocations.js:16-18), session fix commented out; gap-1 and the route both locate it. |
| t30, t36 | 0.70, 0.70 | NG-SSJS-EVAL | y | 4/4 | eval() of preTax/afterTax/roth at contributions.js:32-34. |
| t55, t57 | 0.70, 0.70 | NG-OPEN-REDIRECT | y | 2/2 | res.redirect(req.query.url) at index.js:72, no allow-list. |
| t65 | 0.75 | NG-VULNERABLE-DEPS | n | 4/4 | Names marked 0.3.5 and both GHSAs (preconditions hold: sanitize:true), but claims execution for "every user who later loads" /memos (both bypasses need a click on a crafted link) and theft of a "non-httpOnly" cookie (it is HttpOnly). Same overclaims as after-fix t63. |
| t82 | 0.70 | NG-REDOS-ROUTING | y | 2/2 | /([0-9]+)+\#/ at profile.js:59 on raw bankRouting. |
| t88 | 0.70 | NG-SSRF-RESEARCH | y | 2/2 | url + symbol fetched by needle (research.js:15-16), body echoed at :25. |
| t89 | 0.55 | (blank) | y | 2/2 | research.js logs nothing about the caller or target URL. |
| t97 | 0.70 | NG-PLAINTEXT-PASSWORDS | y | 3/3 | Stored as given (user-dao.js:25) and compared with === (:61). |
| t104 | 0.25 | NG-SSRF-RESEARCH | y | 1/1 | Same flaw as t88; metadata target depends on hosting. |
| t117 | 0.35 | NG-PLAINTEXT-PASSWORDS | y | 1/1 | Signup password stored verbatim; bcrypt commented out. |

### Expected-item candidates: straightforward

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t4 | 0.10 | NG-NOSQL-WHERE | y | 1/1 | while(true) in $where; mongo:4.4 has no default query time limit (the key names this DoS). |
| t7, t22, t34, t51 | 0.00, 0.00, 0.00, 0.00 | NG-PLAINTEXT-HTTP;NG-INSECURE-SESSION-COOKIE | y | 0/0 | As t109; no citations. |
| t8 | 0.20 | NG-NOSQL-WHERE | y | 1/1 | Same $where injection. |
| t17, t20 | 0.05, 0.05 | NG-MISSING-FUNCTION-AUTHZ | y | 1/1 | POST /benefits: any user sets any userId's start date (benefits.js:29-35, benefits-dao.js:23). |
| t19 | 0.20 | NG-MISSING-FUNCTION-AUTHZ | y | 1/1 | GET /benefits behind isLoggedIn only (index.js:55); isAdmin fix commented out. |
| t21, t35, t71 | 0.00, 0.00, 0.00 | NG-CSRF | y | 0/0 | csurf and the token commented out (server.js:104-113); SameSite assumption stated. |
| t23 | 0.00 | (blank) | n | 0/0 | "Other processes co-resident on the runner": GitHub-hosted runners are single-job VMs and the traffic is loopback; not a deployment exposure. |
| t25, t52, t74, t108 | 0.01, 0.01, 0.01, 0.01 | NG-OPEN-REDIRECT | y | 0/1 | /learn open redirect; ev-gap-2 (generic no-validation-library gap) not counted. |
| t26 | 0.00 | NG-IDOR-ALLOCATIONS | y | 1/1 | Same IDOR; CI framing irrelevant (as after-fix t28). |
| t29, t61, t83 | 0.00, 0.05, 0.05 | NG-CSRF | y | 1/1 | Same; the route locates the forged POST. t83 says the form "renders no token field" (profile.html:73 has an empty, unverified one), as after-fix t31. |
| t42 | 0.05 | NG-PLAINTEXT-HTTP | y | 1/1 | "4000:4000" on all interfaces, no TLS terminator in compose; deployment assumptions stated; deploy-3 locates the web service. |
| t49 | 0.20 | NG-PLAINTEXT-HTTP | y | 2/2 | Login form and POST over plain HTTP; no-TLS-terminator assumption stated. |
| t53 | 0.00 | NG-XSS-AUTOESCAPE-OFF | n | 0/0 | <script> placed inside value="{{lastName}}" does not execute without a quote breakout; the impact is HttpOnly cookie theft. |
| t56, t58 | 0.01, 0.01 | NG-OPEN-REDIRECT | n | 0/1 | javascript:/data: in Location is not followed by browsers, and Node rejects CR/LF in header values; the claimed scheme or header injection fails. |
| t62 | 0.20 | NG-PLAINTEXT-HTTP | y | 1/1 | Plain HTTP on POST /memos; deployment dependence stated. |
| t63 | 0.20 | NG-XSS-AUTOESCAPE-OFF | n | 1/1 | marked sanitize:true escapes <img onerror> (tested); autoescape does not apply to marked output. |
| t68 | 0.10 | NG-PLAINTEXT-PASSWORDS | y | 1/1 | === compare at user-dao.js:61 implies plaintext storage. |
| t69, t81 | 0.00, 0.00 | NG-UNENCRYPTED-PII | y | 0/0 | profile-dao.js encryption helpers and the encrypted ssn/dob fix commented out; fields stored raw. |
| t72 | 0.00 | NG-INSECURE-SESSION-COOKIE | n | 0/0 | Secret is hard-coded (real), but express-session signs only a session id and userId is server-side, so a forged admin cookie is not possible. As after-fix t92. |
| t75 | 0.00 | NG-XSS-AUTOESCAPE-OFF;NG-MISSING-SECURITY-HEADERS | n | 0/0 | Memo <script> is escaped by marked sanitize; the CSP mention is secondary; cookie is HttpOnly. |
| t77, t102, t112 | 0.06, 0.00, 0.00 | NG-IDOR-ALLOCATIONS | y | 1/1 | Same IDOR; gap-1 locates the missing ownership check. |
| t84, t109, t113 | 0.20, 0.20, 0.20 | NG-PLAINTEXT-HTTP;NG-INSECURE-SESSION-COOKIE | y | 1/1 | http.createServer only (server.js:145); cookie has no secure flag; assumption states no TLS terminator. Same bundling as after-fix t9. |
| t85 | 0.20 | NG-REDOS-ROUTING | y | 1/1 | Same regex as t82. |
| t86 | 0.10 | NG-SSRF-RESEARCH | y | 1/1 | Attacker-chosen fetch target, so spoofed content; a facet of the SSRF (as after-fix t83). |
| t87, t91 | 0.00, 0.20 | NG-SSRF-RESEARCH | n | 1/1 | Echo is real, but the only stated impact is reading document.cookie; the cookie is HttpOnly. |
| t92, t94 | 0.20, 0.10 | NG-SSRF-RESEARCH | y | 1/1 | url + symbol fetched without allow-list, body echoed. |
| t96, t115 | 0.20, 0.20 | NG-USER-ENUMERATION | y | 1/1 | "Invalid username" vs "Invalid password" (session.js:60-61, 82-98); identical-error fix commented out. |
| t98 | 0.05 | NG-SESSION-FIXATION | y | 1/1 | req.session.userId set on the existing session, no regenerate (session.js:116); fix commented. |
| t99 | 0.20 | NG-WEAK-PASSWORD-POLICY | y | 2/2 | PASS_RE /^.{1,20}$/ (session.js:144); stronger regex commented out. Signup and login are both in the claim. |
| t101 | 0.20 | NG-SESSION-FIXATION | y | 1/1 | Same; /dashboard is where the fixed cookie is reused. |
| t110 | 0.05 | NG-CSRF | y | 0/1 | Scenario is CSRF on POST /profile (true). "Session fixation" appears only in the title and is not credited. GET / is not the forged route. |
| t116 | 0.20 | NG-WEAK-PASSWORD-POLICY | y | 1/1 | Same as t99. |

### Expected-item candidates: uncertain

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t5 **?** | 0.10 | NG-NOSQL-WHERE | y | 1/1 | Scenario (always-true predicate, names joined per allocation) holds; the title's "collections beyond allocations" is not what the scenario claims. |
| t93 **?** | 0.00 | NG-SSRF-RESEARCH | y | 1/1 | Also claims a fake login form on the app origin capturing typed credentials, which works; the cookie half fails. Title says "steals the session cookie". |
| t106 **?** | 0.20 | NG-PLAINTEXT-HTTP | y | 2/2 | Cookie readable and response injectable on plain HTTP. The assumption says "non-TLS listener" but not that no TLS terminator exists. |

### Unmatched clusters: straightforward

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t2, t18, t31, t66, t80 | 0.06, 0.05, 0.20, 0.20, 0.05 | (blank) | y | 1/1 | No actor/target recorded (DAOs log only fixed strings); the route citation locates the flow. |
| t9, t10, t14, t32, t39, t59, t67, t79 | 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00 | (blank) | y | 0/0 | Credential-free, non-TLS MongoDB URI (docker-compose.yml:8); conditional on container-network access. Setting isAdmin works because the flag is read per request. |
| t12 | 0.00 | (blank) | y | 1/1 | Same MongoDB exposure; semgrep-2 locates the plaintext compare the sniffed document feeds. |
| t13, t33, t103, t114, t118 | 0.00, 0.00, 0.00, 0.00, 0.00 | (blank) | y | 0/0 | No rate limit or lockout; per-request DB work. Degree of exhaustion is conditional. |
| t15 | 0.05 | (blank) | y | 1/1 | getAllNonAdminUsers unbounded and re-run after each update (benefits.js:36-39). |
| t24, t27 | 0.00, 0.00 | (blank) | n | 0/0 | Fork pull_request runs get a read-only token and no secrets; artifacts need a GitHub login and show fixture data (as after-fix t50/t51). |
| t37 | 0.05 | (blank) | y | 0/1 | Same MongoDB exposure; ev-datastore-1 (dependency line) does not locate the URI (as after-fix t38). |
| t38 | 0.20 | (blank) | n | 1/1 | No specific driver vulnerability named (as after-fix t39). |
| t40 | 0.05 | (blank) | y | 0/1 | db-reset.js drops collections and seeds admin/Admin_123 (literal, line 18) on each start; ev-deploy-4 is the mongo service, not the web command. |
| t41 | 0.00 | (blank) | y | 0/0 | db-reset.js logs only to stdout. |
| t43 | 0.05 | (blank) | y | 1/1 | Compose web command reruns db-reset.js; deploy-3 locates the web service (as after-fix t40). |
| t44 | 0.20 | (blank) | y | 0/1 | Dockerfile hardening commented out; ev-deploy-5 (EXPOSE) does not show it (as after-fix t48). |
| t45 | 0.20 | (blank) | n | 0/1 | EOL base image, no specific CVE (as after-fix t47). |
| t46 | 0.20 | (blank) | n | 0/1 | .dockerignore exists and excludes .git, .github and others; the stated premise "no .dockerignore" is false. |
| t48 | 0.20 | (blank) | n | 1/1 | Fork-PR caches are not restored by base-branch runs (as after-fix t49). |
| t54, t76 | 0.00, 0.00 | (blank) | n | 0/0 | error-template.html:11 renders {{error}} (message only), not the stack (as after-fix t73). |
| t60 | 0.20 | (blank) | n | 2/2 | "Multi-megabyte memo strings" are rejected by body-parser's 100 KB default (as after-fix t62). |
| t64 | 0.20 | (blank) | n | 1/1 | Same as t60. |
| t70 | 0.15 | (blank) | n | 0/1 | GHSA-mh5c needs an invalid collection name; NodeGoat uses fixed names (as after-fix t69). |
| t90, t95, t105 | 0.10, 0.00, 0.10 | (blank) | y | 1/1 | needle.get with no response/read timeout or size cap (as t86 in after-fix). |
| t107 | 0.20 | (blank) | y | 2/2 | saveUninitialized:true with the default MemoryStore creates a session per anonymous request; unbounded memory. |

### Unmatched clusters: uncertain

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t11 **?** | 0.20 | (blank) | n | 1/1 | process.exit(1) on a failed connect is real, but only at startup: the compose until-loop retries and succeeds once mongo is back, so "forever restarts into the same failure loop" is not supported. |
| t28 **?** | 0.00 | (blank) | n | 0/0 | CI hygiene, not an application threat; Cypress fails fast on a refused port rather than hanging for six hours. |
| t47 **?** | 0.20 | (blank) | y | 1/1 | actions/checkout@v2, setup-node@v1 and cache@v2 are mutable tags (true); the risk is conditional on an upstream compromise. |
| t50 **?** | 0.20 | (blank) | y | 1/1 | Repudiation claim holds (no audit log). The title's "forgeable" cookie is not argued in the scenario and not credited. |

