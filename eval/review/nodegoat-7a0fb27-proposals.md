# NodeGoat at 7a0fb27: proposed labels (not applied)

> **AI PROPOSALS, NOT LABELS.** From `eval/results/nodegoat-7a0fb27.json` (snapshot `eval/baselines/nodegoat-7a0fb27/`). Blank sheet: `eval/labels/nodegoat-7a0fb27.csv` (98 rows, 35 visible). Nothing applied. Rules as in `pending-evaluation-requirements.md`, including the HttpOnly note. Rows marked **?** are uncertain.

## Gap-floor promotion

- 21 threats cite `ev-gap-2` (csrf_missing) or `ev-gap-3` (security_headers_missing). **18 sit at exactly 0.40 because of the gap floor**: gap-only evidence with certainty >= 0.8 is lifted to 0.40 even with an assumption attached.
- CSRF, floor-promoted (8): t5, t9, t13, t22, t47, t68, t87, t90. Not floor-promoted: t73 (0.54, route + gap), t76 (0.44, Semgrep + gap).
- Headers, floor-promoted (10): t2, t10, t12, t55, t58, t69, t75, t78, t83, t95. Not floor-promoted: t88 (0.57, route + gap).
- Duplicate claims: t5, t13, t22, t47, t68, t90 (forged POST /profile rewriting bank details); t2, t12, t75, t78 (clickjacking a form page).
- The floor makes three proposed-unsupported rows visible: t55, t69, t10.

## Gap-citing: straightforward

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t5, t13, t22, t47, t68, t90 | 0.40, 0.40, 0.40, 0.40, 0.40, 0.40 | NG-CSRF | y | 1/1 | Duplicates: forged POST /profile rewrites bankAcc/bankRouting. csurf and the token are commented out (server.js:104-113); ev-gap-2 states the repo-wide missing control accurately. Promoted to 0.40 by the gap floor alone. |
| t9 | 0.40 | NG-CSRF | y | 1/1 | Login CSRF (victim logged into an attacker account) or profile writes; both work without a token. SameSite assumption stated. Gap floor, 0.40. |
| t55 | 0.40 | NG-MISSING-SECURITY-HEADERS | n | 1/1 | Framing /learn gains nothing (the attacker can frame their own page), and default Referrer-Policy (strict-origin-when-cross-origin) sends only the origin, not the path and query. Gap floor, 0.40. |
| t58 | 0.40 | NG-MISSING-SECURITY-HEADERS | y | 1/1 | research.js:18-20 sets only Content-Type and helmet is commented out, so no CSP limits the echoed attacker HTML. Gap floor, 0.40. |
| t69 | 0.40 | NG-XSS-AUTOESCAPE-OFF;NG-MISSING-SECURITY-HEADERS | n | 1/1 | allocations.html:35 does print {{allocation.firstName}} raw, but the only impact claimed is exfiltrating a cookie it says "carries no httpOnly flag" (it is HttpOnly). Gap floor, 0.40. |
| t73 | 0.54 | NG-CSRF | y | 2/2 | Forged POST /benefits; route and gap both relevant. Not floor-promoted (route + gap). |
| t76 | 0.44 | NG-CSRF | y | 2/2 | Forged POST /contributions delivers an eval() payload; semgrep-3 locates the sink. Not floor-promoted (Semgrep + gap). |
| t87 | 0.40 | NG-CSRF | y | 1/1 | Forged POST /memos publishes content as the victim (the "including an XSS payload" aside is not needed for the claim). Gap floor, 0.40. |
| t88 | 0.57 | NG-XSS-AUTOESCAPE-OFF;NG-MISSING-SECURITY-HEADERS | n | 2/2 | Memo <script> is escaped by marked sanitize:true (tested earlier), and the impact is HttpOnly cookie theft. Route + gap, 0.57. |

## Gap-citing: uncertain

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t2, t75, t78 **?** | 0.40, 0.40, 0.40 | NG-MISSING-SECURITY-HEADERS | y | 1/1 | Clickjacking of a form page with no X-Frame-Options (t78 also claims cookie theft, not credited). Same claim as after-fix t13 (labelled y). Caveat: modern browsers do not send a cookie without SameSite into a cross-site iframe, so the framed page is usually logged out. Gap floor, 0.40. |
| t10 **?** | 0.40 | NG-MISSING-SECURITY-HEADERS | n | 1/1 | Headers really are missing, but the attack is profile/memo XSS on the dashboard: the layout renders the viewer's own name (self-XSS) and memos are sanitized, so exfiltrating a victim's data is not established. Gap floor, 0.40. |
| t12 **?** | 0.40 | NG-MISSING-SECURITY-HEADERS | y | 1/1 | Duplicate of t2 on the CI flow (clickjack /profile; memo-script example fails under marked sanitize). Same browser caveat. Gap floor, 0.40. |
| t83 **?** | 0.40 | NG-MISSING-SECURITY-HEADERS | n | 1/1 | Clickjacking target /allocations/:userId is read-only (no action to trick), and the CSP half is conditional on an injection it does not establish. As after-fix t104. Gap floor, 0.40. |
| t95 **?** | 0.40 | NG-SSRF-RESEARCH;NG-MISSING-SECURITY-HEADERS | y | 1/1 | Attacker HTML echoed on the app origin with no CSP; same-origin script reading /profile and /dashboard works (no cookie claim). Gap floor, 0.40. Whether to add the headers match is the open point. |

## Other visible: straightforward

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t21 | 0.25 | NG-PLAINTEXT-PASSWORDS | y | 1/1 | === compare at user-dao.js:61. |
| t38 | 0.70 | NG-SSRF-RESEARCH | y | 2/2 | url + symbol fetched by needle with no allow-list (research.js:15-16), body echoed. |
| t39 | 0.55 | NG-SSRF-RESEARCH | y | 2/2 | Echoed attacker HTML runs fetch("/profile") on the app origin: a same-origin authenticated action, which the assumption allows. |
| t41, t54, t81 | 0.70, 0.70, 0.70 | NG-OPEN-REDIRECT | y | 2/2 | res.redirect(req.query.url) at index.js:72; semgrep-6 and the route. |
| t46 | 0.75 | (blank) | n | 1/2 | GHSA-mh5c needs an invalid collection name; NodeGoat uses fixed names. ev-datastore-1 locates the driver; ev-osv-2 preconditions fail (as after-fix t69). |
| t48 | 0.52 | NG-OPEN-REDIRECT | y | 1/2 | Same; ev-gap-4 (generic no-validation-library gap) not counted. |
| t50 | 0.70 | NG-SSJS-EVAL | y | 2/2 | eval() of contribution fields at contributions.js:32-34. |
| t53, t92 | 0.70, 0.55 | NG-REDOS-ROUTING | y | 2/2 | /([0-9]+)+\#/ at profile.js:59. (t92's brute-force assumption is irrelevant.) |
| t57 | 0.25 | NG-SSRF-RESEARCH | y | 1/1 | Same SSRF. |
| t71 | 0.51 | NG-IDOR-ALLOCATIONS | y | 2/2 | userId from req.params, no ownership check. |
| t79 | 0.70 | NG-SSJS-EVAL | y | 4/4 | Same. |

## Hidden: straightforward

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t1, t37, t62, t77, t93 | 0.00, 0.05, 0.05, 0.05, 0.05 | NG-PLAINTEXT-HTTP;NG-INSECURE-SESSION-COOKIE | y | 0/0 | http.createServer only (server.js:145), cookie has no secure flag, no TLS terminator assumed. (t1/t62 also say "no httpOnly", which is wrong, but sniffing does not need it.) |
| t3, t94 | 0.20, 0.20 | NG-SSRF-RESEARCH | y | 1/1 | Same SSRF; route locates GET /research. |
| t4 | 0.00 | (blank) | n | 0/0 | error-template.html:11 renders {{error}} (message only); parseInt on a bad userId does not throw. |
| t6 | 0.00 | NG-SSJS-EVAL | y | 0/0 | eval() at contributions.js:32-34. |
| t7 | 0.00 | NG-PLAINTEXT-PASSWORDS | y | 0/0 | Stored as given, bcrypt commented out. |
| t8, t72 | 0.00, 0.00 | NG-REDOS-ROUTING | y | 0/0 | Same regex at profile.js:59. |
| t11, t27 | 0.00, 0.00 | (blank) | y | 0/0 | Seeded admin/Admin_123 (db-reset.js:18; also test/e2e/fixtures/users/admin.json) is public; conditional on an unchanged deployment. |
| t14 | 0.01 | NG-OPEN-REDIRECT | y | 0/1 | Open redirect; ev-gap-4 not counted. |
| t15, t35 | 0.00, 0.20 | (blank) | y | 1/1 | Actions referenced by mutable tags (t47 in the c8dd73f run); t15 also cites mongo:4.0 by tag. |
| t16 | 0.00 | (blank) | n | 0/0 | Artifacts upload only on failure, need a GitHub login, and show fixture data. |
| t17, t52 | 0.06, 0.06 | NG-IDOR-ALLOCATIONS | y | 1/1 | Same IDOR; gap-1 locates the missing ownership check. |
| t18, t25, t29, t43 | 0.00, 0.00, 0.00, 0.00 | (blank) | y | 0/0 | Credential-free, non-TLS MongoDB URI; conditional on container-network access. |
| t19, t20, t23, t44 | 0.10, 0.10, 0.10, 0.10 | NG-NOSQL-WHERE | y | 1/1 | threshold interpolated into $where (allocations-dao.js:78): always-true predicate or while(true). |
| t24 | 0.10 | (blank) | y | 0/1 | benefits-dao logs only "Updated benefits"; memos store no author. semgrep-2 (plaintext compare) does not locate the audit gap. |
| t26 | 0.00 | (blank) | y | 0/0 | Compose command and Heroku postdeploy run db-reset.js, which drops collections. |
| t28 | 0.00 | (blank) | y | 0/0 | db-reset.js logs only to stdout. |
| t30, t31 | 0.20, 0.20 | (blank) | y | 2/2 | Same MongoDB exposure; deploy-3 (web) and deploy-4 (mongo) locate both ends. |
| t32 | 0.20 | (blank) | y | 1/1 | "4000:4000" on all interfaces, no resource limits; deploy-3 locates the web service. |
| t33 | 0.20 | (blank) | n | 0/1 | EOL base image, no specific CVE (as before). |
| t34 | 0.05 | (blank) | y | 0/1 | Dockerfile hardening commented out; ev-deploy-5 (EXPOSE) does not show it. |
| t36 | 0.20 | (blank) | n | 1/1 | Caches written by a feature-branch or PR run are not restored by default-branch runs, so poisoning later runs fails. |
| t40, t60 | 0.10, 0.00 | (blank) | y | 1/1 | needle.get with no timeout or size cap. |
| t42, t82 | 0.01, 0.01 | NG-OPEN-REDIRECT | n | 0/1 | javascript:/data: Location is not followed by browsers and Node rejects CR/LF in headers; the claimed script execution fails. |
| t45 | 0.00 | (blank) | n | 1/1 | $where runs in a read-only query and cannot update another user's allocation; semgrep-1 accurately locates the $where. |
| t49 | 0.05 | NG-USER-ENUMERATION | y | 1/1 | "Invalid username" vs "Invalid password" (session.js:60-61) lets an attacker enumerate before guessing; no throttle. Enumeration is stated as part of the attack. |
| t51 | 0.20 | (blank) | y | 2/2 | No attributable record of profile or benefit changes; both routes are in the claim. |
| t59 | 0.10 | NG-SSRF-RESEARCH | y | 1/1 | Echoed HTML runs on the app origin and submits /profile as the victim (same-origin action; no cookie read needed). |
| t61 | 0.00 | NG-INSECURE-SESSION-COOKIE | n | 0/0 | express-session signs only a session id; userId is server-side, so a forged admin session is not possible. |
| t63, t86 | 0.05, 0.00 | NG-WEAK-PASSWORD-POLICY;NG-USER-ENUMERATION | y | 1/1 | PASS_RE /^.{1,20}$/ (session.js:144) plus distinct login errors; brute force unthrottled. |
| t64 | 0.20 | (blank) | y | 1/2 | No record of successful logins or admin checks; POST /login is in the claim, GET /logout is not. |
| t65 | 0.05 | NG-PLAINTEXT-HTTP | y | 2/2 | Tutorial responses rewritable on plain HTTP; TLS assumption stated. |
| t66 | 0.20 | NG-MISSING-SECURITY-HEADERS | n | 2/2 | Tutorial pages have no action to clickjack and no attacker-controlled script (as after-fix t104). |
| t67 | 0.20 | NG-XSS-AUTOESCAPE-OFF | n | 2/2 | environmentalScripts is [] outside development and not attacker-influenced; no injectable value is shown. |
| t70 | 0.20 | NG-NOSQL-WHERE | y | 1/1 | threshold reaches the $where string uncast; the crafted-string form works (the [$gt] object form only stringifies). |
| t74, t80, t85, t91 | 0.05, 0.05, 0.05, 0.05 | NG-PLAINTEXT-HTTP | y | 1/1 | Cleartext on a named route; no TLS terminator assumed. |
| t84 | 0.20 | (blank) | n | 1/1 | A JSON body makes findOne return the first user, but validateLogin then compares passwords with ===, so the claimed authentication bypass fails. |
| t89 | 0.05 | (blank) | n | 1/1 | "Multi-megabyte memo bodies" are rejected by body-parser's 100 KB default. |
| t96 | 0.05 | NG-PLAINTEXT-HTTP;NG-PLAINTEXT-PASSWORDS | y | 1/1 | Signup over plain HTTP (no TLS terminator assumed) and stored unhashed. |
| t97 | 0.20 | NG-XSS-AUTOESCAPE-OFF | n | 1/1 | Names render raw (layout.html:75, benefits, allocations), but the only impact claimed is document.cookie theft (HttpOnly). |
| t98 | 0.05 | (blank) | y | 1/1 | Open signup, no throttle. |

## Hidden: uncertain

| row | conf | match | sup | evid | reason |
|---|---|---|---|---|---|
| t56 **?** | 0.01 | NG-OPEN-REDIRECT | y | 0/1 | Claims only that crafted values reach the Location header, which is true, and names a protocol-relative //evil.tld redirect, which works; the javascript: example would not execute. |

